# Architecture

## The problem

Unit tests assert on return values and mocks. Production runs on telemetry.
The gap between them is where regressions and, for agent systems, security
failures live: a test passes because it checked the wrong thing, and the thing
that mattered was only ever visible in a trace. Subpoena makes the trace the
test interface and keeps one assertion usable from a unit test to a production
alert.

## One assertion, three tiers

An assertion is a TraceQL string. The harness takes strings, so the same text
moves between places unchanged.

- Tier 1 runs in `go test`. An in-memory recorder (`pkg/harness`) stands in for
  the exporter, and `pkg/traceql` evaluates the query over the captured spans.
  Fast, hermetic, no containers.
- Tier 2 runs the real thing under Grafana OATS: the application, an OTel
  collector, Tempo, Loki and Grafana. The query runs on Tempo itself, so it
  catches what the subset evaluator cannot: real exporter behaviour, sampling,
  attribute limits, query semantics.
- Tier 3 is the production alert rule with the same query. The invariant stops
  being a test and becomes a standing check. A liveness rule beside it alerts
  when the spans it depends on stop arriving, since "no violations" and "no
  telemetry" look the same to the invariant. `make alerts` provisions both into
  a real Grafana and drives them from silence through clean traffic to a
  violation.

`invariants/` holds the strings. A test fails if the OATS case or the alert rule
drifts from the invariant file.

## Completeness and three-valued verdicts

A test that says "no span matched" is only meaningful if the capture was
complete. `Collect()` force-flushes, then checks that nothing was dropped (the
recorder counts capacity overflows and spans ending after shutdown), that
nothing started was left unfinished, and that the SDK dropped no attribute,
event or link of a recorded span. The harness sets its span limits to
unlimited, ignoring the `OTEL_*_LIMIT` environment variables: an attribute
dropped or truncated by a limit changes what a query matches, and the SDK does
not count truncation as a drop. If the capture is incomplete it returns an
error and a snapshot marked incomplete. Absence on that snapshot yields
Inconclusive, not Pass. A positive match is still definitive: a span you saw is
there even if others are missing. Inconclusive fails by default.

Tiers 2 and 3 have no such guarantee. A production SDK, or a collector between
it and Tempo, can drop or truncate attributes under its own limits. The
invariant then runs on incomplete testimony, and nothing in the trace says so.
Check the deployed limits, and keep the attributes an invariant reads short and
set early on the span.

## Testimony versus proof

Spans are emitted by the code under test. If an enforcement check is deleted,
the code can still emit a span saying the decision was "deny", and no exec span,
because the instrumentation is a separate statement from the enforcement. A
suite that trusts spans alone can be green over broken enforcement.

So enforcement is proven by a witness: something outside the application's
control that observes the side effect directly. Here, process exec events and
outbound connection attempts.
Tier 1 uses `ProcWitness`, which polls `/proc` and correlates by cgroup first:
the gateway puts each session's processes in a cgroup named with the trace ID
(`pkg/cgroup`), and the witness reads `/proc/<pid>/cgroup` to tie a process to a
trace, falling back to parent-process lineage when there is no session cgroup.
The exec span records which correlation applies (`subpoena.witness.correlation`).
Tier 2 and production use `pkg/witness/execbpf`: an eBPF program on the exec
tracepoint that reads each process's cgroup in the kernel, run as
`cmd/subpoena-witness` with its events shipped to Loki. That command ships
exec events only. Tier 1 network absence uses `witness.Sinkhole`, a listener
the test stands up. The kernel sibling is `pkg/witness/netbpf`, in
`make test-ebpf`; it is not what `cmd/subpoena-witness` runs. See
`witnesses/README.md` for the gaps in each.

The tier-2 OATS fixture proxies test requests through an independent capture
controller. Its final input stops and drains the witness before OATS judges
any absence, and requires a complete healthy start/stop window using
`witness.ReadLog`. Both OATS cases also require those boundaries and the
healthy stop in Loki. A lost kernel event or failed capture cannot pass on
silence. This does not guarantee lossless collector/Loki transport; the
allowed exec and boundary queries remain positive pipeline controls.

The toy gateway makes this concrete. `Authorize` and `Fetch` are marked
`//subpoena:enforcement_point`, and the tests do not stop at the span: they ask
the witness how many processes were spawned, and whether a forbidden address
was dialed.

## Cross-examination

Tests that look thorough can still be blind to the thing that matters. Cross-examination
checks, per enforcement point, that the suite notices when enforcement is gone.
It copies the module to a temp directory, discovers enforcement points from
that copy, and removes the statement marked
`//subpoena:enforcement` inside each `//subpoena:enforcement_point` function,
and runs the tests. A suite that goes red on a test's assertion kills the mutant,
if that test passes without it. A green suite means the tests
cannot tell enforced from unenforced behaviour, and subpoena-cross reports
`enforcement-mutant-survived <func>`. It requires a green baseline first, and a
mutant that does not compile is "invalid", never "killed". Every run starts from
a fresh copy, so no test sees what another case left there. After a kill, the
packages that failed run again, all their tests: once with the mutant in place,
then three times without it, each on a fresh copy. All their tests, because a
failure can need the tests beside it. Python runs the mutant run's whole test
selection. The baseline, the mutant run and the reruns
all start their test binaries the same way, so a test red only under the way it
was started is red on the baseline too. If the run with the mutant passes, or one
without it fails or does not finish, the verdict is
`enforcement-mutant-unconfirmed` and the run fails: something other than the
mutant turned it red, such as a flake or state outside the copy that persists. A
real kill that needs a clean copy can come back unconfirmed too, since the repeat
reuses the mutant's copy; that costs a kill, and a false one costs more. State
that clears itself before the reruns passes them. A flake must fail twice in a row
with the mutant, then pass three times without it: a test that fails one run in
twenty-five does that on about one mutant in seven hundred, and a test that fails
half the time on about one in thirty-two. Cross narrows this and does not close it: fix
the flake, and confirm a surprising kill by rerunning cross. In Go a kill also
needs a failed test whose binary links the mutated package (`go list -deps
-test`). A suite that runs the code as a separate program links none of it, so
its kills come back unconfirmed. A removed `return`
the function cannot end without gets a return of zero values in its place only
when that turns an error to nil and changes nothing else; any other such return
stays invalid, since zero can be the refusal itself (`return p.Check(u)`). That
includes a return with a call in its error, `fmt.Errorf` too: the call can be
the work itself (`return s.Authorize(admins)`), and cross cannot see what a
call does. A mutant whose tests
run past `-timeout` (5 minutes by default) is `enforcement-mutant-timeout`, also
never "killed": a hang may be the host's, and no assertion caught it. A suite
that goes red with no clean failure message is `enforcement-mutant-crashed`,
which fails the run too: a crash is not evidence that the enforcement is
tested. A package whose test binary died (a panic, a runtime fatal error or
`os.Exit`) gives no kills at all, since a test's log lines before its panic
look like failure messages; a clean failure in another package still counts.
That holds for an assertion library's report too: `go test -json` carries it as
plain text, which the code under test can print, so a testify or Ginkgo failure
ahead of a panic is a crash. Cross reads the death from the binary's exit code,
which it records through `go test -exec`, since `go test -json` does not give
it: anything but 1 is a death, wherever the panic's text fell, even beside
another writer's open line. The wrapper is a small Go program cross builds for
the run. It adds nothing to the environment, a project's own `-exec` or
`go_$GOOS_$GOARCH_exec` runs under it, and with no wrapper cross stops rather than
read the output alone. An exit 1 counts only if the binary finished testing: the
wrapper asks for a heap profile, which package testing writes when `m.Run` ends,
and an `os.Exit(1)` in the middle of a test leaves none. Output cannot show this,
since `go test -json` trusts a `--- FAIL:` line behind the `^V` byte whoever wrote
it. Code that goes looking can still write the profile path it finds in
`os.Args`, and a runner that runs the binary elsewhere leaves no profile, so its
kills are crashes. A `panic:` line also voids a package's kills when it
sits in a test that did not pass, so a panic something recovered, with the
binary exiting 1, stays a crash. In a test that passed it is a log line, and
order does not matter: the binary lived. Ginkgo reports a recovered panic as `[PANICKED]`,
which counts as a crash wherever it falls in the suite, since Ginkgo runs a suite
as one test in random order. Failures outside any test never count: a line
printed while `TestMain` or `init` ran is package output, whatever its shape. Mutant runs use `go test -json -failfast`, so a
package stops at its first red test. Each kill reports its first evidence, the
first failure message of a failed test: `witness` or `testimony` when the
message carries the harness tag (`witness:`, `testimony:`), otherwise `other`
(an error return, exit code, audit row or output). A kill whose first evidence
is not `witness` rested on the system's own account or its side effects. In Go
a tag alone is not `witness`: the code under test can print a line in the shape
of a `t.Log`, so under cross the harness signs its witness failures with a key
made for the run, and an unsigned `witness:` is `other`. A test that asks a
witness itself reports through `harness.WitnessErrorf`, which signs. The output
outside cross does not change. Only a `*testing.T`, `B` or `F` gets the mark, so
production code cannot sign through the public harness with a `testing.TB` of its
own, and a wrapper such as `GinkgoTB` reads as `other`. The key is not a secret
from the code under test. `/proc/<pid>/environ` keeps it after the harness unsets
it, so in-process code, a child process, or any process of the same user can read
it and compute a mark. The mark stops what a system prints in the ordinary way,
not code set on forging one. In Python the failure's type decides: the harness
raises `WitnessFailure`, a test that asks a witness itself calls
`harness.witness_fail`, and no text counts, wherever it stands. A call from the
code under test is a crash, read from the frames; in-process code can still build
what it likes. An Inconclusive or a failed capture says the witness could not
see, which the code under test can cause, so in both languages it fails the test
under `inconclusive:` and reads as `other`. `--require-witness` opts into a stricter
gate: a clean failure whose first evidence is `testimony` or `other` is
`enforcement-mutant-killed-by-self-report` and fails the run. A witness failure
later in that test or its cleanup cannot redeem it. Selection retries such a
result on the full suite (an `unconfirmed` it keeps: a test seen failing without
the mutant is not retried into a kill), and group and pair runs use the same rule, so a
self-report kill cannot mask another layer. The default remains unchanged.
The gateway and adopter CI paths select this gate. The Level 0 Python
quickstart uses ordinary cross mode: its direct dictionary check is `other`,
not a process/network witness. `make cross-self` also retains ordinary mode
while the policy for pure-logic guard oracles is decided separately. A Python
test's call to `harness.witness_fail`, and a Go test's to `harness.WitnessErrorf`, remain reviewed claims:
never use either on a return-value or span assertion to satisfy the gate. `-evidence-dir` keeps every mutant
run's full `go test -json` output, killed ones included. `-j N` runs N single
mutants at once, each in its own copy of the module (group runs stay
sequential); on cross-self it cut 490 s to 135 s at `-j 8` with the same
verdicts. Load can flip a verdict either way: a polling witness sees less on a
busy host, turning a kill into a survivor (which fails the run), and a
timing-sensitive test can fail under contention, turning a survivor into a
kill. Gate releases on `-j 1`, or confirm kills there. `-select`
first runs each test alone with coverage, then runs each mutant against only
the tests that executed its line; a mutant no test executed runs the whole
suite. A test can reach a line where coverage cannot see it (in a
subprocess), so every mutant selection did not kill runs again on the whole
suite, and group runs always use the whole suite. A kill counts only on
tests that are green without the mutant: a test that fails alone, or a
selected subset that fails together (tests that depend on each other's
order), is an error. The coverage pass costs about
one extra suite run, so it pays off when each mutant's suite is long: on
cross-self (short suites) `-j 8 -select` took 141 s against 135 s for `-j 8`,
with the same verdicts. An enforcement point
with no `//subpoena:enforcement` statement is an error, not a skip, so one
covered function cannot hide an unexamined one. The report starts with the
number of enforcement points and mutants.

### What a kill does not prove

A kill says that a test failed on an assertion once the marked statement was
gone. It does not say that the test examined the refusal. This gap is known and
cross does not close it. Removing an early return, an assignment or a `continue`
can stop the allowed path as well (`user = None`, then the admin is refused), and
so can a wrong guard value. Enforcement is then forced on, a test of the allowed
path alone fails, and that is a kill, though no test ever asks about a refused
user. A mutant that crashes a handler can read the same way when the test sees
it second-hand: `assert 500 == 200`, or an `EOF` after `net/http` recovered the
panic. Nothing in the output tells these apart from a real test of the refusal,
so read each kill's first evidence: `admin was refused` on the mutant of a
refusal is this gap. Then write the test of the refused path, which is the one
that shows the enforcement is gone. Python's `None` on a marked return and
Go's stand-in are held back for this reason, and only there: other removals
run. `--require-witness` narrows the gap, since a witness failure is about the
effect, not about the return value.

Enforcement that is a condition, not a statement, is marked on the `if` line
with `//subpoena:enforcement_guard true` (or `false`). The value is the one that
lets the action through, and the mutant forces the condition to it. The value
is a reviewed claim, like the markers: a wrong one forces enforcement on, which
only an allowed-path test notices, and leaves the refusal unexamined. Check it
in review. Enforcement
in layers, where an early refusal and a later check each stop the action alone,
is declared with `group=<name>` on each layer's marker (2 to 8 layers, across
functions and files). Cross also runs the whole group as one mutant. A layer
that survives alone, but goes red together with other layers that also
survived alone, is `enforcement-layer-masked`, and the report names the layer
whose removal together with it turned the suite red. A layer killed on its own
never masks another: a run that includes it is red because of it. A masked
layer fails the run unless it is listed, with a reason, in `cross-masked.txt`
in the target directory (`<file> | <func> | group=<group> | <removed text> | <reason>`,
the file relative to the module root). The group is part of the entry, so a
layer moved to another group needs a fresh review. That file is a reviewed claim. One entry
accepts one layer: an entry that matches two masked layers (the same text
twice in one function), an entry listed twice, and an entry that no longer
matches a masked layer are errors or fail the run. Markers take no free text:
an unknown argument, a guard marker without its value or off an `if` line, and
a group of one are errors. So is a marker that would take no effect: a
statement or guard marker outside an enforcement point, a point marker that is
not on a function's doc comment, and a misspelt `//subpoena:enforcement...`
comment. A run whose context is canceled is an error, never a verdict.

Discovery and mutation use the same saved file bytes. Before each
mutation, cross-examination checks that the fresh copy still matches discovery
and refuses if it has changed. The CLI prints `snapshot <sha256> <path>` for
each mutant-bearing file, so its reported offsets and removals can be tied to
those bytes. These hashes cover only files containing mutants, not tests, the
whole module or external dependencies. The initial module copy is not atomic,
and relative module replacements still point to live directories.

## The registry

`registry/` is a Weaver registry: a manifest, `model/*.yaml`, and a dependency on
upstream OTel semantic conventions. It defines the spans and attributes the
system may emit. Every attribute carries a `tier` annotation: `test` attributes
(such as `session.id`) are never exported in production, `all` attributes are.
`pkg/production` enforces that from the generated `AttributeTiers`: an exporter
wrapper for Go services and a generated Collector transform processor for
everything else (`examples/gateway/production/otelcol.yaml`). A test fails if
an invariant promoted to a production alert reads a test-tier attribute, since
that alert could never fire.
Go constants are generated into `generated/go/semconv` and are the only source
of telemetry names. `subpoena-lint` rejects names that are not in the registry.
CI checks the registry, diffs it against main, and CODEOWNERS requires review.

## Provenance

Each test file declares whether it was derived from the spec (registry and
docs) or from the implementation. A test written after reading the code tends
to assert whatever the code does, bugs included. The marker makes that visible
to reviewers and to tooling.

## Not decided here

Cross-service registry migration policy is still open (`docs/decisions.md`).
The Python port passes its contract checks for the harness, the TraceQL
evaluator, the witness reader, spawn absence checks and network absence
checks with the loopback sinkhole. It has cross-examination for pytest
(layer groups, `-j` and `-select` included) and AST lint; registry-drift
stays Go-only, and it reads the witness file rather than running a witness
(`docs/ports.md`). TypeScript has generated names
(`generated/ts/semconv.ts`) and no harness. An optional exec backstop
was decided and is not built (`docs/decisions.md`, "The exec backstop"). Tetragon was
the first tier-2 witness; outside Kubernetes its events lack the session
cgroup, so Subpoena has its own (`witnesses/README.md`).
