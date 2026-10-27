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
and runs the tests. A red suite kills the mutant. A green suite means the tests
cannot tell enforced from unenforced behaviour, and subpoena-cross reports
`enforcement-mutant-survived <func>`. It requires a green baseline first, and a
mutant that does not compile is "invalid", never "killed". A mutant whose tests
run past `-timeout` (5 minutes by default) is `enforcement-mutant-timeout`, also
never "killed": a hang may be the host's, and no assertion caught it. A suite
that goes red with no clean failure message is `enforcement-mutant-crashed`,
which fails the run too: a crash is not evidence that the enforcement is
tested. A package whose test binary died (a panic, a runtime fatal error or
`os.Exit`) gives no kills at all, since a test's log lines before its panic
look like failure messages; a clean failure in another package still counts. Mutant runs use `go test -json -failfast`, so a
package stops at its first red test. Each kill reports its first evidence, the
first failure message of a failed test: `witness` or `testimony` when the
message carries the harness tag (`witness:`, `testimony:`), otherwise `other`
(an error return, exit code, audit row or output). A kill whose first evidence
is not `witness` rested on the system's own account or its side effects. Tests
can tag their own messages the same way. `-evidence-dir` keeps every mutant
run's full `go test -json` output, killed ones included. `-j N` runs N single
mutants at once, each in its own copy of the module (group runs stay
sequential); on cross-self it cut 490 s to 135 s at `-j 8` with the same
verdicts. Load can flip a verdict either way: a polling witness sees less on a
busy host, turning a kill into a survivor (which fails the run), and a
timing-sensitive test can fail under contention, turning a survivor into a
kill. Gate releases on `-j 1`, or confirm kills there. An enforcement point
with no `//subpoena:enforcement` statement is an error, not a skip, so one
covered function cannot hide an unexamined one. The report starts with the
number of enforcement points and mutants.

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
in the target directory (`<file> | <func> | <removed text> | <reason>`, the
file relative to the module root). That file is a reviewed claim. One entry
accepts one layer: an entry that matches two masked layers (the same text
twice in one function), an entry listed twice, and an entry that no longer
matches a masked layer are errors or fail the run. Markers take no free text:
an unknown argument, a guard marker without its value or off an `if` line, and
a group of one are errors. So is a marker that would take no effect: a
statement or guard marker outside an enforcement point, a point marker that is
not on a function's doc comment, and a misspelt `//subpoena:enforcement...`
comment. A run whose context is canceled is an error, never a verdict.

Discovery, mutation and restoration use the same saved file bytes. Before each
mutation, cross-examination checks that the copied file still matches discovery
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
The Python harness passes its contract checks for the harness, the TraceQL
evaluator and the witness reader; lint and cross-examination are not ported
(`docs/ports.md`). TypeScript has generated names
(`generated/ts/semconv.ts`) and no harness. An exec backstop in the open core
was decided and is not built (`docs/decisions.md`, "The exec backstop"). Tetragon was
the first tier-2 witness; outside Kubernetes its events lack the session
cgroup, so Subpoena has its own (`witnesses/README.md`).
