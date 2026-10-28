# Changelog

## Unreleased

- **Cross: evidence per kill, and crashes.** Each killed mutant reports its
  first evidence, from the first failure message of a failed test: `witness`,
  `testimony` (the harness tags) or `other`. A suite that goes red only by a
  crash (a panic, a runtime fatal error, `os.Exit`, or a failure with no
  message) is `enforcement-mutant-crashed` and fails the run. `-evidence-dir` keeps
  every mutant run's full `go test -json` output.
- **Cross: `-j N` parallel mutants.** Single mutants run N at a time, each in
  its own copy of the module. cross-self: 490 s at `-j 1`, 135 s at `-j 8`, same
  verdicts. Load can flip a verdict either way, so gate on `-j 1`.
- **Cross: `-select` test selection.** Each mutant runs only the tests that
  executed its line in a per-test coverage pass after the baseline. Opt-in: it
  pays off on long suites, not on short ones. A mutant its selected tests do
  not kill runs again on the whole suite, and group runs use the whole suite. A
  test that fails alone, or a selected subset that fails together without any
  mutant, is an error.

- **Guard and layered mutants in `subpoena-cross`.**
  `//subpoena:enforcement_guard true|false` on an `if` forces its condition to
  the bypass value. `group=<name>` on enforcement markers declares layers of one
  guarantee: cross also mutates the whole group, and a layer that survives alone
  but is caught with its group is `enforcement-layer-masked`, naming the masking
  layer. A masked layer fails the run unless `cross-masked.txt` lists it with a
  reason; a stale entry fails too.
- **Breaking:** enforcement markers no longer accept trailing text.
  `//subpoena:enforcement because ...` is now a discovery error; only
  `group=<name>` may follow the marker. A marker that would take no effect (a
  statement or guard marker outside an enforcement point, or a misspelt one) is
  an error too; before, it was ignored and its statement went unexamined.
- **Cross run hygiene.** A timed-out mutant names the packages and tests still
  running at `-timeout`. Ctrl-C (or SIGTERM) cancels the run, killing the
  mutant's test processes and removing the copies. Where a timeout cannot kill
  the test binary (not unix), the run stops at the first timeout. A guard
  marker on a line whose outermost statement is not the `if` (an `if` inside
  an inline closure) is an error.

- **Cross refuses ambiguous `cross-masked.txt` entries.** One entry accepts one
  masked layer; an entry matching two, or listed twice, is an error. An entry
  names the layer's group (`<file> | <func> | group=<group> | <removed text> |
  <reason>`), so a layer moved to another group needs a fresh review. A canceled
  run is an error, not a kill.

- **`harness.WatchSpawns` (Go).** A witness check registered when the witness
  starts that runs at test cleanup, even after an earlier `Fatal`: it stops the
  witness, fails on commands the `SpawnRule` refuses (`Allowed`, `Never`) and on
  missing or bad capture health, and logs every process seen when the test had
  already failed. Moved from GhostGate's test helpers. A `Never` entry's program
  matches with or without a directory (`sleep 1` refuses `/usr/bin/sleep 1`).
- **`harness.CheckNoSpawn`, `CheckNoDial` (Go).** Non-fatal forms of the witness
  absence checks. `subpoena-lint` counts them, and `WatchSpawns`, as asking a
  witness.
- **Name-only sightings are marked.** When `ProcWitness` sees a process only
  by its kernel task name (it exited before its arguments were read),
  `ProcessEvent.CommandSource` is `comm` and `NameOnly()` is true. `WatchSpawns`
  fails on a name-only sighting whose name is a `Never` program, and, with an
  `Allowed` list, on any name-only sighting unless `SpawnRule.ExcuseNameOnly`
  is set and the name is an `Allowed` program. Before, a bare name could slip
  past `Never`.
- **Tagged failure messages.** Harness witness failures start with `witness:`,
  telemetry assertion failures with `testimony:` (Go and Python).
- **Lint: verified `Collect` wrappers.** A test helper that stops the system
  and witness, checks health and calls the harness `Collect` counts as
  `Collect` for `no-trace-assertion` and `unguarded-absence`, but only when
  every `return` hands back the trace from that call. A same-named method that
  doesn't, such as a metrics `Collect`, still doesn't count (`lint/README.md`).
- **`ProcWitness.Coverage` (Go).** The number of full scans and children walks, and
  the longest window in which a process outside the root's children tree could
  have started and exited unseen (from one scan's start to the next one's end,
  or to Stop). A process shorter than that window may have been missed. CI now runs the `BenchmarkProc*` benchmarks (report only).
- **Python harness: span limits (fix).** The Python harness now sets its own
  span limits, all unlimited, so `OTEL_*_LIMIT` variables no longer drop or
  truncate attributes (H1). `collect()` raises `IncompleteError` (`.truncated`)
  when a span lost attributes, events or links (H3). In 0.1.0a1, a span with
  more than 128 attributes silently lost its oldest ones, and
  `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT` truncated values. Both still reported a
  complete capture. `conformance/harness.yaml` gains an `env` field and an
  `env_limits_ignored` case, and the Python runner now applies `filler`.

## Python 0.1.0a1 (2026-10-26)

First PyPI release of the Python port: `pip install subpoena`. The harness,
a native TraceQL subset evaluator and the witness-file reader, passing the
port checks in docs/ports.md (H, Q, W). No lint or cross-examination yet.
Tagged `python/v0.1.0a1`; published from CI through PyPI Trusted Publishing.

## v0.1.0-alpha.1 (2026-10-26)

First alpha. Go only; APIs will change. Everything listed under "Verified" has
run, on a real machine and in CI; anything else says what it is.

### What you get

- **Registry and generated names.** A Weaver registry is the telemetry
  contract; `weaver registry generate` emits Go constants and a per-attribute
  export tier (`test` or `all`). CI checks the registry, diffs it against main,
  and fails if `generated/` is stale.
- **Tier 1: `pkg/harness`.** An in-memory recorder, `Collect()` (force-flush,
  fails on dropped or unfinished spans) and three-valued absence verdicts
  (Pass, Fail, Inconclusive; Inconclusive fails by default).
- **`pkg/traceql`.** A documented TraceQL subset (`docs/traceql-subset.md`)
  evaluated in-process. Tempo is AGPL and is never linked; it runs as a
  separate process in the conformance suite.
- **Witnesses.** `pkg/witness` (`ProcWitness`, polling /proc) and
  `pkg/witness/execbpf` (eBPF, every exec with its cgroup, read in the kernel),
  with `cmd/subpoena-witness` to ship its events. `pkg/cgroup` puts each
  session in a cgroup named with its trace ID, so a witness ties a process to a
  session without trusting the application.
- **`cmd/subpoena-lint`.** unknown-telemetry, no-trace-assertion,
  unwitnessed-enforcement, unguarded-absence, missing-provenance,
  orphan-invariant, provider-override, dead-telemetry, and registry-drift as a
  subcommand. See `lint/README.md`, including its known imprecision.
- **`cmd/subpoena-cross`.** Cross-examination: removes each marked
  enforcement statement and requires the suite to go red.
- **`cmd/subpoena-invgen`.** Generates invariant name constants, from any
  module.
- **`pkg/production`.** Keeps test-tier attributes out of production: an
  exporter wrapper for Go services, and a generated Collector config for
  everything else.
- **Tier 2 and tier 3 examples.** An OATS stack with the eBPF witness, and
  Grafana alert rules (the invariant, plus a liveness rule), for
  `examples/gateway`.
- **A contract for other languages.** `docs/ports.md` says what a Python or
  TypeScript harness must do, and each part has a check: `subpoena-traceql`
  and `subpoena-conform` (any language's evaluator over the corpus),
  `conformance/harness.yaml` (the harness rules as cases), the witness output
  schema (`docs/witness-event.schema.json`, `witness.ReadLog`), and Python and
  TypeScript names generated by Weaver from the same registry.
- **Array attributes are refused.** Measured against Tempo, array values
  follow no rule a subset could copy, so a query that reads one is an error,
  never a verdict (`docs/traceql-subset.md`).
- **Two worked examples.** `examples/gateway` (inside this module) and
  `examples/adopter` (a separate module adopting Subpoena from outside, with
  the commands as Go tools).

### Verified

On Linux 6.17 with rootful Docker, and in CI on GitHub's ubuntu runners:

- `make check`: tests, lint clean, the gateway's enforcement mutant killed.
- `make conformance`: the subset agrees with Tempo 2.8.2 on every query and
  fixture.
- `make test-cgroup`, `make test-ebpf`: real session cgroups; the eBPF witness
  in the kernel, including processes that exit at once.
- `make oats`: both tier-2 cases pass, and both fail against the enforcement
  mutant.
- `make alerts`: the alert rules provisioned into Grafana 13.2 with Tempo 3.1,
  driven through the scheduler: quiet on silence and on clean traffic, firing
  on one violation.
- `examples/adopter`: tests, lint and cross-examination from a separate module.
- `make conform`: the Go evaluator, through the port protocol, agrees on all
  139 cases (13 queries over 9 fixtures, 22 rejected queries).

### Known limits

- Go only. Python and TypeScript harnesses are not written; their contract,
  checks and generated names are.
- No instrumentation helper library yet: spans are written with the OTel API
  and the generated constants.
- The witness interface is process-shaped (`Spawned`). Network, file and
  database witnesses need a sibling interface.
- The lint matches some calls by name, not by type (`lint/README.md`).
- Tetragon is kept only as a draft enforcement policy; it is not the witness.
