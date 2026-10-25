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
  being a test and becomes a standing check.

`invariants/` holds the strings. A test fails if the OATS case or the alert rule
drifts from the invariant file.

## Completeness and three-valued verdicts

A test that says "no span matched" is only meaningful if the capture was
complete. `Collect()` force-flushes, then checks that nothing was dropped (the
recorder counts capacity overflows and spans ending after shutdown) and that
nothing started was left unfinished. If the capture is incomplete it returns an
error and a snapshot marked incomplete. Absence on that snapshot yields
Inconclusive, not Pass. A positive match is still definitive: a span you saw is
there even if others are missing. Inconclusive fails by default.

## Testimony versus proof

Spans are emitted by the code under test. If an enforcement check is deleted,
the code can still emit a span saying the decision was "deny", and no exec span,
because the instrumentation is a separate statement from the enforcement. A
suite that trusts spans alone can be green over broken enforcement.

So enforcement is proven by a witness: something outside the application's
control that observes the side effect directly. Here, process exec events.
Tier 1 uses `ProcWitness`, which polls `/proc` and correlates by cgroup first:
the gateway puts each session's processes in a cgroup named with the trace ID
(`pkg/cgroup`), and the witness reads `/proc/<pid>/cgroup` to tie a process to a
trace, falling back to parent-process lineage when there is no session cgroup.
The exec span records which correlation applies (`subpoena.witness.correlation`).
Production adds Tetragon `process_exec` events shipped to Loki. See
`witnesses/README.md` for the gaps in each.

The toy gateway makes this concrete. `Authorize` is marked
`//subpoena:enforcement_point`, and the tests do not stop at the span: they ask
the witness how many processes were spawned for the trace.

## The fault gate

Tests that look thorough can still be blind to the thing that matters. The gate
checks, per enforcement point, that the suite notices when enforcement is gone.
It copies the module to a temp directory, removes the statement marked
`//subpoena:enforcement` inside each `//subpoena:enforcement_point` function,
and runs the tests. A red suite kills the mutant. A green suite means the tests
cannot tell enforced from unenforced behaviour, and the gate reports
`enforcement-mutant-survived <func>`. It requires a green baseline first, and a
mutant that does not compile is "invalid", never "killed".

## The registry

`registry/` is a Weaver registry: a manifest, `model/*.yaml`, and a dependency on
upstream OTel semantic conventions. It defines the spans and attributes the
system may emit. Every attribute carries a `tier` annotation: `test` attributes
(such as `session.id`) are never exported in production, `all` attributes are.
Go constants are generated into `generated/go/semconv` and are the only source
of telemetry names. `subpoena-lint` rejects names that are not in the registry.
CI checks the registry, diffs it against main, and CODEOWNERS requires review.

## Provenance

Each test file declares whether it was derived from the spec (registry and
docs) or from the implementation. A test written after reading the code tends
to assert whatever the code does, bugs included. The marker makes that visible
to reviewers and to tooling.

## Not decided here

Cross-service registry migration policy, the Python and TypeScript harnesses,
and cgroup names reaching Tetragon events are deferred. The last was checked
on a real node: Tetragon v1.7.1 does not put the session cgroup name in its
exec events (`witnesses/README.md`), so tier 2 correlates by argument.
