# Porting Subpoena to another language

Subpoena is written in Go, but most of it is not Go-specific. The registry is
language-neutral, and so are the invariants (TraceQL strings), the tier-2 stack
and the tier-3 alert rules. What a Python or TypeScript service needs is a
**harness** in its own test runner. This page is the contract that harness must
meet. Each requirement has a check you can run against the port.

A port has passed when every check below passes. Until then it is a port in
progress, and it says so.

## What a port is, and what it reuses

| Piece | Port writes its own | Reuses from this repo |
| --- | --- | --- |
| Generated names | nothing: Python and TypeScript are generated | `registry/`, Weaver |
| Tier-1 harness | yes (H1–H6) | — |
| TraceQL evaluation | optional (Q1–Q3) | `subpoena-traceql`, until it has its own evaluator |
| Witness | a reader for its tests (W1–W3) | `subpoena-witness`, `pkg/cgroup` conventions |
| Lint | eventually (L1) | the rule set and its meaning (`lint/README.md`) |
| Cross-examination | eventually (G1) | the marker and the mutation it applies |
| Tiers 2 and 3 | nothing | OATS stack, alert rules |

## H: the tier-1 harness

- **H1. One provider, from the harness.** The harness owns the tracer provider
  that the code under test uses. It samples every span, and its resource is
  empty, so a span's attributes are only what the code set.
- **H2. Collect before asserting.** `collect()` force-flushes and returns an
  immutable snapshot. Every assertion takes a snapshot; none reads the live
  recorder.
- **H3. Completeness.** A snapshot is *complete* only if no span was dropped
  (the recorder has a fixed capacity; overflow counts as dropped, never as
  silently ignored) and no span that started has failed to end. An incomplete
  snapshot is still returned, together with an error that names the dropped
  count and the names of the unfinished spans.
- **H4. Three verdicts.** `absent(q)` is Fail if `q` matches any trace (even
  from an incomplete snapshot), Pass if it matches none and the snapshot is
  complete, and Inconclusive otherwise. `exists(q)` is Pass on a match, Fail on
  no match from a complete snapshot, and Inconclusive otherwise. A query that
  does not parse is an error, never a verdict.
- **H5. Inconclusive fails.** The test-runner helpers (`require_absent`,
  `requireExists`, …) fail the test on Inconclusive. Downgrading it is an
  explicit per-call option, off by default.
- **H6. The snapshot's model is the evaluator's.** Spans convert to `{trace
  id, span id, parent span id, name, attributes}`. IDs are lower-case hex
  (32 and 16 digits). Attribute values are string, bool, int64 or float64.
  Array and map values are kept as "unsupported", and a query that reads an
  attribute holding one is an error, never a verdict
  ([traceql-subset.md](traceql-subset.md#why-arrays-are-refused)).

Check: `conformance/harness.yaml` holds these rules as cases: spans to
create (start order, parents, which never end, recorder capacity), what
`collect()` must report, and the verdict and the Require helper's outcome for
each assertion. A port runs every case through its own harness. The Go runner
is `conformance/harness_test.go`.

## Q: TraceQL

- **Q1. The subset, and only the subset.** Queries follow
  [traceql-subset.md](traceql-subset.md). Anything outside it is rejected at
  parse time, never evaluated as something else.
- **Q2. Same answers as Go and Tempo.** For every query in the corpus over
  every fixture, the port returns exactly the trace IDs in
  `conformance/expected.yaml`.
- **Q3. Same rejections.** Every query in `conformance/rejected.traceql`
  fails to parse, and every (query, fixture) pair under `unsupported:` in
  `expected.yaml` is refused for reading an array or map value.

A port does not need its own evaluator to start. `subpoena-traceql` is the Go
evaluator as a command, and a harness can shell out to it:

```
subpoena-traceql QUERY_FILE TRACES_FILE
```

`TRACES_FILE` is OTLP/JSON (an `ExportTraceServiceRequest`, the format of
`conformance/fixtures/`). The command prints the matching trace IDs, one per
line, sorted, and exits 0. It exits 2 if the query does not parse, 3 if it
reads an attribute that holds an array or map in the traces (the reason goes
to stderr in both cases), and 1 on any other error.

Check: `subpoena-conform` runs any command that speaks that protocol over the
whole corpus, and compares its output with `expected.yaml` and
`conformance/rejected.traceql`:

```
go run ./cmd/subpoena-conform -- python -m subpoena.traceql
```

It runs the command once per (query, fixture) pair and once per rejected
query. It exits 0 only if every answer matches. CI runs it against
`subpoena-traceql`, which keeps the protocol honest.

## W: the witness

The witness is not ported. `subpoena-witness` (Linux, eBPF) runs beside the
tests in every language and writes one JSON object per line for each exec. A
port reads that file. The format is a contract: its schema is
[witness-event.schema.json](witness-event.schema.json), and a Go test keeps
the command's output and the schema in step.

| Field | Type | Meaning |
| --- | --- | --- |
| `time` | RFC 3339 string | when the exec was seen |
| `pid`, `ppid` | integer | in the process's own PID namespace |
| `host_pid` | integer | in the initial PID namespace |
| `comm` | string | kernel task name (truncated to 15 bytes) |
| `exe` | string | the path passed to execve (may be relative) |
| `command` | string | `args` joined with spaces |
| `args` | array of strings | argv |
| `cgroup_id` | integer | kernel cgroup ID |
| `cgroup` | string | cgroup path without the hierarchy root, such as `subpoena/<trace id>` |
| `trace_id` | string, optional | the session's trace ID, from its cgroup name |
| `attribution` | `"cgroup"`, optional | present when `trace_id` is |

Readers ignore fields they do not know. New fields may be added; existing
ones keep their name and meaning.

- **W1. Ask the witness, not the spans.** A test of an enforcement point
  (`//subpoena:enforcement_point` in Go) asks the witness what ran for the
  session's trace ID. Its own spans are testimony.
- **W2. Sessions run in their trace's cgroup.** The code under test starts a
  session's processes in a cgroup named after its trace ID, under the witness's
  cgroup root (the convention of `pkg/cgroup`). That name is what the kernel
  side reads, so the application cannot misreport it.
- **W3. Spawned over-reports.** `spawned(trace_id)` returns every line whose
  `trace_id` equals it. It must not filter on anything the application
  controls (command name, arguments). A line that does not decode, or has no
  `time`, is an error naming its line number, never skipped: skipping it could
  turn an exec into an absence. The empty trace ID matches nothing.

Check: the Go reader `witness.ReadLog` is the reference;
`pkg/witness/log_test.go` holds the cases a port's reader must also pass.

## L and G: lint and cross-examination

- **L1.** A port's lint applies the same rules as `lint/README.md`, adapted
  to the language: no telemetry string literals, `collect()` before
  telemetry assertions, a witness call in every enforcement-point test, and
  provenance markers.
- **G1.** A port's cross-examination removes each statement marked as enforcement and
  requires the suite to fail. A mutant that does not compile or import counts
  as invalid, not killed.

Neither is needed to start. Until a port has them, it says so.

## Generated names

The registry generates one constants module per language, with Weaver, from
`weaver-templates/registry/<language>/`:

| Language | File | Names |
| --- | --- | --- |
| Go | `generated/go/semconv/semconv.go` | `SpanAgentSessionExec`, `AttrSessionId`, `AttributeTiers` |
| Python | `generated/python/semconv.py` | `SPAN_AGENT_SESSION_EXEC`, `ATTR_SESSION_ID`, `ATTRIBUTE_TIERS` |
| TypeScript | `generated/ts/semconv.ts` | `SPAN_AGENT_SESSION_EXEC`, `ATTR_SESSION_ID`, `ATTRIBUTE_TIERS` |

Each holds the span names, attribute keys, enum values and the per-attribute
export tier (`test` or `all`; see `pkg/production`). A port's code and tests
take every telemetry name from its module, never a string literal. CI
regenerates all three, compiles the Python and TypeScript, and fails if any is
stale; `pkg/production/languages_test.go` checks the three agree.
