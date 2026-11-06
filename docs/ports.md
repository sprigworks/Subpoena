# Porting Subpoena to another language

Subpoena is written in Go, but most of it is not Go-specific. The registry is
language-neutral, and so are the invariants (TraceQL strings), the tier-2 stack
and the tier-3 alert rules. What a Python or TypeScript service needs is a
**harness** in its own test runner. This page is the contract that harness must
meet. Each requirement has a check you can run against the port.

A port has passed when every check below passes. Until then it is a port in
progress, and it says so.

| Port | Status |
| --- | --- |
| Python ([python/](../python/README.md), `pip install subpoena`) | H, Q, W, L and G pass: harness cases, 139 evaluator cases, witness reader with row lines, spawn, network, file and delivery absence checks with the loopback sinkhole, Python AST lint, cross-examination for pytest with groups, selection and parallel runs. Not ported: running a witness (it reads the file `subpoena-witness` writes) and registry-drift |
| TypeScript | generated names only (`generated/ts/semconv.ts`: `SPAN_AGENT_SESSION_EXEC`, `ATTR_SESSION_ID`, `ATTRIBUTE_TIERS`). Harness not started |

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
  empty, so a span's attributes are only what the code set. It sets its own
  span limits, unlimited, so nothing the code recorded is dropped or truncated
  whatever the `OTEL_*_LIMIT` environment variables say, and it records even
  under `OTEL_SDK_DISABLED=true` (or refuses to start). SDKs keep 128
  attributes per span by default, and they do not count a truncated value as
  dropped.
- **H2. Collect before asserting.** `collect()` force-flushes and returns an
  immutable snapshot. Every assertion takes a snapshot; none reads the live
  recorder.
- **H3. Completeness.** A snapshot is *complete* only if no span was dropped
  (the recorder has a fixed capacity; overflow counts as dropped, never as
  silently ignored), no span that started has failed to end, and the SDK
  reported no dropped attribute, event or link on any recorded span. An
  incomplete snapshot is still returned, together with an error that names the
  dropped count, the unfinished spans and the spans that lost data.
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
create (start order, parents, which never end, recorder capacity, filler
attributes), environment variables to set while the case runs, what
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
tests in every language and writes one JSON object per line for each exec, and
with `-deliveries` for each send (W8). A port reads that file. The format is a contract: its schema is
[witness-event.schema.json](witness-event.schema.json), and a Go test keeps
the command's output and the schema in step. The table is an exec line; W7 has
a file line, W8 a delivery line and W9 a row line.

| Field | Type | Meaning |
| --- | --- | --- |
| `time` | RFC 3339 string | when the exec was seen |
| `pid`, `ppid` | integer (int64) | in the process's own PID namespace |
| `host_pid` | integer (int64) | in the initial PID namespace |
| `comm` | string | kernel task name (truncated to 15 bytes) |
| `exe` | string | the path passed to execve (may be relative) |
| `command` | string | `args` joined with spaces |
| `args` | array of strings | argv |
| `cgroup_id` | integer (uint64) | kernel cgroup ID |
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

- **W4. Health comes from the file.** The witness writes a `start` record
  (`{"time", "record": "start", "healthy": false}`) once it is attached and a
  `stop` record (`"record": "stop"`, `"healthy"`, and `"error"` when
  unhealthy) when it stops; a line with a non-null `record` field is a
  record, any other line an exec. The file's capture is healthy only if it
  has exactly one start..stop window, every exec lies inside it, it is
  closed, and its stop says `healthy: true` with no error. Anything else is
  a capture fault: the execs still count, but no absence rests on the file.
  A read error, never a skip: an unknown record kind, a line that is not a
  JSON object (NaN and Infinity included), a time that is not RFC 3339 with
  a zone or is the zero time, a field of the wrong type, an integer outside
  its field's range, and a key that differs from a known field only by
  case. A null field is the same as an absent one.
- **W5. Absence checks.** `no_spawn(witness, trace_id)` is Fail when the
  witness saw any process for the trace (even from an unhealthy capture),
  Inconclusive when it saw none but its health is bad or unreported, and Pass
  only from a healthy witness. `watch_spawns` registers a teardown check with
  a `SpawnRule`: `Never` entries match a command line whose words end with
  theirs, the program compared without its directory on either side;
  `Allowed` matches exactly; a name-only sighting fails when its name is a
  `Never` program, and with an `Allowed` list unless excused. Failure
  messages start with `witness:`.

Check: `conformance/witness.yaml` holds files and what a reader must report
for each (read error, health, spawned PIDs, the no-spawn verdict); the Go
runner is `conformance/witness_test.go`. `pkg/witness/log_test.go` and
`pkg/harness/watch_test.go` hold the reader and `SpawnRule` cases a port must
also pass.

- **W6. Network absence.** `no_dial(witness, trace_id, match)` follows W5's
  rule over `dialed(trace_id)`: one attempt that `match` selects (none: any
  attempt) is Fail even from an unhealthy capture; with none, missing or bad
  health is Inconclusive. `dial_to(addrs)` matches a destination address, a
  zero port matching every port and an IPv4-mapped address matching its IPv4
  form. A rule about a host name needs the test to pin what the name
  resolves to. A port ships the loopback sinkhole: a listener that records
  every arrival for every trace, drains its accept queue when stopped, and is
  healthy only once stopped with no accept or drain error. Go's eBPF network
  witness (`netbpf`) is not ported.

Check: `pkg/witness/sinkhole_test.go` and `pkg/harness/network_test.go`
hold the cases; the Python runner is `python/tests/test_network.py`.

- **W7. File changes.** The file witness is not ported either: Go's
  `FileWatch` runs beside the tests (`subpoena-witness -file-root dir`, no
  privilege) and writes the same kind of file. A line with a non-null `file_op`
  field is one change. `file_op` is `create`, `write`, `rename` or `unlink`;
  `path` is the absolute path, `root` the watched root, `is_dir` a boolean,
  `source` `inotify` or `scan`, `attribution` `root`, and `time` when the
  witness read the event. A rename is two lines, with `rename` `from` and `to`
  and the same `cookie`. The start record names the watched `roots`; the stop
  record may carry a `coverage` line. `wrote(trace_id)` returns every line
  whose `trace_id` is empty or equals it, so a tier-1 line belongs to every
  trace. `no_write(witness, trace_id, *paths)` follows W5's rule: one line that
  touches a path (the path, anything below it, or a rename of a directory
  above it; none: any line) is Fail even from an unhealthy capture. With none,
  a path under no root is Inconclusive, as are missing or bad health. A read
  error, as for an exec: an unknown `file_op`, no `path`, and a field of the
  wrong type. The SQLite reader is Go-only.

Check: the `file_` cases in `conformance/witness.yaml`; the Python runners are
`python/tests/test_witness_cases.py` and `python/tests/test_witness.py`.

- **W8. Delivery lines.** `subpoena-witness -deliveries` also writes one line
  per send from a session cgroup; a line with a non-null `delivery_op` field is
  one, and it comes before the exec reading of a line. The fields are `time`,
  `pid`, `host_pid`, `comm`, `cgroup_id`, `cgroup`, `trace_id` and `attribution`
  as above, and:

  | Field | Type | Meaning |
  | --- | --- | --- |
  | `delivery_op` | `"deliver"` or `"sendmsg"` | a send on a connected socket, or one that named its destination |
  | `protocol` | string | `tcp`, `udp`, or another IP protocol name or number |
  | `peer` | string | the far end, `address:port` or `[address]:port`; empty when the witness could not read it |
  | `local` | string | this end, in the same form; empty when unknown |
  | `bytes` | integer (uint64) | what the caller asked to send, not what the peer received |

  A stop record may carry `coverage`, one line on what the capture might have
  missed even when healthy. W3 and W4 apply: `delivered(trace_id)` returns every
  line whose `trace_id` equals it, the empty trace ID matches nothing, and a line
  outside the window is a capture fault. A read error, never a skip: an unknown
  `delivery_op`, and a `peer` or `local` that is not empty and does not parse. An
  empty `peer` is not an error: such a send may have gone to any peer.
  `no_delivery(witness, trace_id, match)` follows W6's rule over `delivered`.
  `delivery_to(peers)` matches a send that may have gone to a peer: a zero port
  matches every port of the address, an unspecified address matches the port on
  any address, an IPv4-mapped address matches its IPv4 form, a send with an
  unknown peer or no port matches, and naming no peers matches every send. A port
  reads the file; it does not run this witness, which has no tier 1 in any
  language.

Check: the `delivery_` cases in `conformance/witness.yaml` (`delivered`,
`no_delivery`, `no_delivery_peers`); the matching rules are in
`pkg/harness/delivery_test.go`, and the Python runner is
`python/tests/test_delivery.py`.

- **W9. Row lines.** The database witness (`pkg/witness/dbproxy`) is not ported;
  `subpoena-witness db` runs it and writes the same file format, with one line
  per statement. A line with no `record` field and a non-null `event` field is
  a row line; `event` is `row`, and any other value is a read error.

  | Field | Type | Meaning |
  | --- | --- | --- |
  | `engine` | `"postgres"` or `"mysql"` | the wire protocol |
  | `conn` | integer | the witness's number for the connection |
  | `dest` | string | the address the application connected to |
  | `statement`, `verb` | string | SQL as sent, cut at 8 KiB; first keyword. Never bound values |
  | `tables` | array of strings | tables written; a Postgres name is cut to the 63 bytes the server keeps |
  | `opaque`, `reason` | boolean, string | it may have written anything, and why. A call, on Postgres a qualified column, operator or cast, is opaque unless it is proven inert |
  | `rows` | integer | rows changed, -1 if unknown |
  | `outcome` | string | `read`, `committed`, `rolled_back`, `failed` or `unknown` |
  | `attribution` | `"destination"` | it holds for every trace |

  `committed(trace_id)` returns every line with outcome `committed`, for every
  trace, the empty ID included. A line is an effect if it is committed and `rows`
  is not 0. It counts against a table if it is opaque, names no table, or a name
  matches without case on its dotted parts from the right. A line with `rows`
  missing, null or below -1 is a read error, never a skip: read as 0, it would be
  no effect. So is an `outcome` outside the five. A row outside the capture
  window, or with outcome `unknown`, is a capture fault. `unknown` is also what a
  routine gets that failed or rolled back where it could have committed part of
  its work, so `failed` means the server refused the statement and nothing of it
  stayed, as far as the wire can say. W4's other rules apply.
  The file cannot show what only the catalog knows: a view over a writing function,
  or an overload of a built-in name installed before the capture, reads as a plain
  read (`witnesses/README.md` has the list of what is never seen).
  A port ships the reader; a `no_row` check over it is not in Python yet, so a
  Python test reads `committed` and `health` itself.

Check: the row cases in `conformance/witness.yaml`, through both runners, and
`pkg/witness/logrow_test.go`, which `python/tests/test_witness.py` ports.

## L and G: lint and cross-examination

- **L1.** A port's lint applies the same rules as `lint/README.md`, adapted
  to the language: no telemetry string literals, `collect()` before
  telemetry assertions, a witness call in every enforcement-point test, and
  provenance markers. Python runs `subpoena-lint <dir>` (or
  `python -m subpoena.lint <dir>`); its eight rules are tested in
  `python/tests/test_lint.py`. Registry-drift remains a Go-only subcommand.
- **G1.** A port's cross-examination removes each statement marked as enforcement and
  requires the suite to fail. A mutant that does not compile or import counts
  as invalid, not killed. So does a marked return with no honest stand-in: one
  that ends the function, in a function that gives None on no other path, where
  None could force enforcement on. As in Go: a guard marker forces an `if` condition;
  a red suite is a kill only on an assertion failure in test code (an
  assertion in the code under test, a crash, an exception other than an
  assertion, or a dead test process is `crashed`; an assertion library's own
  failure type counts as an assertion, as webtest's status check does in
  Python); a hang, or a test-framework
  timeout, is `timeout`; a kill that passes when run again with the mutant, or
  fails in a rerun without it, is `unconfirmed`, which fails the run, and `-select` does not retry
  it on the whole suite; a marker that takes no effect, and an enforcement point with no
  statement marker, are errors; the baseline must be green. Python's
  `subpoena-cross` also refuses a mutant the suite never imported from the
  copy (an installed package shadowing it) as invalid. It also implements layer
  groups, reviewed `cross-masked.txt`, `-j`, `-select` and `-evidence-dir`;
  `python/tests/test_cross_parity.py` checks these with real pytest runs. It
  reads pytest-xdist workers (`-- -n 4`) the same way; only `-select` refuses
  them, since per-test coverage needs one process.

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
