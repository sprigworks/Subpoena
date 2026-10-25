# Conformance: pkg/traceql versus a real Tempo

`pkg/traceql` evaluates a documented subset of TraceQL
([docs/traceql-subset.md](../docs/traceql-subset.md)). It is only trustworthy if
it agrees with Tempo, so this directory proves that: the same OTLP traces and
the same queries go through the subset evaluator and through a real Tempo, and
the sets of matching trace IDs must be identical.

Tempo is AGPL-3.0, so it is a separate process reached over HTTP and never a
linked dependency. Nothing here imports Tempo code.

## Two tests, two jobs

| Test | Needs | What it proves |
| --- | --- | --- |
| `TestSubsetMatchesExpected` (and the fixture checks) | nothing | `pkg/traceql` returns exactly the results in `expected.yaml` for every query over every fixture. The fixtures and the table are verified in CI. |
| `TestTempoAgreesWithSubset` | Tempo, Docker | A real Tempo returns the same trace IDs as `pkg/traceql` for every query over every fixture. Opt-in: skips unless `SUBPOENA_CONFORMANCE_REQUIRE=1` or `SUBPOENA_TEMPO_URL` is set, so `make test` never touches the network. |

`expected.yaml` was derived by hand from the subset documentation, before the
evaluator was run against it. Together the two tests say: the docs, the
evaluator and Tempo agree.

## Running it locally

```
make conformance
```

starts `docker-compose.yml` (Tempo only, pinned image, OTLP/HTTP on host port
14318 and the query API on 13200, offset so it can run beside a local LGTM stack), runs the Tempo test with `SUBPOENA_CONFORMANCE_REQUIRE=1`
(an unreachable Tempo is a failure, not a skip), and tears it down. By hand:

```
docker compose -f conformance/docker-compose.yml up -d
SUBPOENA_CONFORMANCE_REQUIRE=1 go test ./conformance -run TestTempo -v -count=1
docker compose -f conformance/docker-compose.yml down -v
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `SUBPOENA_TEMPO_URL` | `http://localhost:13200` | Tempo query API (`/ready`, `/api/search`); setting it opts in to the comparison |
| `SUBPOENA_OTLP_URL` | `http://localhost:14318` | OTLP/HTTP receiver (`/v1/traces`) |
| `SUBPOENA_CONFORMANCE_REQUIRE` | unset | `1`: fail instead of skip when Tempo is unreachable |

Point the URLs at any Tempo (the OATS stack's, for example). Stray traces from
other sources in a shared Tempo are ignored; only the fixtures' trace IDs are
compared.

## What the Tempo test does

1. `GET /ready` decides between running and skipping (opted in, unreachable
   is a skip, or a failure under `SUBPOENA_CONFORMANCE_REQUIRE=1`), then waits for 200.
2. Pushes each fixture to `POST <otlp>/v1/traces` as OTLP/JSON, with timestamps
   rebased to now (Tempo searches a time window; the fixtures carry fixed ones).
3. Waits for ingestion by polling `/api/search` until every fixture trace ID is
   listed. It lists with `{ true }` rather than searching by ID, so it does not
   depend on a trace-ID intrinsic being available in the Tempo version.
4. For every query, runs `/api/search?q=<traceql>` and `pkg/traceql`, and fails
   on any difference, naming the query, the fixture and the trace ID, and which
   side matched. A query Tempo rejects is a failure too: a query that parses in
   the subset must mean the same thing in Tempo.

The client, the push/poll/compare path and its ability to notice a
disagreement are themselves tested against an in-process fake Tempo
(`tempo_test.go`), so they run everywhere.

## Layout

```
fixtures/*.json       OTLP/JSON export requests (8), one scenario each
queries/*.traceql     construct queries; the invariants/*.traceql files are queried too
expected.yaml         expected matches per (query, fixture)
docker-compose.yml    Tempo only
tempo.yaml            minimal Tempo config (OTLP/HTTP in, fast search availability)
otlp.go               OTLP/JSON model, fixture loader, conversion to traceql.Trace
tempo.go              HTTP client and the comparison run
```

Fixtures: `deny_then_exec_violation`, `deny_without_exec`, `allow_then_exec`,
`nested_descendant_vs_direct_child`, `attribute_type_mismatch`,
`multiple_traces_one_push` (three traces, interleaved spans),
`missing_attribute_and_orphan`, `repeated_names_deep_chain`.

## Adding to the corpus

New invariant: it is picked up automatically; add its row to `expected.yaml`.
New construct query: add `queries/<name>.traceql` and a row. New fixture: add
`fixtures/<name>.json` with unique trace IDs that do not start with `0`, then
extend the rows that should match. The tests fail until the table is complete.

## Status

The fixture and subset half runs and is green in `make check`. The Tempo half
has **not been run against a real Tempo** (no Docker in the sandbox where this
was written); it is exercised only against the fake. Two expectations are the
likeliest to expose a real difference and are worth looking at first on the
first real run: `!=` across a type mismatch (`int_attr_ne_string_literal`) and
the missing-attribute case under `!=` (`authorize_not_denied`). If Tempo
disagrees, either the docs and evaluator change or the query leaves the subset;
the table is never edited to make the comparison pass.
