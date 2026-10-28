# gateway: the reference example

A toy agent gateway that runs all three tiers. It has four operations: open
a session, authorize an action, exec a command, and fetch from a named
upstream. It has two enforcement points:

- `Authorize`: when it denies, no command may run in that session.
- `Fetch`: when the host is denied, nothing may be sent to it.

The invariant is `invariants/no_exec_after_deny.traceql`, from the root
registry, and the span and attribute names come from `generated/go/semconv`.

| Where | What it checks |
| --- | --- |
| `gateway_test.go`, `server_test.go` | Tier 1. A denied session leaves a denial span and no exec span, and `ProcWitness` saw no process. An allowed session execs exactly once, so the absence is not vacuous. |
| `fetch_test.go` | A denied fetch never reaches the host. Only the `Sinkhole` witness, which sees the connection arrive, can show this, because the spans say "denied" either way. |
| `cgroup_test.go` | One cgroup per session, named with the trace ID, so a kernel witness can tie each exec to its session. |
| `oats/` | Tier 2. The same invariant on a real collector and Tempo, with `subpoena-witness` (eBPF) shipping exec events to Loki. One case is correlated by cgroup and one by command-line argument. See [oats/README.md](oats/README.md). |
| `alerts/` | Tier 3. The same TraceQL string as a Grafana alert rule, plus a rule that fires when authorize spans stop arriving. |
| `production/` | A Collector config that drops test-only attributes before production. |

## Run it

From the repository root:

```
go test ./examples/gateway/...                               # tier 1
go run ./cmd/subpoena-lint -dead-telemetry ./examples/gateway # lint
go run ./cmd/subpoena-cross ./examples/gateway                # cross-examination: both mutants killed
make oats      # tier 2: rootful Docker, cgroup v2, kernel BTF
make alerts    # tier 3: Docker
```

`make test`, `make lint` and `make cross` run the first three.
