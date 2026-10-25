# Witnesses

A witness is an observer of side effects that the application does not
control. Subpoena's rule: the system's own spans are testimony, not proof. The
code that enforces a policy is also the code that emits the span saying it did.
If that code is wrong, the span can be wrong in the same direction. Enforcement
is proven only by something outside the process: "no `exec` happened" must be
checked by a process-exec observer, not by the absence of an `agent.session.exec`
span.

The Go interface is `pkg/witness.Witness`:

```go
Spawned(traceID string) []ProcessEvent
```

## Tier 1: `ProcWitness` (runs in `go test`)

Polls `/proc`, reports processes that appeared after `Start()` and descend from
the gateway process by ppid lineage, and reads `/proc/<pid>/cgroup` to tie a
process to a trace when a cgroup path contains the trace ID.

It is a unit-test stand-in, and it is honest about its gaps:

- Polling can miss a process that lives less than the polling interval (2ms by
  default). Tests spawn something that lives a little longer (the toy gateway
  runs `sleep 0.15`). A kernel-side witness has no such gap.
- A Go program's first `os/exec` call forks a throwaway probe (the runtime
  checking pidfd support) that briefly carries the parent's command line.
  `Start()` absorbs it with a warm-up exec; found the hard way as an
  intermittent phantom second process.
- Lineage is lost if an intermediate parent exits first.
- Lineage alone cannot say which trace a process belongs to. `Spawned` therefore
  returns lineage-only events for every trace and excludes only events whose
  cgroup is named with a different trace ID. That over-reports, which is the
  safe direction for an absence claim, and it is exact when one trace is in
  flight, as in a unit test.

## Production design (not built here)

1. One cgroup per agent session, named with the session's trace ID
   (`.../subpoena/<trace-id>`). The gateway creates it at session open and
   starts every child the session spawns inside it. The cgroup is the
   correlation key because it survives double-forks and reparenting, which
   lineage does not.
2. Cilium Tetragon runs on the node and emits `process_exec` events from the
   kernel. They are exported as JSON, shipped to Loki (Alloy or Promtail), and
   labelled with the cgroup name, giving a log line per exec with the trace ID.
3. The witness query is LogQL, and the same string runs in OATS (tier 2) and in
   an alert rule (tier 3): zero exec lines for a trace that was denied.
4. Lineage stays as a secondary signal, for cases where cgroup creation fails.
   A process outside the session cgroup but inside the gateway's lineage is
   itself a finding.

Open item to validate on a real node: how the cgroup name reaches the Tetragon
event. Candidates are a Tetragon field if the version exposes one, or an
Alloy pipeline stage that resolves cgroup id to name. `tetragon/` is a draft
that has never been loaded into a kernel; check it with `tetra getevents`
before relying on it.

## Layout

- `tetragon/process-exec.yaml`: TracingPolicy for exec events.
- `../pkg/witness/`: interface and `ProcWitness`.
