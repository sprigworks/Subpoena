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

## Correlation: cgroup first, lineage second

Which process belongs to which trace is the hard part. Three modes exist, and
the gateway records which one a given exec supports on the exec span, as
`subpoena.witness.correlation` (registry, tier `test`):

| Value | Meaning | Strength |
| --- | --- | --- |
| `cgroup` | The exec was started inside a cgroup named with the session's trace ID | Strong. Survives double forks and reparenting; readable by a kernel-side witness |
| `lineage` | No session cgroup; a witness follows parent-process lineage | Weak. Lost if an intermediate parent exits; cannot tell concurrent traces apart |
| `argument` | No cgroup and no usable lineage; a distinguishing command-line argument is the key | Weakest. Only for a rig where the caller controls the arguments (the OATS fallback case) |

Like every span attribute this is testimony: it says what the gateway believes.
The witness decides for itself by reading the process's cgroup, and does not
need the attribute.

### The gateway (`examples/gateway`, `pkg/cgroup`)

At session open, the gateway creates `<root>/<trace id>`, with `<root>` from
`SUBPOENA_CGROUP_ROOT` (default `/sys/fs/cgroup/subpoena`), and starts every
exec inside it. On a real cgroup v2 the child is created directly in the group
(`CLONE_INTO_CGROUP`, Linux 5.7+, through `SysProcAttr.CgroupFD`), so it is
never outside the group, not even for an instant. Where that is unavailable the
child is started normally and its PID is written to `cgroup.procs`; a process it
forks in the window between start and write would escape. `Session.Close`
removes the (by then empty) cgroup; the HTTP handler calls it.

Any failure falls back to the previous behaviour and is logged once, at debug
level: no permission, no cgroup v2, a root that is not cgroupfs, a PID that
cannot be written. `Create` refuses a root without a `cgroup.controllers` file
rather than make a plain directory: on cgroup v1 and hybrid hosts (including
many CI sandboxes) `/sys/fs/cgroup` is a tmpfs where `mkdir` succeeds and
isolates nothing. The fallback mode is `lineage`, or `argument` with
`SUBPOENA_CORRELATION_FALLBACK=argument` (the OATS stack sets it).

A hybrid host has its cgroup2 mount at `/sys/fs/cgroup/unified`; point
`SUBPOENA_CGROUP_ROOT` there (for example `/sys/fs/cgroup/unified/subpoena`).
The witness compares only the last element of the root with the path in
`/proc/<pid>/cgroup` (`.../subpoena/<trace id>`), because that path is relative
to the mount or cgroup namespace and cannot be derived from the filesystem path.

**Stand-in directory for tests.** If `SUBPOENA_CGROUP_ROOT` is a plain directory
that contains a `cgroup.controllers` file, `Create` treats it as a deliberate
stand-in, makes the `cgroup.procs` file cgroupfs would have made, and PIDs are
written into it. That exercises the whole write path with no privileges, and is
what most of the unit tests do. Under a stand-in the processes are not really
isolated, so a witness reading `/proc` sees them by lineage. Tests that need a
real cgroup (`TestRealCgroup`, `TestStartIntoIsAtomic`,
`TestRealCgroupSessionIsWitnessedByCgroup`) use one when the machine allows it
(root or a delegated subtree; `SUBPOENA_CGROUP_REAL_ROOT` names a parent to try)
and skip otherwise.

## Tier 1: `ProcWitness` (runs in `go test`)

Polls `/proc` and reports processes that appeared after `Start()`. Cgroup
correlation is preferred: a process whose `/proc/<pid>/cgroup` path contains a
session cgroup (`<root base>/<trace id>`, root from `ProcWitness.CgroupRoot` or
`SUBPOENA_CGROUP_ROOT`) is attributed to that trace (`ByCgroup`), and is
noticed even when it is not a descendant of the watched process. A process in no
session cgroup falls back to ppid lineage from the watched process (`ByLineage`).

It is a unit-test stand-in, and it is honest about its gaps:

- Polling can miss a process that lives less than the polling interval (2ms by
  default). Tests spawn something that lives a little longer (the toy gateway
  runs `sleep 0.15`). A kernel-side witness has no such gap.
- A Go program's first `os/exec` call forks a throwaway probe (the runtime
  checking pidfd support) that briefly carries the parent's command line.
  `Start()` absorbs it with a warm-up exec; found the hard way as an
  intermittent phantom second process.
- Lineage is lost if an intermediate parent exits first. A cgroup is not.
- Lineage alone cannot say which trace a process belongs to. `Spawned` therefore
  returns lineage-only events for every trace and excludes only events whose
  cgroup is named with a different trace ID. That over-reports, which is the
  safe direction for an absence claim, and it is exact when one trace is in
  flight, as in a unit test. A process in a session cgroup is returned for that
  trace only.
- A process that is a descendant but outside every session cgroup, while the
  gateway uses cgroups, is returned by lineage and is itself worth a look: it
  escaped the session.

## Production design (partly built)

1. One cgroup per agent session, named with the session's trace ID
   (`.../subpoena/<trace-id>`). **Built** in the gateway (above); validated on a
   real cgroup v2 mount and in the OATS stack next to Tetragon.
2. Cilium Tetragon runs on the node and emits `process_exec` events from the
   kernel, exported as JSON and shipped to Loki. **Runs** in the OATS stack
   (Tetragon v1.7.1, Linux 6.17). The events are **not** labelled with the
   session cgroup name: see the open item below.
3. The witness query is LogQL, and the same string runs in OATS (tier 2) and in
   an alert rule (tier 3): zero exec lines for a trace that was denied. The
   OATS case that runs, `oats-case-argument.yaml`, correlates by argument;
   `oats-case.yaml` (by cgroup) is blocked on item 2.
4. Lineage stays as a secondary signal, for cases where cgroup creation fails.
   A process outside the session cgroup but inside the gateway's lineage is
   itself a finding.

Open item, narrowed on a real node (2026-10-25, Tetragon v1.7.1, outside
Kubernetes): **the cgroup name does not reach the event.** A `process_exec`
event carries binary, arguments, cwd, pid, uid, `exec_id`, `parent_exec_id`
and `in_init_tree`; no cgroup path, name or ID. The one cgroup-derived field is
`process.docker`, which Tetragon fills from the process's leaf cgroup name only
when the name passes its container-ID heuristic (64 characters of hex, among
other runtime patterns), truncated to 31 characters. Tested: a leaf named with
a 32-hex trace ID yields no `docker` field; a 64-hex leaf yields its first 31
characters. An Alloy stage cannot resolve a cgroup ID to a name either, since
the event has no ID.

Ways forward, none taken yet: name the session cgroup with 64 hex characters
so `process.docker` carries 31 of them (depends on a Tetragon heuristic and
truncates the trace ID to 124 bits); run Tetragon in Kubernetes mode; or
contribute a cgroup-name field upstream. Until then cgroup correlation is
unproven at tier 2, and the argument case is the one that runs.

`tetragon/process-exec.yaml` loads on Tetragon v1.7.1 (not on v1.4.0, whose
kprobe program the 6.17 kernel rejected). It adds nothing the exec events need
today; it is kept for the later switch to enforcement.

## Layout

- `tetragon/process-exec.yaml`: TracingPolicy for exec events.
- `../pkg/witness/`: interface and `ProcWitness`.
- `../pkg/cgroup/`: per-session cgroup creation and placement, shared by the gateway and the witness.
