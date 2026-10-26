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

## Tier 2 and production: `execbpf` (kernel-side)

`pkg/witness/execbpf` is Subpoena's own kernel-side witness, and
`cmd/subpoena-witness` runs it as a daemon writing one JSON line per exec.
An eBPF program on the `sched_process_exec` tracepoint (`tp_btf`, BTF and
Linux 5.8+) records, in the kernel at the moment of exec:

- the cgroup ID (`bpf_get_current_cgroup_id`, equal to `pkg/cgroup`'s
  `Group.ID()`) and the cgroup path, up to 8 elements;
- the process and parent IDs in the witness's own PID namespace, and in the
  initial one;
- the executable path and up to 511 bytes of argv.

A process in a session cgroup is attributed to that trace (`ByCgroup`). With
`Config.RootPID`, a `sched_process_fork` hook also follows lineage
(`ByLineage`), with ProcWitness's semantics. Compared with ProcWitness,
nothing is too short-lived to be seen, and the cgroup is read before the
process can move or exit. It observes; it does not block.

Needs root (or CAP_BPF plus CAP_PERFMON), cgroup v2 and BTF.
`make test-ebpf` runs its kernel tests in a privileged container: execs in a
real session cgroup are attributed with the right cgroup ID, a process that
exits at once is seen, lineage follows a fork that never execs, and a burst
of execs before `Stop` is not lost. In the OATS stack it is the witness for
both cases (`examples/gateway/oats/README.md`).

### How other witnesses identify a process's cgroup

The kernel's own identity for a cgroup is its path, or its 64-bit cgroup ID
(the cgroupfs inode number). `pkg/cgroup` exposes both (`Group.Path`,
`Group.ID`), so a witness that reports either can join a process to a session.

| Witness | Reports | Session correlation |
| --- | --- | --- |
| `execbpf` (here) | cgroup ID and path | Yes; verified |
| `ProcWitness` (here) | cgroup path, from `/proc` | Yes; verified (polls, can miss short processes) |
| Falco | cgroup path (`thread.cgroups`) | Should work by path; not tested |
| Tracee | cgroup ID per event | Should work by ID; not tested |
| bpftrace | cgroup ID (`cgroup`), path (`cgroup_path`) | Yes, by either; not tested |
| Tetragon, outside Kubernetes | no cgroup; `process.docker` only when the leaf name looks like a container ID | No (see below) |
| auditd | no cgroup in exec records (the container-ID patches did not merge) | No |

A 64-hex name is not a cgroup standard: it is the shape of a Docker/OCI
container ID, which these tools look for in cgroup paths. Session cgroups are
not containers, and Subpoena does not disguise them as containers.

### Tetragon

Tetragon was the tier-2 witness first, and runs fine (v1.7.1 on Linux 6.17;
v1.4.0's kprobe program was rejected by that kernel). Outside Kubernetes its
`process_exec` events carry binary, arguments, cwd, pid, uid, `exec_id`,
`parent_exec_id` and `in_init_tree`, but no cgroup path, name or ID. Its one
cgroup-derived field, `process.docker`, is filled only when the leaf cgroup
name passes its container-ID heuristic, truncated to 31 characters. Tested: a
32-hex trace-ID leaf yields nothing; a 64-hex leaf yields 31 characters.

Tetragon can also enforce (kill a process in the kernel), which execbpf does
not. `tetragon/process-exec.yaml` loads on v1.7.1 and is kept as a draft; it is
not part of the tier-2 stack and has never enforced anything. To kill only a
denied session's processes it needs the session's cgroup, which it does not see
outside Kubernetes, so off Kubernetes it is unproven as a backstop.

## Production design

1. One cgroup per agent session, named with the session's trace ID
   (`.../subpoena/<trace-id>`). **Built** in the gateway; validated on a real
   cgroup v2 mount and in the OATS stack.
2. A kernel-side witness on the node reports every exec with its cgroup.
   **Built** (`execbpf`, `subpoena-witness`); runs in the OATS stack, its
   events shipped to Loki.
3. The witness query is LogQL, and the same string runs in OATS (tier 2) and
   in an alert rule (tier 3). The OATS cgroup case asserts exactly one exec in
   any session cgroup across an allowed and a denied request.
4. Lineage stays as a secondary signal, for when cgroup creation fails. A
   process outside the session cgroup but inside the gateway's lineage is
   itself a finding.
5. A kernel-side backstop (not built): an optional, per-session-cgroup exec
   backstop in the open core, decided in `docs/decisions.md` amendment 4, with
   Tetragon as the alternative where Kubernetes is in use. It is a test
   backstop, not an agent guardrail. In tests a backstop intervention counts
   as a failure, and cross-examination runs with the backstop observing only.

## Layout

- `../pkg/witness/`: interface and `ProcWitness`.
- `../pkg/witness/execbpf/`: the kernel-side witness; `bpf/exec.c` is the eBPF
  program (dual MIT/GPL-2.0, as the kernel requires for its helpers).
- `../cmd/subpoena-witness/`: runs it as a daemon, JSON lines out.
- `../pkg/cgroup/`: per-session cgroup creation, placement and IDs, shared by
  the gateway and the witnesses.
- `tetragon/process-exec.yaml`: TracingPolicy kept for enforcement.
