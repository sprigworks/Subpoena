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

Its siblings are `NetworkWitness` (`Dialed`) and `FileWitness` (`Wrote`), under
the same rules.

## Capture health and absence

`Spawned` remains a raw observation API. Zero observations alone cannot certify
absence. Stop the witness, call the harness's `Collect()`, then use:

```go
harness.RequireNoSpawn(t, w, traceID)
```

`harness.NoSpawn(w, traceID)` returns a verdict and diagnostic error. An observed
process is Fail even with unhealthy capture; zero processes is Pass only when
the optional `witness.HealthReporter` (`Health() error`) reports healthy capture.
Unknown health, capture still running, or a known capture failure yields
Inconclusive. `RequireNoSpawn` fails on both Fail and Inconclusive.
`CheckNoSpawn` and `CheckNoDial` are the non-fatal forms: they report the
failure and let the test go on, so one failing run can show every kind of
evidence. Witness failures start with `witness:` and telemetry failures with
`testimony:`.

A test can stop before its witness assertion, for example on a failed exit
status or audit check, and then nobody asks the witness what ran. Register the
check when the witness starts instead:

```go
harness.WatchSpawns(t, w, traceID, harness.SpawnRule{
	Allowed: []string{"sleep 0.6"},  // nil allows anything not in Never
	Never:   []string{"sleep 1"},    // must not run, whatever Allowed says
})
```

It runs at cleanup, even after an earlier `Fatal`. It stops the witness, fails
on any process the rule refuses and on missing or bad capture health, and when
the test has already failed it logs every process the witness saw. `Never`
matches a command line whose words end with the entry's words, so it still
fires when `timeout` or `env` wraps the command. Its program matches with or
without a directory on either side (`sleep 1` refuses `/usr/bin/sleep 1`); its
arguments match exactly. `Allowed` matches the whole command line exactly, so
`sh -c "x; sleep 0.6"` is not allowed by `"sleep 0.6"`.

A process that exits before `ProcWitness` reads its arguments is seen by name
only: `ProcessEvent.Command` is the kernel task name (cut to 15 bytes) and
`NameOnly()` is true (`CommandSource` is `comm`, not `cmdline`). `touch` could
have been an allowed `touch approved` or a refused `touch rejected`, so the
rule treats it as seen but not identified. It fails when the name is the
program of a `Never` entry (its first word, without the directory). With an
`Allowed` list it also fails as unidentified, unless `ExcuseNameOnly` is set
and the name is the program of an `Allowed` entry; then it is logged. Set
`ExcuseNameOnly` only when the test runs commands too short-lived to read, and
keep refused probes long-lived so a refused one is always seen whole. A child
first seen with its parent's command line (just forked) that is later seen
with no arguments and a different name has exec'd (or renamed itself) since:
its command line is kept, and the name is added as a second, name-only event
for the same process. A later, different command line (`bash -c` replacing
itself with its last command, or a process rewriting its own argv) likewise
keeps the earlier line as an event of its own; only a child's first line that
equals its parent's is replaced by its exec, since it was never the child's.
`/proc` cannot tell that fork image from a child that exec'd its parent's exact
command line, so such a child that later rewrites its argv loses the first
line when its parent is not itself tracked (the root, or a process older than
`Start`). One process can therefore give several events: count events, not
processes.
A fork that execs a program with the same name
(`sh` running `sh -c ...`) is not caught this way: the parent's line stays.
Keep refused commands distinguishable by program where that matters. With an
`Allowed` list, a forked child seen before its exec and then only by name keeps
its parent's command line, which `Allowed` must list (or the test fails as not
allowed); `ExcuseNameOnly` does not excuse a command line. Never entries must start with the program
(`rm -rf /tmp/x`, not `/tmp/x` or `env rm ...`) to match a name. The kernel
witness (`execbpf`) reads arguments at exec; when that read fails it, and the
witness-file reader, report the task name as name-only rather than an empty
command.

`ProcWitness.Health` retains the first scan error and number of failed scans,
including the final poll. Permission/I/O errors and malformed process stat
entries invalidate capture; processes disappearing during a scan remain a
known polling limitation. A later successful scan does not erase a failure.
`Stop` retains its existing signature; check `Health` after it.

`ProcWitness` sees the root's descendants every tick by walking
`/proc/<pid>/task/*/children`, which needs `CONFIG_PROC_CHILDREN`. If `Start`
cannot read the root's children lists, `Health` fails with
`witness.ErrChildrenWalkUnavailable`: full scans alone miss most short-lived
children on a busy host. Processes outside the root's children tree
(double-forked, reparented, moved into a session cgroup) are seen only by full
scans even when `Health` is nil. `ProcWitness.Coverage()` reports how many
full scans and children walks ran and the longest gap between full scans. An
out-of-tree process that lived shorter than that gap may have been missed, so
log it next to an absence claim. Use the eBPF witness where that gap matters.
Seeing a calibration probe proves the witness saw that probe, not that capture
was complete: a shorter process can still slip between polls. The
`BenchmarkProc*` benchmarks (`pkg/witness/proc_bench_test.go`) measure full-scan
and walk cost and short-process capture on the host they run on; CI runs them
for the record, with no pass bar.

The eBPF witness counts failed ring-buffer reservations for both exec and fork
hooks in a per-CPU map. `Stop` detaches, drains, sums the counters and returns
capture failures; `Health` retains them. Any host-wide drop invalidates the
window because a lost event's session is unknown. Read/decode errors, failed
counter reads and failed Flush also invalidate it. Closing after a failed Flush
may discard an unknown number of samples; this is an error even if the kernel
counter is zero. `NoRetain` is for streaming: its empty `Spawned` cannot certify
absence. The daemon propagates capture errors when it stops; this is not a
continuous health signal in Loki or an automatic production witness join.

Health reports known capture faults. It does not remove polling or attribution
gaps documented below, nor certify completeness of an imported witness log.
A log's caller must also verify the producer completed successfully.

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

### Network, tier 1: `Sinkhole` (runs in `go test`)

`witness.Sinkhole` is a loopback TCP listener the test points the code under
test at, standing in for a destination it must never reach. Every connection
that arrives is recorded and closed. It needs no root, and the application
cannot unsay a connection the listener accepted. `Stop` drains connections the
kernel completed but the accept loop has not taken yet, so a client that hung
up at once still counts; a drain or accept failure fails `Health`.
A proxy turns a closed connection into a 502, which can hide what it did next.
`NewAnsweringSinkhole` (`Sinkhole(answer=True)` in Python) stands in for an
upstream that must answer: it replies 200 with an empty body and records the
request line and headers. `Marked(mark)` finds the arrivals whose first
`X-Subpoena-Mark` header is `mark`, so a test can tell one request from another.
The header travels through the code under test, so it decides nothing about
absence: `Dialed`, and so `NoDial`, returns every arrival whatever it says.

`NewSinkhole` listens on 127.0.0.1; `NewSinkholeAt` takes the address, for an
IPv6 path or a second loopback address.

It certifies only "nothing reached this address". Arrivals carry no PID or
cgroup, so `Dialed` returns every arrival for every trace (`ByDestination`):
safe for an absence claim, exact when one trace is in flight. Pair it with a
positive control, a test in which the destination is allowed and the sinkhole
sees the connection, so an unreachable sinkhole cannot pass for the wrong
reason. `examples/gateway/fetch_test.go` does both. Its cross-examination
mutant removes `Fetch`'s deny return and leaves the "denied" authorize span
standing; the sinkhole sees the connection and the test goes red.

### Network: `netbpf` (kernel-side)

`pkg/witness/netbpf` is the network sibling of `execbpf`. It implements
`witness.NetworkWitness`:

```go
Dialed(traceID string) []NetworkEvent
```

Two eBPF programs, on `fentry/security_socket_connect` and
`fentry/security_socket_sendmsg`, record every outbound inet connection
attempt on the machine: `connect`, and `sendto`/`sendmsg`/`sendmmsg` that
carry a destination (unconnected UDP, TCP Fast Open). These are the LSM entry
points, traced without an LSM boot parameter. Every user-space path goes
through them, including io_uring, and the destination is a kernel copy by
then. Each event carries the caller's cgroup ID and path, PIDs, protocol, and
the destination address and port. It records attempts, not outcomes, so a
refused connect still counts. Attribution is by session cgroup only. A
connection has no parent to follow, so there is no lineage fallback.

The absence check is `harness.RequireNoDial(t, w, traceID, match)`, with the
same rules as `RequireNoSpawn`. A matching attempt is Fail. With none, the
verdict is Pass only on healthy, stopped, retained capture. `harness.DialTo`
matches destinations. Destinations are addresses, not names: a rule about a
host name needs the test to pin what the name resolves to.

Loss accounting is the same as `execbpf`: a per-CPU counter of failed
ring-buffer reservations, the drain on `Stop`, and reader errors, all retained
in `Health`. Not seen: packet sockets; the header destination of raw sockets
that write their own IP header; traffic the kernel originates; and
destinations reached through another process outside the session cgroup (a
proxy, a resolver, a sidecar); and SCTP `connectx`, which goes through
setsockopt. `make test-ebpf` runs its kernel tests: a
successful and a refused TCP connect, an unconnected UDP send and an IPv6
connect in a real session cgroup are attributed with the right cgroup ID; the
test process's own dial is not attributed; and a burst of sends before `Stop`
is not lost.

### Files, tier 1: `FileWatch` (runs in `go test`)

`witness.FileWatch` is inotify on directories the test names, recursive, with
no privilege needed. It implements `witness.FileWitness`:

```go
Wrote(traceID string) []FileEvent
Covers(path string) bool
```

Each event has a kind (`create`, `write`, `rename`, `unlink`), a path, the time
the witness read it (`SeenAt`, not when it happened), and where it came from
(`Source`). A rename is two events, `from` and `to`, tied by `Cookie`; a rename
across the edge of the watched tree has only one. It reports what the kernel
queued, not a before and after comparison, so a file written and put back is
still a write.

```go
w, err := witness.NewFileWatch(root)              // starts recording
harness.WatchWrites(t, w, traceID, harness.WriteRule{
	Allowed: []string{filepath.Join(root, "log")}, // nil allows anything not in Never
	Never:   []string{filepath.Join(root, "data")}, // must not change, whatever Allowed says
})
// ... run the code under test, stop it ...
w.Stop()
harness.RequireNoWrite(t, w, traceID, filepath.Join(root, "data"))
```

`NoWrite`, `RequireNoWrite` and `CheckNoWrite` take absolute paths, each with
everything below it; no paths means anything under the roots. They follow the
same rule as `RequireNoDial`: a matching event is Fail even from a bad capture,
and silence is Pass only from a stopped, healthy one. A rename of a directory
above a path counts as touching it, since it moved the path with no event
naming it. A path the witness does not cover is Inconclusive. `Covers` goes by
spelling, so a path that reaches a root through a symlink is not covered: a
typo must not read as a pass. `WatchWrites` is the cleanup form, with
`WatchSpawns`' rules. Point a positive control at the root, a test where the
write is allowed and the witness sees it, so a wrong root cannot pass for the
wrong reason.

**Attribution is by root.** inotify carries no PID, and unprivileged fanotify
gives inode marks only and `pid=0` for other processes (Linux 6.17). Nothing ties an
event to a process or a trace, so `Wrote` returns every event for every trace
(`ByRoot`), as `Sinkhole` does: safe for an absence claim, exact when one trace
is in flight.

**New directories.** A new directory gets its watch first and is listed after,
so a change is in the listing, in the queue, or in both. What the listing finds
is reported with `Source` `scan` and kind `create`, whatever was done to it,
and a directory moved in is scanned the same way. A name can therefore appear
twice: count events, not files. A directory that was gone before its watch
landed is a gap, because it may have held anything.

**Inconclusive.** `Health` fails, for good, on any of: `IN_Q_OVERFLOW` (events
were lost anywhere under any root); a directory with no watch because
`fs.inotify.max_user_watches` ran out; a root deleted, moved, unmounted or
replaced (a directory above a root moving shows up only at `Stop`, which
compares the root with the directory it watched); a directory that could not
be watched or listed; and a read of the queue that failed or did not decode. It
fails too until `Stop` has drained the queue. The events already seen stand.

`Coverage()` reports the gaps, and what a clean capture still cannot rule out.
Log it next to an absence claim:

- `MaxWatchLag`: the longest a new directory went unwatched, as an upper bound.
  **A file created and removed inside a new directory within this long left no
  trace at all**: inotify had no watch, and the scan came after it was gone.
  Unprivileged inotify has no way to close this, so it is reported and does not
  fail `Health`, as `ProcWitness` reports its longest gap between full scans.
- `SilentCloses`: files closed after being opened for writing with no write
  seen. Most are harmless, since SQLite opens read-write and may only read, but
  this is the only sign of a change made through `mmap`, which inotify does not
  report as a write. An `mmap` write through a descriptor still open at `Stop`
  leaves no sign.

Not seen at all: a write through a hard link outside the root, changes made on
another host (NFS) or in a layer below an overlay mount, attribute changes
(`chmod`, `chown`, `utimes`), and anything reached through a symlink, which is
not followed. A change made during `Stop` may be missed, so stop the code under
test first. Linux only: elsewhere `NewFileWatch` is an error.

A test in another language runs `subpoena-witness -file-root dir`, which needs
no privilege and writes the capture when it gets SIGTERM, or calls
`FileWatch.WriteLog` itself. `witness.ReadLog` and Python's `read_log` read the
file (`docs/ports.md`, W7).

### SQLite: `WatchSQLite` and `RequireNoCommit`

A bare "the file was written" cannot carry a claim about a database. A denied
request can write an audit row to the same file, a read can open it for
writing, and a rolled-back transaction can write to it. `witness.WatchSQLite`
reads the database's own files, with no triggers, no connection and no SQLite
library, and says whether anything was committed, and to which tables:

```go
db, err := witness.WatchSQLite(path)   // the baseline, before the request
w, err := witness.NewFileWatch(filepath.Dir(path))
// ... run the denied request, stop the code under test ...
w.Stop()
harness.RequireNoCommit(t, w, db, traceID, "users")  // an audit row may land; users may not change
```

`NoCommit`, `RequireNoCommit` and `CheckNoCommit` take table names; none means
nothing at all may be committed. `db.Change(events)` gives the raw answer:
`no-change`, `committed` or `unknown`, with the page numbers and table names.

| Mode | How a commit is known | How pages are known | Basis |
| --- | --- | --- | --- |
| WAL, frames still there | a commit frame whose salts and checksum chain hold, as in SQLite's own recovery | the frames, commit by commit | `wal-frames` |
| WAL, frames gone (a checkpoint restarted the log, or the last connection closed and removed it) | the pages differ from the baseline | comparison with the baseline | `page-diff` |
| Rollback journal | the file change counter in the header moved | comparison with the baseline | `page-diff` |

Frames with no commit after them (a spilled transaction, open or rolled back)
are counted in `Uncommitted`, and are no change. In rollback mode the journal
itself cannot show a commit: committing deletes or blanks it. What it can show
is a live transaction, and a journal in that state makes the answer `unknown`.
The reader therefore keeps a copy of the pages as its baseline, which is a
before and after comparison, unlike `FileWatch`. The format leaves no other way.

**Tables are named soundly, at b-tree level.** The reader walks the schema and
every b-tree, overflow chains and the freelist included, on each side of a
change, and names the table owning each committed page on either side. Indexes
count as their table, `WITHOUT ROWID` tables work, and a page that passes from
one table to another is named under both. Row content is not read. Since a row
lives on a page of its table's tree, a table whose rows changed is always named
if its pages were seen, and a test holds this against SQLite's own answer over
random writes. It over-reports: a page rewritten unchanged, or moved by
`auto_vacuum` or `VACUUM`, names a table no row of which changed. Commits to
page 1's header alone do not name the schema; `sqlite_schema` is named only for
a change after the header. A tree that cannot be walked gives page numbers and
`TableError`, with no table list.

**`Exact` is what a table claim rests on.** It means every committed page of the
window was seen, so a table not listed did not change. It holds on the
`wal-frames` basis, and on `page-diff` for a single commit in rollback mode.
With several commits in rollback mode, or with a WAL's frames gone, a change
made and then undone leaves no mark on the pages, so `Exact` is false, and
`NoCommit` about a table not listed is Inconclusive; a table that is listed is
still Fail. To keep table claims conclusive, take the baseline right before the
one request the claim is about. A rig whose code opens and closes its only
connection per request loses the WAL at each close, and gets `page-diff`; in WAL
mode a claim about a table then needs a second connection held open by the rig,
outside the code under test, so the frames survive. A claim with no tables
needs none of this.

`unknown`, which `NoCommit` reports as Inconclusive: a live journal; a file
missing, replaced or unreadable; and in WAL mode the frames gone, the pages the
same as the baseline, and the file witness showing writes to the WAL, which
is what a change made and undone looks like. That last case is why the reader
needs the witness: in WAL mode a healthy capture is what proves the WAL was not
written, and that a checkpoint did not run. `NoCommit` is Inconclusive when the
witness does not watch the database, when its health is bad, and for a table the
database never had.

Limits. `Commits` comes from the change counter in rollback mode, and a
connection in `locking_mode=EXCLUSIVE` bumps that only once, so several commits
there can read as one and `Exact` is then wrong. An encrypted database is not a
SQLite file to this reader: `WatchSQLite` fails. The whole database is read into
memory, and held for the baseline. The reader takes no locks: read while the
code under test is idle. It retries a read that a write crossed, but a write
that lands inside one clock tick with no change of size can tear a read. If the
code under test runs in the same process, closing the reader's descriptor drops
every POSIX lock that process holds on the file, SQLite's included, so never
read mid-transaction there.

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
   backstop in Subpoena itself, decided in `docs/decisions.md` ("The exec backstop"), with
   Tetragon as the alternative where Kubernetes is in use. It is a test
   backstop, not an agent guardrail. In tests a backstop intervention counts
   as a failure, and cross-examination runs with the backstop observing only.

## Layout

- `../pkg/witness/`: interfaces, `ProcWitness`, `Sinkhole`, `FileWatch` and the
  SQLite reader.
- `../pkg/witness/execbpf/`: the kernel-side witness; `bpf/exec.c` is the eBPF
  program (dual MIT/GPL-2.0, as the kernel requires for its helpers).
- `../pkg/witness/netbpf/`: the kernel-side network witness; `bpf/net.c` is
  its eBPF program (dual MIT/GPL-2.0).
- `../cmd/subpoena-witness/`: runs it as a daemon, JSON lines out.
- `../pkg/cgroup/`: per-session cgroup creation, placement and IDs, shared by
  the gateway and the witnesses.
- `tetragon/process-exec.yaml`: TracingPolicy kept for enforcement.
