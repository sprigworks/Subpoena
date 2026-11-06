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
`CheckNoSpawn`, `CheckNoDial` and `CheckNoDelivery` are the non-fatal forms: they report the
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
of execs before `Stop` is not lost. The checks `netbpf` has for a task leaving its
session, for kernel recursion misses and for a deeply nested cgroup are not in
`execbpf` yet, so `Spawned` still rests on the application staying where it was
put. In the OATS stack it is the witness for
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
naming it. A path the witness does not cover is Inconclusive, and so is any
claim to a witness with no roots, such as an exec witness's log. `Covers` goes by
spelling, so a path that reaches a root through a symlink is not covered, and
neither is one that goes on through a symlink inside the root, whose writes are
spelled another way or land outside: a typo must not read as a pass. A file
closed with no write seen (`SilentCloses`, below) is Inconclusive too.
`NewFileWatch` refuses one directory under two spellings, two roots or one
inside the other through a symlink: the kernel keeps one watch and one spelling,
so a claim on the other could never match an event. `WatchWrites` is the cleanup form, with
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
be watched or listed; a read of the queue that failed or did not decode; writers
still going when `Stop` had read as many events as the queue can hold, which is
every event made before `Stop`; and more than a million events kept. It fails too
until `Stop` has drained the queue. The events already seen stand.

**The check at `Stop`.** inotify reports what the kernel queued, and some writes
queue nothing. So the capture's start records every file under the roots (size,
mtime, ctime, inode), and `Stop` compares them. A difference no event explains,
a file gone or a file arrived, is reported as an event with `Source` `stat`, so a
claim about that file is Fail. ctime is there because the application cannot put
it back: restoring mtime moves it. This is weaker than an event. It sees net
change only, says nothing of when, and adds to the record without clearing
anything. It over-reports: a `chmod`, a `chown` or a new hard link to a file reads
as a write. It covers files that were there at the start; a file made during the
capture has its create event already.

`Coverage()` reports the gaps, and what a clean capture still cannot rule out.
Log it next to an absence claim:

- `MaxWatchLag`: the longest a new directory went unwatched, as an upper bound.
  **A file created and removed inside a new directory within this long left no
  trace at all**: inotify had no watch, and the scan came after it was gone.
  Unprivileged inotify has no way to close this, so it is reported and does not
  fail `Health`, as `ProcWitness` reports its longest gap between full scans.
- `SilentCloses`: files closed after being opened for writing with no write
  seen. Most are harmless, since SQLite opens read-write and may only read, but
  a change made through `mmap` or Linux native AIO (`io_submit`), buffered or
  `O_DIRECT`, queues no inotify event, so this may be its only mark. `NoWrite`
  and `WatchWrites` are therefore Inconclusive about a file listed here, which
  costs a false Inconclusive for a read-write open that only read.

**No privilege-free observation closes `mmap` and native AIO.** The kernel's
notify hooks are not on those paths, for any process, so an application that
wants to can avoid the queue. What is left is the check at `Stop`, then
`SilentCloses`. Together they caught `mmap` and AIO on ext4 and tmpfs, descriptor
closed or still open. One case leaves no sign: a store through a mapping to a
page already dirty when the capture began, with the mapping held open past
`Stop`, moves no timestamp, closes nothing and queues nothing, so `NoWrite` is
Pass. An AIO write still in flight when `Stop` compares is likewise missed. Start
the witness before the code under test maps the file, and stop that code first.

Seen by the check at `Stop` alone, as a difference and not an event: a write
through a hard link, inside the root or out (inside it, the event names the other
name), changes made on another host (NFS) or in a layer below an overlay mount,
provided the file's timestamps moved here, and attribute changes (`chmod`,
`chown`, `utimes`). Not seen at all: anything reached through a symlink, which is
not followed, and a change to a file made during the capture beyond its create
event. A symlink made and removed inside the capture is not known to `Covers`.
A change made during `Stop` may be missed, so stop the code under test first.
Linux only: elsewhere `NewFileWatch` is an error.

A test in another language runs `subpoena-witness -file-root dir`, which needs
no privilege, writes the start record once attached and the rest when it gets
SIGTERM, or calls `FileWatch.WriteLog` itself. A witness killed before it stopped
leaves a window that never closed, so `Health` fails on the file, even one an
earlier run left healthy. `witness.ReadLog` and Python's `read_log` read the file
(`docs/ports.md`, W7). A file name that is not UTF-8 cannot be carried in JSON, so
a capture holding one is written as unhealthy.

### SQLite: `WatchSQLite` and `RequireNoCommit`

A bare "the file was written" cannot carry a claim about a database. A denied
request can write an audit row to the same file, a read can open it for
writing, and a rolled-back transaction can write to it. `witness.WatchSQLite`
reads the database's own files, with no triggers, no connection and no SQLite
library, and says whether anything was committed, and to which tables:

```go
db, err := witness.WatchSQLite(path)   // the baseline, before the request; symlinks resolved
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
are counted in `Uncommitted`, and are no change: nothing was committed when the
files were read, and a transaction committing after that is outside the window.
An open WAL transaction cannot be refused at the baseline, since unspilled it is
in no file. In rollback mode the journal
itself cannot show a commit: committing deletes or blanks it. What it can show
is a live transaction, and a journal in that state makes the answer `unknown`.
The reader therefore keeps a copy of the pages as its baseline, which is a
before and after comparison, unlike `FileWatch`. The format leaves no other way.

**Tables are named soundly, at b-tree level.** The reader walks the schema and
every b-tree, overflow chains and the freelist included, on each side of a
change, and names the table owning each committed page on either side. Indexes
count as their table, `WITHOUT ROWID` tables work, and a page that passes from
one table to another is named under both, written or not. Row content is not
read. Since an ordinary table's row lives on a page of its tree, such a table
whose rows changed is named if its pages were seen, and a test holds this
against SQLite's own answer over random writes.

A table can read differently with no page of its tree written, so the schema
rows are compared too: any table, index, trigger or view row that differs names
its table. A table dropped with its pages left as they were, renamed, swapped
for another by renames, or given a column with a default is named on both sides.
A header that changes how the file decodes (text encoding, page size, reserved
space) leaves no table list at all.

**A virtual table has no pages.** FTS5, rtree and the like keep their rows in
shadow tables, or outside the database, so `SQLiteChange.Virtual` lists them and
a claim about one is Inconclusive unless the table is named, whatever else
happened. Name a shadow table in the claim if that is what is meant.

It over-reports: a page rewritten unchanged, a page moved by `auto_vacuum` or
`VACUUM`, or a new index or trigger, names a table no row of which changed.
Commits to page 1's header alone do not name the schema; `sqlite_schema` is named
only for a change after the header. A tree that cannot be walked gives page
numbers and `TableError`, with no table list.

**`Exact` is what a table claim rests on.** It means every committed page of the
window was seen, so a table not listed did not change. It holds on the
`wal-frames` basis, and on `page-diff` for a single commit in rollback mode whose
writes to the database were one run.
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
missing, replaced or unreadable; a path that no longer resolves to the file the
baseline read; a symlink at the WAL's or journal's name, which SQLite would write
through, out of the watched directory; a WAL frame naming a page past anything the
files could hold; in WAL mode the frames gone, the pages the same as the
baseline, and the file witness showing writes to the WAL, which is what a change
made and undone looks like; and in rollback mode the database written with pages
and counter the same as the baseline, which is a spilled transaction rolled
back, or a commit undone by copying the file back. Nothing tells those two apart,
so a spilled rollback is Inconclusive. Those last cases are why the reader
needs the witness: a healthy capture is what proves the files were not written,
and that a checkpoint did not run. `NoCommit` is Inconclusive when the witness
does not watch the database, when its health is bad, and for a table the database
never had.

The database is what SQLite would open. `WatchSQLite` resolves symlinks, as SQLite
does, since its WAL and journal sit beside the real file, and `Path` is the real
file. Watch that directory, by a root spelled without a symlink: a witness that
does not is not covering the database, and `NoCommit` is Inconclusive.

Limits. `Commits` comes from the change counter in rollback mode, and a
connection in `locking_mode=EXCLUSIVE` bumps that only once, so several commits
there can read as one and `Exact` is then wrong. The counter is only bytes in a
file the application can write. A commit undone by copying the file back, then
one more commit, shows a count of one, so the reader also counts runs of writes
to the database between journal events, and more than one clears `Exact`. That
costs a spilled transaction its `Exact` too. It needs a journal file to separate
the runs: with `journal_mode=MEMORY` or `OFF`, or an application writing the
file's bytes itself and setting the counter, one run can hide a change undone,
and `Exact` is then wrong. A claim that must hold against an application that
rewrites its own database file needs WAL mode. An encrypted database is not a
SQLite file to this reader: `WatchSQLite` fails. The whole database is read into
memory, and held for the baseline. The reader takes no locks: read while the
code under test is idle. It retries a read that a write crossed, but a write
that lands inside one clock tick with no change of size can tear a read. If the
code under test runs in the same process, closing the reader's descriptor drops
every POSIX lock that process holds on the file, SQLite's included, so never
read mid-transaction there.

### Delivery on an existing socket: `netbpf`, tier 2 only

A broker delivers a message by writing to a subscriber on a socket it accepted
earlier. Nothing dials, so `Sinkhole` and `Dialed` see nothing. A second eBPF
program in `netbpf`, also on `fentry/security_socket_sendmsg`, reports those
sends, and `netbpf.Witness` also implements `witness.DeliveryWitness`:

```go
Delivered(traceID string) []DeliveryEvent
```

**There is no tier 1 for this, and none is planned.** Seeing a write on a socket
another process holds takes the kernel. A listener the test stands up sees only
its own connections, and a subscriber the test runs is a plain recorder of what
reached it, not a witness of what the broker did. Without root, BTF and cgroup
v2 this witness cannot run, and a test that needs it must say the claim was not
checked. `Sinkhole` is no substitute.

The hook sees `write`, `writev`, `send`, `sendto`, `sendmsg`, `sendmmsg` and, on
Linux 6.5 and later, `sendfile` and `splice`, because all of them reach the same
LSM entry point; `write` gets there through `sock_write_iter`. `make test-ebpf`
runs `write`, `writev`, `sendmsg` and `sendfile`, and the rest are not tested.
The program reads the peer from the socket, not from the call:
each `DeliveryEvent` has `Peer` (the far end), `Local` (this end, for a broker its
listener's port), `Bytes`, `Protocol` and the caller's PID and cgroup. A send that
names its destination (a UDP server's `sendto`) is delivery to that destination:
`Op` is `sendmsg` instead of `deliver`, and the same send is in `Dialed` too.

A claim names a peer, because a broker also writes acks to the publisher on the
publisher's own socket:

```go
// Subscribers connect first. The peer is the subscriber's end of the connection.
denied := netip.MustParseAddrPort(subscriber.LocalAddr().String())
w := netbpf.New(netbpf.Config{CgroupRoot: root})
w.Start()                     // after the subscribe handshakes, see below
harness.WatchDeliveries(t, w, traceID, harness.DeliveryRule{
	Never: []netip.AddrPort{denied},
})
// or, once stopped:
harness.RequireNoDelivery(t, w, traceID, harness.DeliveryTo(denied))
```

`harness.NoDelivery`, `RequireNoDelivery` and `CheckNoDelivery` have the verdict
rules of `NoDial`: a matching send is Fail even from a bad capture, and with none
the verdict is Pass only on healthy, stopped, retained capture. A nil match means
any send, the broker's acks included. `DeliveryRule` works like `SpawnRule`: `Never`
wins over `Allowed`, nil `Allowed` allows any peer not in `Never`, and an empty
non-nil `Allowed` allows none. Unlike `SpawnRule`, a rule that names no peer at all
fails, as it claims nothing.

In a peer, a zero port matches every port of the address, and a zero or
unspecified address matches the port on any address. The kernel reports no zone,
so `DeliveryTo` and `Never` leave a zone out, and the form above works for a
link-local subscriber. An `Allowed` entry with a zone excuses nothing, since the
event does not say which link the send took: write it without one. A send the witness could not
place (`PeerUnknown`) is a hit for `DeliveryTo` and `Never`, and so is one to the
right address with no port; no `Allowed` entry excuses either. Raw and SCTP
sockets can give these, as can a send on a socket with no peer at all.

Read a Pass with these in mind:

- **It sees that bytes went, not what they were.** A `PINGRESP` or `SUBACK` on the
  subscriber's socket looks like a `PUBLISH`, and a TLS socket looks the same as
  a plain one. Start the witness after the subscribers have finished their
  handshakes so those are out of the window, or use the `match` function on
  `Bytes`. Keepalives inside the window are a real false Fail.
- **The sender must be in the session cgroup.** Attribution is by cgroup alone,
  so a broker running inside the test binary, as a Go library often does, is not
  seen unless the test process itself is in the session cgroup. The clean form is
  a separate broker process started with `Group.Start`. A process outside every
  session cgroup is not even reported: unlike dials, these sends are filtered in
  the kernel, because host-wide they would fill the ring buffer. A worker the
  broker hands sends to, outside the cgroup, is not seen either.
- **The sender must stay there.** Attribution reads the cgroup at the moment of
  the send, so a task that leaves its session takes its sends out of the claim.
  The witness cannot attribute those, so it counts the leaving instead: a write to
  `cgroup.procs` or `cgroup.threads` that takes a task out of its session, to the
  root, an ancestor or another session, and a child made elsewhere with
  `CLONE_INTO_CGROUP`, each fail `Health` for the whole capture, every trace in it.
  A move inside the session is fine. A send from under the root that names no
  session fails `Health` too. A move by the operator counts just the same, so end
  the capture first.
- **A wrong peer passes.** Naming the broker's listener port instead of the
  subscriber's matches nothing. Pair the claim with a positive control, as with
  `Sinkhole`: a subscriber that was allowed, whose delivery `Delivered` shows.
- **It records the attempt.** The hook runs before the send, so a send that then
  fails still counts, and `Bytes` is what the caller asked for, not what the peer
  got. That over-reports, the safe direction for absence, but it is not proof a
  message arrived. It also reports a TCP send's ignored name, alongside the real
  peer. A datagram or raw socket goes to the name a send gives, so that send is
  charged to the name, not to the peer the socket holds. A raw IPv6 name with
  family 0 is a name; on UDP over IPv6 it is none, and the send goes to the peer.
- **The peer is what the sender's kernel holds.** Behind NAT or a proxy it is the
  proxy. It is an address, not an identity: an ephemeral port reused inside the
  window is a different peer with the same name, and two network namespaces can
  hold the same address.

Not seen: sockets that are not inet (`AF_UNIX`, netlink), which have no address
to report, so a broker serving subscribers over a Unix socket needs another
witness; `sendfile` and `splice` before Linux 6.5, which by the kernel's history
took a path without this hook (not tested; only Linux 6.17 has been run), with no
fault raised, so do not rest this claim on an older kernel; kernel TCP
retransmits. Not tested: `io_uring`, `sendmmsg`, MPTCP and SCTP.

A session may nest cgroups as it likes: the kernel walks up to 32 levels to the
top of the hierarchy, and the session is the one nearest the top, so a cgroup the
application names like another session changes nothing. `Cgroup` keeps 8 elements,
so past that it loses those nearest the leaf. A path too long to walk, session or
not, attributes nothing and fails `Health`, for this and for `Dialed`.

Limits that remain, and why:

- **What happened before `Start`.** The hooks count from when they attach. A task
  that left its session earlier is simply not in it. Start the witness before the
  session's first process.
- **A process with the host's privileges.** One that can unload eBPF programs, or
  kill the witness, can end the capture. A witness killed leaves no stop record,
  which proves nothing, but a program detached by another root process is not
  noticed. Run the code under test without `CAP_BPF` and `CAP_SYS_ADMIN` on the
  host: this is a limit of any observer on the same kernel.
- **A threaded cgroup that spans sessions.** A write to `cgroup.procs` is judged
  by the thread group leader, so a leader outside the session with a thread inside
  it would be missed. That needs write access to the session root, to make it a
  threaded domain, and no session is set up that way.
- **`cgroup_attach_task` is a kernel function, not an interface.** Should it go,
  `Start` fails on attach. Should its arguments change, the check would read
  the wrong thing, and only `make test-ebpf` on that kernel would show it.

`DeliveryCoverage()` says what a capture might have missed: sends reported, how
many have no known peer, sends in session cgroups on sockets that are not inet
(counted in the kernel), lost events, and the counts below that fail `Health`.
`WatchDeliveries` logs the count of
those other sends. A healthy capture with that count above zero means a peer
reached over such a socket is simply not in `Delivered`.

Capture health is `netbpf`'s, one ring buffer and one loss counter for both kinds
of event. A failed reservation, a reader or decode error, a failed drain or an
unreadable counter fails `Health`, and so does a failed load or attach of any of
the five hooks, with the reason kept. A cgroup root name the kernel filter could
never match (empty, `.`, `..`, or 64 bytes and over) fails `Start`. Any other
wrong root gives a healthy, empty capture, so every claim needs the positive
control above, not only one about a peer.

Four more counts fail `Health`, as a send can go unseen with no ring-buffer loss.
A task left a session (above). A path was too long to walk. A send or dial came
from under the session root in no session. And the kernel skipped a program: an
fentry program already active on a CPU is not run again there, and that is counted
only as a recursion miss. On a `preempt=full` kernel a task preempted inside a
program skips every send on that CPU until it runs. Under harsh load on one CPU a
QEMU guest lost 12 to 20 percent of its sends this way, with no misses in the same
runs under `voluntary` or `lazy`. The misses are host-wide, so on such a kernel
under load a capture may be Inconclusive for a neighbour's traffic. That is the
witness saying it cannot be sure, not a bug in the test. No test forces a miss on a
`voluntary` kernel: `make test-ebpf` covers the reading of the counter, a unit test
what a nonzero one does, and the QEMU run was by hand. `make test-ebpf` runs its
kernel tests: a broker process in a real session cgroup writing on accepted
sockets (IPv4, a dual-stack listener, IPv6), with the real subscribers' sockets
as the check; a denied subscriber that was written to; connected and unconnected
UDP; a child cgroup of the session; an `AF_UNIX` send counted and not reported; a
burst drained at `Stop`; a real overflow, with the reader held so reservations
fail; a refused attach of the delivery hook; a raw IPv6 send with family 0, with
and without a peer held; a task leaving its session each way above; and nesting,
forged sessions and a path too long to walk.

`subpoena-witness -deliveries` runs this next to `execbpf` and writes one line per
send from a session cgroup, so a test in another language can read it. Its start
record lists `"captures":["exec","delivery"]`. A file that does not name
`delivery` has no delivery lines because nothing looked, so `NoDelivery` over it
is Inconclusive in both languages, however healthy it is. Python's
`Log.delivered`, `no_delivery`, `require_no_delivery`, `check_no_delivery` and
`delivery_to` read that file. Running the witness stays Go-only, and Python has
no `watch_deliveries`.

### Database rows: `dbproxy` (runs in `go test`)

`pkg/witness/dbproxy` is a wire-protocol proxy for PostgreSQL and MySQL. The test
points the application's DSN at its loopback listener; it forwards to the real
server and logs statements and commits per connection. There is no ORM awareness,
nothing inside the database, and no trigger. It needs no root.

**It has no SQLite or MongoDB support.** Neither speaks these protocols, and
SQLite has no socket at all, so a suite on either gets nothing from it. MariaDB
may work and has not been tested; its extended commands are unreadable frames.

```go
w, err := dbproxy.New(dbproxy.Config{Engine: dbproxy.Postgres, Upstream: "127.0.0.1:5432"})
// point the app at w.Addr(), sslmode=disable or prefer; run migrations and seeds
w.Mark() // what committed so far is setup
harness.WatchRows(t, w, traceID, harness.RowRule{Allowed: []string{"audit_log"}})
// drive the denied request
w.Stop()
harness.RequireNoRow(t, w, traceID, "users")
```

The interface is `witness.DBWitness`, with `Committed(traceID)`.
`harness.NoRow`, `RequireNoRow` and `CheckNoRow` follow `NoDial`: a committed write
that changed rows and counts against the table is Fail even from an unhealthy
capture; with none, missing or bad health is Inconclusive. The empty table means
any table. `WatchRows` runs at cleanup like `WatchSpawns`; a `RowRule` has `Never`
and `Allowed` tables, and a statement it could not read fails on either. Names
compare without case, with or without a schema.

**Attribution** is by destination, as with `Sinkhole`. The proxy sees a socket, not
a request, and the harness drives one request at a time, so every statement holds
for every trace. There is no pool tagging, which would need the application's
cooperation. Run the app's setup before `Mark`, or against the real address.
`Mark` hides what has committed; a transaction open across it still counts, and
faults are never forgotten. It does not take back lines already in a witness file.

**What is reported is what committed, on the server's word.** A write is held per
connection until the server says how its transaction ended:

- Postgres: `ReadyForQuery` and the `CommandComplete` tag. Status `I` ends a
  transaction, explicit or implicit, and an error in that cycle makes the ending
  a rollback, so a failed pipeline or multi-statement query undoes what ran first.
  `COMMIT` of a failed transaction is answered `ROLLBACK`, and the tag wins.
  `PREPARE TRANSACTION` settles at its own tag, as committed, so nothing after it
  in the same query can undo it.
- MySQL: the status flags on every OK and EOF. With no transaction open after a
  statement, everything pending has committed, whether by `COMMIT`, autocommit, or
  implicitly by DDL. A `ROLLBACK` that leaves a warning could not undo a
  non-transactional table, and its writes stand. ERR carries no status, so a
  failed statement commits what came before it unless its verb is on a short list
  known not to: a failed DDL statement has, and so has `LOCK TABLES` of a table that
  isn't there. A parse error in such a statement over-reports. `rolled_back` is
  written only on a `ROLLBACK` or `ROLLBACK TO` the server answered with no warning.

A routine can commit by itself, so its failure proves nothing. `CALL` or `DO` that
fails, or is rolled back with a pipeline around it, outside a transaction block
gets outcome `unknown` and a capture fault: `DO $$ BEGIN INSERT ...; COMMIT; RAISE
... END $$` leaves its row. The same goes for any opaque statement that is not known
to run whole, and text no parser finished. On MySQL it holds inside a transaction
too, since a procedure may `COMMIT` and ERR carries no status. A function called
from a `SELECT` runs inside that statement, so that failure stays `failed`.

Savepoints undo only what followed them. Prepared statements are tied to their SQL
through `Parse`/`Bind`/`Execute` and `COM_STMT_PREPARE`/`EXECUTE`, and a name takes
its SQL only when the server confirms the Parse: a refused second `Parse` of a name
leaves the first in place, on both sides. SQL-level `PREPARE` and `DEALLOCATE` share
those names, so a name they touch is opaque from then on. A routine can run those
too, and neither a rollback nor a failure undoes them, so on Postgres every name and
portal on the connection is opaque after any opaque statement, whether it ended well
or not. MySQL's savepoint names compare without case, quoted or not, and a second one
of a name replaces the first; one outside plain ASCII could equal any other, so the
savepoints before it are forgotten, and rolling back to them undoes nothing here.
Bound values are never read or logged; statement text is, so a literal in SQL is in
the log.

**Zero rows is no row.** `UPDATE 0` and an OK with no rows affected are committed
but are not an effect, so `DELETE ... WHERE owner = $1` refusing by matching
nothing passes. The count comes from the server. A trigger that redirects an insert
can make it report 0 for a row that exists elsewhere.

**What it cannot read over-reports.** Table extraction is deliberately strict:
any form it does not know is opaque, and an opaque statement counts against every
table and cannot be excused by a zero count. That covers text that does not
tokenize, MySQL's executed `/*! */` comments, `U&` strings and names, `EXECUTE` of
SQL-level `PREPARE`, `COMMIT PREPARED`, `CALL`, `DO`, `COPY ... PROGRAM`,
data-modifying `WITH`, multi-table `UPDATE` and `DELETE`, `TRUNCATE CASCADE`, `ALTER
TABLE ... RENAME`, `INHERIT`, `SET SCHEMA` and `ATTACH PARTITION`, `CREATE TABLE ...
INHERITS` and `PARTITION OF`, schema changes other than to a table, and an `EXPLAIN`
with an option it does not read. A `CREATE TABLE ... AS` query and the expressions of `ALTER
TABLE` get the same analysis as a `SELECT`. The server also checks the text: a tag or
row count that contradicts it, or more results than statements, makes the statement
opaque.

**A name proves nothing the application could own.** Every call is opaque unless it
is one of a short list of exact built-in names, kept per engine, even in a `SELECT`:
`SELECT delete_user(1)` and `SELECT to_archive()` are opaque, and a false alarm is
the cost. A schema-qualified call is opaque, except `pg_catalog.` and a listed name
on Postgres. So is a quoted name. A word that looks like a keyword is a keyword only
in the one position where the grammar cannot take a call: `CUBE (` after `GROUP BY`,
`CONFLICT (` after an `ON` with `DO` behind it, `INSERT (` after a `THEN` outside any
`CASE`. Anywhere else it is a name (`SELECT partition()`, `ORDER BY rollup(1)`). The
reverse holds too: `name(` right after an operand or a table reference cannot be a
call, so bare `JOIN (`, `LIKE (` and an alias's column list (`AS t(id)`, `t(id)`) read
as what they are, and so do `WITH t(a) AS (` and `INSERT INTO o AS u (id)`. On
Postgres a word counts as an operand only if it isn't one of the server's keywords,
apart from a short list that take no expression after them; a live test holds that
list of keywords to `pg_get_keywords()`. So `role JOIN (`, with `role` unqualified
and unaliased, is opaque: a false alarm. MySQL needs
the name to touch its parenthesis: `count (1)` is a stored function. Postgres can
also run a routine with no call syntax, so these are opaque there too: an operator
outside a short built-in list, a cast or typed string to a type outside one
(`1::mydomain`, `1::double`, `x '1'`: a word the grammar would take as a type is
excused only in its exact keyword position, as `X'1F'` touching its quote or
`AT TIME ZONE 'UTC'`), and a field of an expression, `(o).w`. The lists hold what
pgx, psql and common ORMs send; a live test holds them to `pg_proc`, where every
function but the few that touch sequences, locks or the clock is stable or immutable. A
plain qualified column
`o.w` stays a read, though it is `w(o)` when `o` has no column `w`: every ORM writes
them, and a Fail on an ordinary read is a false verdict too. That one is a limit,
listed below.

**A session it can't read is opaque for good.** The witness reads text by the
server's rules, and some settings change them. Postgres's `standard_conforming_strings`
off, or a client encoding whose characters can hold a backslash (SJIS, BIG5, GBK and
the like), are taken from `ParameterStatus`, so they are seen however they were set;
a `SET` in the text counts at once, since a report waits for the next `Sync`. On
MySQL `NO_BACKSLASH_ESCAPES` comes from the status flags, the charset from the
handshake, and `ANSI_QUOTES`, `SET NAMES` and the like only from the text. A search
path that puts a schema ahead of `pg_catalog` counts as well. Values are not parsed
for what they mean. A statement that touches one of these settings, in any spelling
(quoted, any case, `-` for `_`, `set_config`, or text the witness could not read that
holds a `SET`), taints the session unless the value is on an allow-list in a plain
form: a word, a quoted name, or a string with no escape in it. For a search path that
means a plain list leaving `pg_catalog` first; for `sql_mode`, a literal list of modes
that leave quoting alone, or `CONCAT(@@sql_mode, ',MODE')` of them; for a charset, one
whose multibyte characters hold no ASCII byte. So `SET sql_mode = @x`, `= 4` and
`SET search_path = E'...'` taint it, whatever they hold, and a safe value in an
unknown form is a false alarm. The startup packet goes by the same rule, its keys and
`options` read as the server reads them; any switch in `options` but `-c name=value`
and `--name=value` taints the session. From then on every statement on that connection
is opaque, even if the setting goes back. `SET GLOBAL` and `SET PERSIST` are opaque.

Postgres keeps 63 bytes of a name and drops the rest without complaint, so events
carry the cut name; a long non-ASCII name is opaque, since where it is cut depends
on the server's encoding. Claim the name the server holds, not a longer spelling.

**TLS is refused, never passed through.** Postgres's `SSLRequest` and
`GSSENCRequest` get `N`; MySQL's greeting has `CLIENT_SSL` and the compression flags
cleared. Query attributes stay offered, because libmysql sets that flag regardless;
a query carrying real attributes is opaque. A client that prefers TLS goes on in the clear. One that insists leaves, or
sends a TLS record anyway, and that is Inconclusive: encrypted bytes it cannot read
must never read as no row. pgx with `sslmode=prefer` leaves and redials, so a
Postgres departure is excused by a plain connection that followed; that is decided
at `Stop`. A MySQL client leaving at the greeting can't be told from a port probe,
and is Inconclusive either way.

**Inconclusive.** `Health` fails for: an unreadable frame, a frame that panics the
parser, or a reply matching no command (the connection goes on as a raw copy, so
the application is not broken by its witness); a connection dropped with a transaction open or a reply owed, whose
writes get outcome `unknown`; a connection it could not proxy, or left queued at
`Stop`; a client insisting on TLS or compression; a routine that failed or rolled
back where it could have committed; a failed write to the witness file; and a
a MySQL session that ended with a write open; a failed write to the witness file;
and a capture not yet stopped. Faults are per capture, not per table. A Postgres
`Terminate` with a transaction open is a clean rollback. On MySQL `COM_QUIT`,
`COM_RESET_CONNECTION` and `COM_CHANGE_USER` with a write open give that write outcome
`unknown` and a fault, InnoDB or not: no reply follows, the wire does not show a
table's engine, and a MyISAM table keeps its rows. With no write open they are clean.
An idle pooled connection at `Stop` is no fault. `Stop` waits up to a second for
replies already owed.

`Coverage()` reports counts, faults, and in `Missed` what the capture may have
missed. Log it next to an absence claim. Nothing connecting looks the same as nothing
being written (`Connections` is 0), so pair a no-row claim with a positive control,
as with `Sinkhole`, in which an allowed write is seen.

Not seen, in every capture:

- connections that do not go through the listener, which is TCP only: a DSN on a
  Unix socket bypasses it;
- rows written by triggers, rules and foreign-key actions, on tables the statement
  does not name;
- rows that reach a table the statement does not name through a relation installed
  before the capture. `INSERT INTO v` where `v` is an updatable view of `users` is a
  write to `v`, and so is a write to a Postgres partition or inheritance child, which
  shows in its parent, and a write to a parent, which lands in a partition. **A claim on
  a table is only as good as the name in the statement:** a no-row claim on `users` says
  no statement named `users`, not that `users` gained no row. Only the catalog can
  resolve these, and these are ordinary schemas, so no adversary is needed. Claim every
  name rows can be written under, or claim the empty table for any write. Changes that
  set such a link up through the listener are opaque; ones a migration made are not seen;
- bound values, so it can say a table was written, and not with what;
- routines installed before the capture that read as something else, which the wire
  cannot show because only the catalog can. `SELECT * FROM v` where `v` is a view over
  a writing function reads as a plain `SELECT`. So does field notation on Postgres:
  `SELECT o.w FROM one o` calls `w(o)` if `one` has no column `w`. So does a Postgres
  overload of a listed name, operator or cast for other argument types: `lower(1)`
  with a `public.lower(int)` that writes. One created through the listener is opaque
  when it is created, which is why the claim fails then, unless `Mark` hid it as
  setup; one a migration installed is not seen;
- work a function commits on another connection, such as `dblink`, when the
  statement around it fails or rolls back;
- settings the server was started or configured with and never reports: a global
  `sql_mode` with `ANSI_QUOTES`, or a role's `search_path` naming `pg_catalog` late.
  A non-default `NAMEDATALEN` likewise moves where a name is cut;
- rows left in a non-transactional MySQL table by a statement that failed part way:
  the ERR has no count.

Over-reported, in the safe direction: `PREPARE TRANSACTION` counts as committed,
since it can be decided on another connection; after a MySQL deadlock, whose ERR
carries no status, pending writes count until the next flags are seen; a call
outside the list counts even if it only reads; a failed `CALL` that wrote
nothing is Inconclusive; an InnoDB write left open at `COM_QUIT` is Inconclusive,
though it rolled back; a Postgres prepared name stays opaque after any opaque
statement, so a pooled connection that ran one before `Mark` reads its cached
statements as opaque after it; and a value of a lexing setting outside the allow-lists
taints the session even if it is harmless.

For a suite in another language, `subpoena-witness db -engine postgres -upstream
host:port -out file` runs the same witness, needs no privileges, and stops on
SIGTERM; `Config.Output` is the same thing in Go. The file holds row lines
(`docs/ports.md`, W9), which Python reads with `read_log(f).committed(trace_id)`.
Running the witness stays Go-only.

`pkg/witness/dbproxy/live` tests it against real `postgres` and `mysql` containers,
with pgx, go-sql-driver, `psql` and the `mysql` client, checking each verdict against
what the tables hold. Those tests skip without Docker or the images, and under
`subpoena-cross`; `make test-db` makes a skip a failure. The limits above that can
be pinned are, in `TestReview6PostgresStatedLimits`. The frame parsers also
replay bytes recorded from those servers, in `pkg/witness/dbproxy/testdata`.

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
- `../pkg/witness/netbpf/`: the kernel-side network and delivery witness;
  `bpf/net.c` is its eBPF program (dual MIT/GPL-2.0).
- `../pkg/witness/dbproxy/`: the database witness, a wire-protocol proxy.
- `../cmd/subpoena-witness/`: runs it as a daemon, JSON lines out.
- `../pkg/cgroup/`: per-session cgroup creation, placement and IDs, shared by
  the gateway and the witnesses.
- `tetragon/process-exec.yaml`: TracingPolicy kept for enforcement.
