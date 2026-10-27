package witness

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sprigworks/subpoena/pkg/cgroup"
)

// ProcWitness is the tier-1 witness. It polls /proc and notices processes that
// appear after Start. Two pollers feed the same record: every tick it walks the
// root's descendants through /proc/<pid>/task/*/children, which costs a few
// reads however busy the machine is; and it scans all of /proc, which is slow
// on a busy machine but finds processes the walk cannot. It prefers cgroup correlation: a process whose
// /proc/<pid>/cgroup path contains a session cgroup (<root base>/<trace ID>,
// see pkg/cgroup) is attributed to that trace, and is noticed even if it is not
// a descendant of the root process (a double-forked or reparented child). A
// process in no session cgroup falls back to ppid lineage from the root process.
//
// Limitations, deliberately visible:
//   - Polling can miss a process that starts and exits between two polls.
//     Tests that rely on seeing a process should run one that lives a few
//     polling intervals. For descendants the interval is the children walk's
//     tick (it needs CONFIG_PROC_CHILDREN; without it the walk finds nothing).
//     Anything else, such as a process reparented into a session cgroup, waits
//     for a full scan, which on a busy machine under the race detector can
//     take 100ms or more. The kernel-side witness (pkg/witness/execbpf) does
//     not have this gap.
//   - A Go program's first os/exec call forks a throwaway pidfd probe; Start
//     absorbs it with a warm-up. A process that never ran Start before its first
//     exec could still see that probe as an extra event.
//   - Lineage is lost if an intermediate parent exits and the child is
//     reparented to init.
//   - Without a cgroup carrying the trace ID, an event is attributed by lineage
//     only. Spawned(traceID) then returns it for every trace, which
//     over-reports (safe for absence claims) and is exact only when one trace
//     is in flight, as in a unit test.
type ProcWitness struct {
	// ProcRoot is the procfs mount; "/proc" if empty. Tests point it at a fake.
	ProcRoot string
	// RootPID is the process whose descendants are watched.
	RootPID int
	// Interval is the polling interval; 2ms if zero.
	Interval time.Duration
	// CgroupRoot is the directory the gateway creates session cgroups under;
	// only its last element is compared with /proc/<pid>/cgroup paths. If
	// empty, $SUBPOENA_CGROUP_ROOT or the default is used.
	CgroupRoot string

	lifecycle    sync.Mutex // serializes Start and Stop
	mu           sync.Mutex
	baseline     map[procKey]bool
	tracked      map[procKey]*ProcessEvent
	order        []procKey
	stop         chan struct{}
	done         chan struct{}
	finished     bool
	scanErrors   uint64
	firstScanErr error

	afterScan func() // test hook: runs in Poll between the scan and recording
}

type procKey struct {
	pid   int
	start string // starttime field of /proc/<pid>/stat, to survive PID reuse
}

// NewProcWitness watches descendants of rootPID.
func NewProcWitness(rootPID int) *ProcWitness { return &ProcWitness{RootPID: rootPID} }

func (w *ProcWitness) cgroupBase() string {
	root := w.CgroupRoot
	if root == "" {
		root = cgroup.FromEnv().Root
	}
	return cgroup.RootBase(root)
}

func (w *ProcWitness) root() string {
	if w.ProcRoot == "" {
		return "/proc"
	}
	return w.ProcRoot
}

var warmOnce sync.Once

// warmUp runs one throwaway child process. On its first os/exec use a Go
// program forks a short-lived probe child (the runtime checking pidfd support)
// that carries the parent's command line; a witness started before that would
// report the probe as a spawned process. Doing it first, once, keeps the probe
// out of the observation window.
func warmUp() {
	warmOnce.Do(func() {
		for _, p := range []string{"/bin/true", "/usr/bin/true"} {
			if _, err := os.Stat(p); err == nil {
				_ = exec.Command(p).Run()
				return
			}
		}
	})
}

// Start takes a baseline of existing processes and begins polling. Processes
// that already exist are never reported.
func (w *ProcWitness) Start() error {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	warmUp()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stop != nil {
		return fmt.Errorf("witness: already started")
	}
	w.finished, w.scanErrors, w.firstScanErr = false, 0, nil
	procs, err := w.scan(nil)
	if err != nil {
		w.scanErrors, w.firstScanErr = 1, err
		return err
	}
	w.baseline = map[procKey]bool{}
	for k := range procs {
		w.baseline[k] = true
	}
	w.tracked = map[procKey]*ProcessEvent{}
	w.order = nil
	w.stop, w.done = make(chan struct{}), make(chan struct{})
	iv := w.Interval
	if iv <= 0 {
		iv = 2 * time.Millisecond
	}
	stop, done := w.stop, w.done
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); w.loop(iv, stop, w.Poll) }()
	go func() { defer wg.Done(); w.loop(iv, stop, w.pollChildren) }()
	go func() { wg.Wait(); close(done) }()
	return nil
}

// Stop ends polling after one final poll of each kind.
func (w *ProcWitness) Stop() {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	w.mu.Lock()
	stop, done := w.stop, w.done
	w.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
	w.mu.Lock()
	w.stop, w.finished = nil, true
	w.mu.Unlock()
}

func (w *ProcWitness) loop(iv time.Duration, stop chan struct{}, poll func()) {
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		poll()
		select {
		case <-stop:
			poll()
			return
		case <-t.C:
		}
	}
}

type procInfo struct {
	pid, ppid int
	snap      *procSnap // nil for baseline processes
}

// procSnap is what a process looked like when its stat was read. Empty fields
// were unreadable (the process had exited, or had not yet exec'd).
type procSnap struct {
	cmdline, comm, exe, cgroup string
}

// scan reads the stat of every process, and the details of every process not in
// baseline right after its stat: a full scan of a busy /proc can outlast a
// short-lived child, so reading them after the scan would find it gone.
func (w *ProcWitness) scan(baseline map[procKey]bool) (map[procKey]procInfo, error) {
	ents, err := os.ReadDir(w.root())
	if err != nil {
		return nil, fmt.Errorf("witness: read %s: %w", w.root(), err)
	}
	out := map[procKey]procInfo{}
	var scanErr error
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		k, ppid, err := w.readStat(pid)
		if err != nil {
			// Exit races are an inherent polling gap. Permission, I/O and other
			// failures are known capture faults, not evidence of absence.
			if !exited(err) && scanErr == nil {
				scanErr = err
			}
			continue
		}
		p := procInfo{pid: pid, ppid: ppid}
		if baseline != nil && !baseline[k] {
			p.snap = w.readSnap(pid)
		}
		out[k] = p
	}
	return out, scanErr
}

// readStat reads pid's stat. An error that exited reports is the process
// leaving between the listing and the read; any other error is a capture fault.
func (w *ProcWitness) readStat(pid int) (k procKey, ppid int, err error) {
	b, err := os.ReadFile(filepath.Join(w.root(), strconv.Itoa(pid), "stat"))
	if err != nil {
		return procKey{}, 0, fmt.Errorf("witness: read process stat: %w", err)
	}
	ppid, start, ok := parseStat(string(b))
	if !ok {
		return procKey{}, 0, fmt.Errorf("witness: malformed stat for PID %d", pid)
	}
	return procKey{pid, start}, ppid, nil
}

// exited reports whether err from readStat means the process is gone.
func exited(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func (w *ProcWitness) readSnap(pid int) *procSnap {
	dir := filepath.Join(w.root(), strconv.Itoa(pid))
	s := &procSnap{}
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		s.cmdline = strings.Join(strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), " ")
	}
	if s.cmdline == "" {
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			s.comm = strings.TrimSpace(string(b))
		}
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		s.exe = exe
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		s.cgroup = strings.TrimSpace(string(b))
	}
	return s
}

// parseStat extracts ppid (field 4) and starttime (field 22). The comm field
// can contain spaces and parentheses, so fields are counted after the last ')'.
func parseStat(s string) (ppid int, start string, ok bool) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, "", false
	}
	f := strings.Fields(s[i+1:])
	// f[0] is state (field 3), so ppid is f[1] and starttime is f[19].
	if len(f) < 20 {
		return 0, "", false
	}
	p, err := strconv.Atoi(f[1])
	if err != nil {
		return 0, "", false
	}
	return p, f[19], true
}

// Poll scans /proc once and records new descendants. It is called by the
// background loop and may be called directly (tests do, with a fake procfs).
func (w *ProcWitness) Poll() {
	w.mu.Lock()
	baseline := w.baseline // never mutated after Start
	w.mu.Unlock()
	if baseline == nil {
		return
	}
	procs, err := w.scan(baseline)
	if err != nil {
		w.mu.Lock()
		w.scanErrors++
		if w.firstScanErr == nil {
			w.firstScanErr = err
		}
		w.mu.Unlock()
		// Keep positive observations from the readable part of a partial scan.
	}
	if w.afterScan != nil {
		w.afterScan()
	}
	byPID := map[int]procInfo{}
	for _, p := range procs {
		byPID[p.pid] = p
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tracked == nil {
		return
	}
	// Deterministic discovery order within one poll: by PID.
	keys := make([]procKey, 0, len(procs))
	for k := range procs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].pid < keys[j].pid })
	for _, k := range keys {
		p := procs[k]
		if p.snap == nil || p.pid == w.RootPID {
			continue
		}
		// Cgroup membership is checked first: it finds processes lineage loses.
		if !w.inSessionCgroup(p.snap.cgroup) && !descends(p.pid, w.RootPID, byPID) {
			continue
		}
		w.record(k, p)
	}
}

// maxWalk bounds the children walk, as descends bounds lineage hops.
const maxWalk = 4096

// pollChildren walks the root's descendants through
// /proc/<pid>/task/*/children and records the new ones. Its cost grows with
// the root's threads and descendants, not with the whole machine, so it can
// run every tick while a full scan is still reading /proc. A process that
// existed at Start is not recorded, but its children are walked.
func (w *ProcWitness) pollChildren() {
	w.mu.Lock()
	baseline := w.baseline // never mutated after Start
	w.mu.Unlock()
	if baseline == nil {
		return
	}
	type found struct {
		k procKey
		p procInfo
	}
	var news []found
	visited := map[int]bool{w.RootPID: true}
	queue := []int{w.RootPID}
	for len(queue) > 0 && len(visited) < maxWalk {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range w.children(pid) {
			if visited[c] {
				continue
			}
			visited[c] = true
			queue = append(queue, c)
			// The walk only adds sightings; capture faults are the full
			// scan's to report, so a failed read here is skipped.
			k, ppid, err := w.readStat(c)
			if err != nil || baseline[k] {
				continue
			}
			// Details right after the stat, as in scan.
			news = append(news, found{k, procInfo{pid: c, ppid: ppid, snap: w.readSnap(c)}})
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tracked == nil {
		return
	}
	for _, f := range news {
		w.record(f.k, f.p)
	}
}

// children lists the child PIDs of every thread of pid.
func (w *ProcWitness) children(pid int) []int {
	dir := filepath.Join(w.root(), strconv.Itoa(pid), "task")
	tasks, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		b, err := os.ReadFile(filepath.Join(dir, t.Name(), "children"))
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if c, err := strconv.Atoi(f); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// record adds or updates the event for k. w.mu must be held.
func (w *ProcWitness) record(k procKey, p procInfo) {
	ev, seen := w.tracked[k]
	if !seen {
		ev = &ProcessEvent{PID: p.pid, PPID: p.ppid, SeenAt: time.Now()}
		w.tracked[k] = ev
		w.order = append(w.order, k)
	}
	w.refresh(ev, p.snap)
}

// refresh updates an event from a later sighting. It is repeated while the
// process is alive because a forked child briefly shows its parent's cmdline;
// fields the sighting could not read (an exited process) keep what was seen.
func (w *ProcWitness) refresh(ev *ProcessEvent, s *procSnap) {
	if s.cmdline != "" {
		ev.Command = s.cmdline
	} else if ev.Command == "" {
		ev.Command = s.comm
	}
	if s.exe != "" {
		ev.Exe = s.exe
	}
	if s.cgroup != "" {
		ev.Cgroup = s.cgroup
	}
	ev.Attribution, ev.TraceID = ByLineage, ""
	if id, ok := cgroup.SessionTrace(ev.Cgroup, w.cgroupBase()); ok {
		ev.Attribution, ev.TraceID = ByCgroup, id
	}
}

// inSessionCgroup reports whether a cgroup file's content names a session cgroup.
func (w *ProcWitness) inSessionCgroup(cg string) bool {
	_, ok := cgroup.SessionTrace(cg, w.cgroupBase())
	return ok
}

func descends(pid, root int, byPID map[int]procInfo) bool {
	for hops := 0; hops < 4096; hops++ {
		p, ok := byPID[pid]
		if !ok {
			return false
		}
		if p.ppid == root {
			return true
		}
		if p.ppid <= 1 {
			return false
		}
		pid = p.ppid
	}
	return false
}

// cgroupHasTrace reports whether any path element of a cgroup file's content
// contains the trace ID.
func cgroupHasTrace(cgroup, traceID string) bool {
	if traceID == "" {
		return false
	}
	return strings.Contains(strings.ToLower(cgroup), strings.ToLower(traceID))
}

// Events returns every observed event, in discovery order.
func (w *ProcWitness) Events() []ProcessEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]ProcessEvent, 0, len(w.order))
	for _, k := range w.order {
		out = append(out, *w.tracked[k])
	}
	return out
}

// Spawned implements Witness. Cgroup correlation wins: an event in a session
// cgroup is returned for that trace only. Otherwise it returns events whose
// cgroup path merely carries traceID, plus lineage-only events (which cannot
// be excluded; see the type comment). Events whose cgroup names a different
// trace are excluded.
func (w *ProcWitness) Spawned(traceID string) []ProcessEvent {
	var out []ProcessEvent
	for _, ev := range w.Events() {
		switch {
		case ev.Attribution == ByCgroup && ev.TraceID != "":
			// A session cgroup: this process belongs to exactly one trace.
			if strings.EqualFold(ev.TraceID, traceID) {
				out = append(out, ev)
			}
		case cgroupHasTrace(ev.Cgroup, traceID):
			ev.Attribution, ev.TraceID = ByCgroup, traceID
			out = append(out, ev)
		case cgroupNamesOtherTrace(ev.Cgroup):
			// Provably another trace's process.
		default:
			out = append(out, ev)
		}
	}
	return out
}

// cgroupNamesOtherTrace reports whether a cgroup path has an element that is a
// 32-hex-digit name, i.e. a trace-ID-named cgroup.
func cgroupNamesOtherTrace(cgroup string) bool {
	for _, seg := range strings.FieldsFunc(cgroup, func(r rune) bool { return r == '/' || r == ':' || r == '\n' }) {
		seg = strings.TrimSuffix(strings.TrimPrefix(seg, "trace-"), ".scope")
		if len(seg) == 32 && isHex(seg) {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

var _ Witness = (*ProcWitness)(nil)

// Health reports failed scans, including the final poll. Recovery on a later
// poll does not erase a gap. Stop must complete before absence is certified.
//
//subpoena:enforcement_point
func (w *ProcWitness) Health() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.firstScanErr != nil {
		return fmt.Errorf("witness: %d failed scan(s), first: %w", w.scanErrors, w.firstScanErr) //subpoena:enforcement
	}
	if !w.finished {
		return fmt.Errorf("witness: capture has not stopped") //subpoena:enforcement
	}
	return nil
}

var _ HealthReporter = (*ProcWitness)(nil)
