package witness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sprigworks/subpoena/pkg/cgroup"
)

// ProcWitness is the tier-1 witness. It polls /proc and notices processes that
// appear after Start. It prefers cgroup correlation: a process whose
// /proc/<pid>/cgroup path contains a session cgroup (<root base>/<trace ID>,
// see pkg/cgroup) is attributed to that trace, and is noticed even if it is not
// a descendant of the root process (a double-forked or reparented child). A
// process in no session cgroup falls back to ppid lineage from the root process.
//
// Limitations, deliberately visible:
//   - Polling can miss a process that starts and exits between two polls.
//     Tests that rely on seeing a process should run one that lives a few
//     polling intervals. The kernel-side witness (pkg/witness/execbpf) does
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

	mu       sync.Mutex
	baseline map[procKey]bool
	tracked  map[procKey]*ProcessEvent
	order    []procKey
	stop     chan struct{}
	done     chan struct{}
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
	warmUp()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stop != nil {
		return fmt.Errorf("witness: already started")
	}
	procs, err := w.scan()
	if err != nil {
		return err
	}
	w.baseline = map[procKey]bool{}
	for k := range procs {
		w.baseline[k] = true
	}
	w.tracked = map[procKey]*ProcessEvent{}
	w.stop, w.done = make(chan struct{}), make(chan struct{})
	iv := w.Interval
	if iv <= 0 {
		iv = 2 * time.Millisecond
	}
	go w.loop(iv, w.stop, w.done)
	return nil
}

// Stop ends polling after one final poll.
func (w *ProcWitness) Stop() {
	w.mu.Lock()
	stop, done := w.stop, w.done
	w.stop = nil
	w.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
}

func (w *ProcWitness) loop(iv time.Duration, stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		w.Poll()
		select {
		case <-stop:
			w.Poll()
			return
		case <-t.C:
		}
	}
}

type procInfo struct {
	pid, ppid int
}

// scan reads the stat of every process.
func (w *ProcWitness) scan() (map[procKey]procInfo, error) {
	ents, err := os.ReadDir(w.root())
	if err != nil {
		return nil, fmt.Errorf("witness: read %s: %w", w.root(), err)
	}
	out := map[procKey]procInfo{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(w.root(), e.Name(), "stat"))
		if err != nil {
			continue // exited
		}
		ppid, start, ok := parseStat(string(b))
		if !ok {
			continue
		}
		out[procKey{pid, start}] = procInfo{pid: pid, ppid: ppid}
	}
	return out, nil
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
	procs, err := w.scan()
	if err != nil {
		return
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
		if w.baseline[k] || p.pid == w.RootPID {
			continue
		}
		// Cgroup membership is checked first: it finds processes lineage loses.
		if !w.inSessionCgroup(p.pid) && !descends(p.pid, w.RootPID, byPID) {
			continue
		}
		ev, seen := w.tracked[k]
		if !seen {
			ev = &ProcessEvent{PID: p.pid, PPID: p.ppid, SeenAt: time.Now()}
			w.tracked[k] = ev
			w.order = append(w.order, k)
		}
		w.refresh(ev)
	}
}

// refresh (re)reads cmdline, exe and cgroup. It is repeated while the process
// is alive because a forked child briefly shows its parent's cmdline.
func (w *ProcWitness) refresh(ev *ProcessEvent) {
	dir := filepath.Join(w.root(), strconv.Itoa(ev.PID))
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(b) > 0 {
		ev.Command = strings.Join(strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), " ")
	} else if ev.Command == "" {
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			ev.Command = strings.TrimSpace(string(b))
		}
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		ev.Exe = exe
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		ev.Cgroup = strings.TrimSpace(string(b))
	}
	ev.Attribution, ev.TraceID = ByLineage, ""
	if id, ok := cgroup.SessionTrace(ev.Cgroup, w.cgroupBase()); ok {
		ev.Attribution, ev.TraceID = ByCgroup, id
	}
}

// inSessionCgroup reports whether the process is in a session cgroup.
func (w *ProcWitness) inSessionCgroup(pid int) bool {
	b, err := os.ReadFile(filepath.Join(w.root(), strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	_, ok := cgroup.SessionTrace(string(b), w.cgroupBase())
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
