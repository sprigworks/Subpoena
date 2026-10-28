// Package execbpf is a kernel-side process witness. An eBPF program on the
// sched_process_exec tracepoint reports every exec on the machine, with the
// process's cgroup ID and cgroup path read in the kernel at the moment of exec,
// so a process is attributed to a session's trace by its session cgroup
// (pkg/cgroup) without trusting the application and without polling.
//
// Compared with ProcWitness (pkg/witness), which polls /proc: nothing is too
// short-lived to be seen, and the cgroup is captured before the process can
// move or exit. Compared with Tetragon outside Kubernetes: the session cgroup
// name is reported, not only a container ID. See witnesses/README.md.
//
// Loading the program needs root (or CAP_BPF plus CAP_PERFMON), cgroup v2 and
// a kernel with BTF (5.8 or later). It observes only; it does not block.
package execbpf

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sprigworks/subpoena/pkg/cgroup"
	"github.com/sprigworks/subpoena/pkg/witness"
)

// Config configures a Witness.
type Config struct {
	// CgroupRoot is the parent directory of the session cgroups, as given to
	// pkg/cgroup. Only its last element is compared with the kernel's cgroup
	// path (the path is relative to a cgroup namespace). Empty means
	// $SUBPOENA_CGROUP_ROOT or cgroup.DefaultRoot.
	CgroupRoot string
	// RootPID, if non-zero, enables lineage attribution: a process descended
	// from RootPID (followed through fork events) and in no session cgroup is
	// reported as ByLineage, as ProcWitness does. It is a PID in the witness's
	// own PID namespace, like os.Getpid().
	RootPID int
	// OnEvent, if set, is called for every event the kernel reports, attributed
	// or not, from the reader goroutine. Exec events on a busy host are many.
	OnEvent func(Event)
	// NoRetain stops the Witness keeping attributed events in memory (Events
	// and Spawned then return nothing). For long-running use with OnEvent.
	NoRetain bool
}

// Kind is what the kernel reported.
type Kind string

const (
	KindExec Kind = "exec"
	KindFork Kind = "fork"
)

// Event is one kernel report.
type Event struct {
	Kind Kind
	// PID and PPID are as seen in the witness's own PID namespace, so they match
	// its /proc and the PIDs of processes it started; 0 when the process is not
	// visible there (the witness runs in a container that cannot see it).
	PID, PPID int
	// HostPID and HostPPID are the same processes in the initial namespace.
	HostPID, HostPPID int
	Comm              string // task name after exec
	Exe               string // path passed to execve (may be relative); empty for forks
	Args              []string
	CgroupID          uint64 // bpf_get_current_cgroup_id: equals pkg/cgroup Group.ID()
	// Cgroup is the cgroup path as far up as the kernel walked (up to 8
	// elements), root-most first, without the hierarchy root: "subpoena/<trace id>".
	Cgroup string
	Time   time.Time

	// Set by the Witness: how the event was attributed to a trace, if at all.
	TraceID     string
	Attribution witness.Attribution
}

// Witness implements witness.Witness with the eBPF program in this package.
type Witness struct {
	cfg  Config
	base string

	lifecycle sync.Mutex // serializes Start and Stop
	mu        sync.Mutex
	events    []witness.ProcessEvent
	desc      map[int]bool // RootPID and its descendants, from fork and exec events

	k         *kernel // loaded program; guarded by lifecycle
	healthErr error
	finished  bool

	// Test hooks. ringBytes, if set, replaces the ring buffer's size (a
	// power of two, at least a page); holdReads, if set, holds the reader
	// until it is closed, so a test can fill the buffer and force drops.
	ringBytes uint32
	holdReads chan struct{}
}

var _ witness.Witness = (*Witness)(nil)

// New returns a Witness. Call Start to load the program.
func New(cfg Config) *Witness {
	root := cfg.CgroupRoot
	if root == "" {
		root = cgroup.FromEnv().Root
	}
	w := &Witness{cfg: cfg, base: cgroup.RootBase(root)}
	if cfg.RootPID != 0 {
		w.desc = map[int]bool{cfg.RootPID: true}
	}
	return w
}

// handle attributes one event and records it. It is the whole of the
// Witness's logic apart from loading the program, and is tested directly.
func (w *Witness) handle(e Event) {
	w.mu.Lock()
	// A session cgroup decides; lineage applies only outside one, as in
	// ProcWitness.
	if tid, ok := cgroup.SessionTrace("0::/"+e.Cgroup, w.base); ok {
		e.TraceID, e.Attribution = tid, witness.ByCgroup
	}
	if w.desc != nil && e.PID != 0 && (w.desc[e.PPID] || w.desc[e.PID]) {
		w.desc[e.PID] = true
		if e.Attribution == "" {
			e.Attribution = witness.ByLineage
		}
	}
	if e.Kind == KindExec && e.Attribution != "" && !w.cfg.NoRetain {
		// Without argv (the read failed), the task name stands in, marked as
		// name-only, rather than an empty command no rule can match.
		cmd, src := strings.Join(e.Args, " "), witness.CommandLine
		if len(e.Args) == 0 {
			cmd, src = e.Comm, witness.CommandName
			if cmd == "" {
				src = ""
			}
		}
		w.events = append(w.events, witness.ProcessEvent{
			CommandSource: src,
			PID:           e.PID,
			PPID:          e.PPID,
			Exe:           e.Exe,
			Command:       cmd,
			Cgroup:        e.Cgroup,
			CgroupID:      e.CgroupID,
			TraceID:       e.TraceID,
			Attribution:   e.Attribution,
			SeenAt:        e.Time,
		})
	}
	w.mu.Unlock()
	if w.cfg.OnEvent != nil {
		w.cfg.OnEvent(e)
	}
}

// Events returns every attributed exec seen so far, in kernel order.
func (w *Witness) Events() []witness.ProcessEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]witness.ProcessEvent(nil), w.events...)
}

// Spawned returns the execs attributed to traceID: those in its session
// cgroup, plus lineage-only events, which cannot be told apart by trace and
// are returned for every trace (the safe direction for an absence claim,
// exact when one trace is in flight). Call Stop first so no event is still in
// the ring buffer.
func (w *Witness) Spawned(traceID string) []witness.ProcessEvent {
	traceID = strings.ToLower(traceID)
	var out []witness.ProcessEvent
	for _, e := range w.Events() {
		if e.Attribution == witness.ByLineage || e.TraceID == traceID {
			out = append(out, e)
		}
	}
	return out
}

// splitArgs turns the kernel's NUL-separated argv copy into arguments. A
// trailing empty element (the final NUL) is dropped; a copy truncated at
// ARGS_LEN keeps its partial last argument.
func splitArgs(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\x00")
	return strings.Split(s, "\x00")
}

// cgroupPath joins the kernel's leaf-first path elements root-most first,
// dropping the hierarchy root (an empty name).
func cgroupPath(leafFirst []string) string {
	var parts []string
	for i := len(leafFirst) - 1; i >= 0; i-- {
		if n := leafFirst[i]; n != "" && n != "/" {
			parts = append(parts, n)
		}
	}
	return strings.Join(parts, "/")
}

// Health reports known loss or reader failures from this capture. Stop must
// finish draining the ring buffer and reading the loss counter first.
func (w *Witness) Health() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.healthLocked()
}

//subpoena:enforcement_point
func (w *Witness) healthLocked() error {
	if w.healthErr != nil {
		return w.healthErr //subpoena:enforcement
	}
	if !w.finished {
		return fmt.Errorf("execbpf: capture has not stopped") //subpoena:enforcement
	}
	if w.cfg.NoRetain {
		return fmt.Errorf("execbpf: capture not retained; use the event sink's health and records") //subpoena:enforcement
	}
	return nil
}

func (w *Witness) recordError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Preserve the first failure; repeated decode errors must not grow memory.
	if w.healthErr == nil {
		w.healthErr = err
	}
}

var _ witness.HealthReporter = (*Witness)(nil)
