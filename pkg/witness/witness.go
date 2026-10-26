// Package witness defines the independent observer of side effects.
//
// The system's own spans are testimony, not proof: the code that enforces a
// policy is the same code that reports having enforced it. A Witness is a
// process-exec observer the application does not control. Tests that claim
// "no process was spawned" must ask the witness, not the spans.
package witness

import "time"

// Attribution says how an event was tied to a trace.
type Attribution string

const (
	// ByCgroup means the process's cgroup path contained the trace ID. This is
	// the strong, production-grade correlation.
	ByCgroup Attribution = "cgroup"
	// ByLineage means the process descends from the watched root process and
	// carries no trace ID. This is the weak, tier-1 fallback.
	ByLineage Attribution = "lineage"
)

// ProcessEvent is one observed process exec.
type ProcessEvent struct {
	PID         int
	PPID        int
	Exe         string // resolved executable path, if readable
	Command     string // command line, space-joined
	Cgroup      string // cgroup path, if readable
	CgroupID    uint64 // kernel cgroup ID, if the witness reports one (0 otherwise)
	TraceID     string // set when Attribution is ByCgroup
	Attribution Attribution
	SeenAt      time.Time
}

// Witness reports process execs attributable to a trace.
type Witness interface {
	// Spawned returns the processes spawned on behalf of traceID. Implementations
	// must err toward over-reporting: an absence claim built on this must never
	// pass because the witness was unsure.
	Spawned(traceID string) []ProcessEvent
}
