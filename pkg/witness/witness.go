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

// CommandSource says what ProcessEvent.Command holds.
type CommandSource string

const (
	// CommandLine means Command is the argument list, space-joined.
	CommandLine CommandSource = "cmdline"
	// CommandName means Command is only the kernel's task name, cut to 15
	// bytes: the arguments could not be read (the process exited first, or
	// the kernel witness's argv read failed), or ProcWitness saw the name
	// change after reading a command line (an exec or a rename; the line is
	// kept as its own event). The process was seen but not identified:
	// "touch" may have been an allowed "touch approved" or a refused
	// "touch rejected".
	CommandName CommandSource = "comm"
)

// ProcessEvent is one observed process exec.
type ProcessEvent struct {
	PID     int
	PPID    int
	Exe     string // resolved executable path, if readable
	Command string // command line, space-joined; see CommandSource
	// CommandSource says whether Command is a command line or only a name.
	// Empty when Command is empty or the witness does not say.
	CommandSource CommandSource
	Cgroup        string // cgroup path, if readable
	CgroupID      uint64 // kernel cgroup ID, if the witness reports one (0 otherwise)
	TraceID       string // set when Attribution is ByCgroup
	Attribution   Attribution
	SeenAt        time.Time
}

// NameOnly reports whether the witness saw the process but read only its
// name, not its arguments.
func (e ProcessEvent) NameOnly() bool { return e.CommandSource == CommandName }

// Witness reports process execs attributable to a trace.
type Witness interface {
	// Spawned returns the processes spawned on behalf of traceID. Implementations
	// must err toward over-reporting: an absence claim built on this must never
	// pass because the witness was unsure.
	Spawned(traceID string) []ProcessEvent
}

// HealthReporter reports capture integrity for the current observation window.
// Call Stop before checking health for a final absence claim. A nil error means
// no known capture failure, not freedom from documented polling/correlation gaps.
// Witnesses that cannot report health cannot certify absence with the harness.
type HealthReporter interface {
	Health() error
}
