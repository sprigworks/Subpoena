// Package netbpf is a kernel-side network witness. eBPF programs on the LSM
// entry points security_socket_connect and security_socket_sendmsg report
// every outbound inet connection attempt on the machine (connect, and sendto,
// sendmsg or sendmmsg with a destination, including through io_uring), with
// the caller's cgroup ID and cgroup path read in the kernel at the moment of
// the call. An attempt is attributed to a session's trace by its session
// cgroup (pkg/cgroup), without trusting the application.
//
// It is the network sibling of execbpf, with the same loss accounting: a full
// ring buffer, a failed drain or a reader error makes Health fail, so an empty
// Dialed cannot certify absence by accident.
//
// What it does not see: packet sockets (AF_PACKET); raw sockets that write
// their own IP header (the reported destination is the one passed to the
// call, not the one in the header); traffic the kernel originates itself; and
// destinations reached through another process (a proxy, a resolver, a
// sidecar) outside the session cgroup; and SCTP's connectx, which goes
// through setsockopt. Those are the application's or the deployment's to rule
// out.
//
// Loading the programs needs root (or CAP_BPF plus CAP_PERFMON), cgroup v2 and
// a kernel with BTF and fentry (5.8 or later on amd64, 6.0 or later on arm64).
// It observes only; it does not block.
//
// Every inet connect and named send on the host is reported to user space,
// not only those in session cgroups. On a busy host a full ring buffer fails
// Health for every capture: Inconclusive, never a false Pass.
package netbpf

import (
	"fmt"
	"net/netip"
	"strconv"
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
	// OnEvent, if set, is called for every event the kernel reports, attributed
	// or not, from the reader goroutine. DNS and other UDP on a busy host are many.
	OnEvent func(Event)
	// NoRetain stops the Witness keeping attributed events in memory (Events
	// and Dialed then return nothing). For long-running use with OnEvent.
	NoRetain bool
}

// Event is one kernel report.
type Event struct {
	Op witness.Op
	// PID is as seen in the witness's own PID namespace; 0 when the process is
	// not visible there. HostPID is the same process in the initial namespace.
	PID, HostPID int
	Comm         string
	SockType     int    // SOCK_STREAM (1), SOCK_DGRAM (2), SOCK_RAW (3), ...
	Protocol     string // "tcp", "udp", "icmp", "icmpv6", or the IP protocol number
	Dest         netip.AddrPort
	CgroupID     uint64 // bpf_get_current_cgroup_id: equals pkg/cgroup Group.ID()
	// Cgroup is the cgroup path as far up as the kernel walked (up to 8
	// elements), root-most first, without the hierarchy root: "subpoena/<trace id>".
	Cgroup string
	Time   time.Time

	// Set by the Witness: how the event was attributed to a trace, if at all.
	TraceID     string
	Attribution witness.Attribution
}

// Witness implements witness.NetworkWitness with the eBPF programs in this
// package.
type Witness struct {
	cfg  Config
	base string

	lifecycle sync.Mutex // serializes Start and Stop
	mu        sync.Mutex
	events    []witness.NetworkEvent

	k         *kernel // loaded programs; guarded by lifecycle
	healthErr error
	finished  bool
}

var (
	_ witness.NetworkWitness = (*Witness)(nil)
	_ witness.HealthReporter = (*Witness)(nil)
)

// New returns a Witness. Call Start to load the programs.
func New(cfg Config) *Witness {
	root := cfg.CgroupRoot
	if root == "" {
		root = cgroup.FromEnv().Root
	}
	return &Witness{cfg: cfg, base: cgroup.RootBase(root)}
}

// handle attributes one event and records it. It is the whole of the
// Witness's logic apart from loading the programs, and is tested directly.
//
// Attribution is by session cgroup only. execbpf's lineage fallback follows
// fork events to a root PID; a connection carries no parent, so an attempt
// from outside a session cgroup is not attributed to any trace.
func (w *Witness) handle(e Event) {
	if tid, ok := cgroup.SessionTrace("0::/"+e.Cgroup, w.base); ok {
		e.TraceID, e.Attribution = tid, witness.ByCgroup
	}
	if e.Attribution != "" && !w.cfg.NoRetain {
		w.mu.Lock()
		w.events = append(w.events, witness.NetworkEvent{
			PID:         e.PID,
			Comm:        e.Comm,
			Op:          e.Op,
			Protocol:    e.Protocol,
			Dest:        e.Dest,
			Cgroup:      e.Cgroup,
			CgroupID:    e.CgroupID,
			TraceID:     e.TraceID,
			Attribution: e.Attribution,
			SeenAt:      e.Time,
		})
		w.mu.Unlock()
	}
	if w.cfg.OnEvent != nil {
		w.cfg.OnEvent(e)
	}
}

// Events returns every attributed attempt seen so far, in kernel order.
func (w *Witness) Events() []witness.NetworkEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]witness.NetworkEvent(nil), w.events...)
}

// Dialed returns the attempts attributed to traceID by its session cgroup.
// Call Stop first so no event is still in the ring buffer.
func (w *Witness) Dialed(traceID string) []witness.NetworkEvent {
	traceID = strings.ToLower(traceID)
	var out []witness.NetworkEvent
	for _, e := range w.Events() {
		if e.TraceID == traceID {
			out = append(out, e)
		}
	}
	return out
}

// Health reports known loss or reader failures from this capture. Stop must
// finish draining the ring buffer and reading the loss counter first.
//
//subpoena:enforcement_point
func (w *Witness) Health() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.healthErr != nil {
		return w.healthErr //subpoena:enforcement
	}
	if !w.finished {
		return fmt.Errorf("netbpf: capture has not stopped") //subpoena:enforcement
	}
	if w.cfg.NoRetain {
		return fmt.Errorf("netbpf: capture not retained; use the event sink's health and records") //subpoena:enforcement
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

// protocolName names the IP protocols a connect or sendmsg commonly carries.
func protocolName(p uint32) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	case 262:
		return "mptcp"
	}
	return strconv.FormatUint(uint64(p), 10)
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
