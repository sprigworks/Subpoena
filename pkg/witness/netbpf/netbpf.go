// Package netbpf is a kernel-side network witness. eBPF programs on the LSM
// entry points security_socket_connect and security_socket_sendmsg report
// every outbound inet connection attempt on the machine (connect, and sendto,
// sendmsg or sendmmsg with a destination, including through io_uring), with
// the caller's cgroup ID and cgroup path read in the kernel at the moment of
// the call. An attempt is attributed to a session's trace by its session
// cgroup (pkg/cgroup), without trusting the application.
//
// A second program on security_socket_sendmsg reports sends on connected inet
// sockets from session cgroups, with the peer read from the socket. That is
// witness.DeliveryWitness: a broker writing to a subscriber on a socket it
// accepted, which involves no connect at all. The sender must be in the session
// cgroup; a broker running inside the test binary, outside it, is not seen.
// It sees that bytes went to a peer, not what they were, and it reports the
// attempt, before the send can fail. There is no tier-1 form of this: the
// kernel is the only outside observer of a write on someone else's socket.
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
// out. Delivered also misses sends on sockets that are not inet (counted in
// DeliveryCoverage) and, before Linux 6.5, sendfile and splice to a socket,
// which then took a path without this hook.
//
// Loading the programs needs root (or CAP_BPF plus CAP_PERFMON), cgroup v2 and
// a kernel with BTF and fentry (5.8 or later on amd64, 6.0 or later on arm64).
// It observes only; it does not block.
//
// Every inet connect and named send on the host is reported to user space,
// not only those in session cgroups. On a busy host a full ring buffer fails
// Health for every capture: Inconclusive, never a false Pass. Connected sends
// are filtered in the kernel to cgroups under the session root, since on any
// host those would be far too many.
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
	// NoRetain stops the Witness keeping attributed events in memory (Events,
	// Dialed and Delivered then return nothing). For long-running use with
	// OnEvent.
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
	// Dest is the destination, and for OpDeliver the peer the socket holds: the
	// zero AddrPort if it holds none.
	Dest     netip.AddrPort
	Local    netip.AddrPort // this end of the socket, on a send
	Bytes    uint64         // on a send, the bytes the caller asked to send
	CgroupID uint64         // bpf_get_current_cgroup_id: equals pkg/cgroup Group.ID()
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
	// deliveries are sends: OpDeliver events, and the OpSendmsg ones also in
	// events, since a named send is delivery to the peer it names.
	deliveries []witness.DeliveryEvent
	coverage   witness.DeliveryCoverage

	k         *kernel // loaded programs; guarded by lifecycle
	healthErr error
	finished  bool
}

var (
	_ witness.NetworkWitness  = (*Witness)(nil)
	_ witness.DeliveryWitness = (*Witness)(nil)
	_ witness.HealthReporter  = (*Witness)(nil)
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
	if e.Attribution != "" {
		w.record(e)
	}
	if w.cfg.OnEvent != nil {
		w.cfg.OnEvent(e)
	}
}

// record keeps one attributed event: a connection attempt, a send, or both.
func (w *Witness) record(e Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	send := e.Op == witness.OpDeliver || e.Op == witness.OpSendmsg
	d := witness.DeliveryEvent{
		PID:         e.PID,
		Comm:        e.Comm,
		Op:          e.Op,
		Protocol:    e.Protocol,
		Peer:        e.Dest,
		Local:       e.Local,
		Bytes:       e.Bytes,
		Cgroup:      e.Cgroup,
		CgroupID:    e.CgroupID,
		TraceID:     e.TraceID,
		Attribution: e.Attribution,
		SeenAt:      e.Time,
	}
	if send {
		w.coverage.Sends++
		if d.PeerUnknown() {
			w.coverage.UnknownPeers++
		}
	}
	if w.cfg.NoRetain {
		return
	}
	if send {
		w.deliveries = append(w.deliveries, d)
	}
	if e.Op != witness.OpDeliver {
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

// Delivered returns the sends attributed to traceID by its session cgroup: to
// the peer a connected socket holds, or to the destination a send named. Call
// Stop first so no event is still in the ring buffer.
func (w *Witness) Delivered(traceID string) []witness.DeliveryEvent {
	traceID = strings.ToLower(traceID)
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []witness.DeliveryEvent
	for _, e := range w.deliveries {
		if e.TraceID == traceID {
			out = append(out, e)
		}
	}
	return out
}

// DeliveryCoverage reports what this capture might have missed even when
// healthy. OtherFamilySends and Lost are read at Stop.
func (w *Witness) DeliveryCoverage() witness.DeliveryCoverage {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.coverage
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
