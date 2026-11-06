package witness

import (
	"net/netip"
	"time"
)

// DeliveryEvent is one send seen leaving a process in a session cgroup: bytes
// handed to an inet socket for a peer. It is the event a broker or a fan-out
// produces when it writes to a subscriber on a socket it accepted long ago,
// which has no dial for NetworkWitness to see.
//
// It records the attempt, not its outcome, and says nothing of content: the
// kernel hook runs before the send, so a send that later fails still counts,
// and a keepalive or an ack on a peer's socket looks like a message on it.
type DeliveryEvent struct {
	PID  int
	Comm string // task name, if the witness reports one
	// Op is OpDeliver for a send on a connected socket, OpSendmsg for a send
	// that named its destination.
	Op       Op
	Protocol string // "tcp", "udp", or another IP protocol name or number
	// Peer is the far end of the send: the socket's remote address and port,
	// or the destination the send named. It is the zero AddrPort, or an
	// unspecified address, when the witness could not tell (see PeerUnknown).
	// IPv4-mapped IPv6 addresses are unmapped.
	Peer netip.AddrPort
	// Local is this end of the socket: for a broker, usually its listener's
	// port. Peers are told apart by Peer, not by Local.
	Local       netip.AddrPort
	Bytes       uint64 // bytes the caller asked to send, not bytes the peer got
	Cgroup      string // cgroup path, if readable
	CgroupID    uint64 // kernel cgroup ID, if the witness reports one (0 otherwise)
	TraceID     string // set when Attribution is ByCgroup
	Attribution Attribution
	SeenAt      time.Time // when the witness read the event, not when it was sent
}

// PeerUnknown reports whether the witness saw the send but not where it went.
// The send may have gone to any peer, so a rule about a peer counts it as a
// hit and no allow list excuses it.
func (e DeliveryEvent) PeerUnknown() bool {
	return !e.Peer.Addr().IsValid() || e.Peer.Addr().IsUnspecified()
}

// DeliveryWitness reports sends attributable to a trace, on connected sockets
// included. It is the delivery sibling of Witness and NetworkWitness, under the
// same rules: independent of the application, over-reporting rather than
// under-reporting, and able to certify absence only through HealthReporter.
//
// There is no tier-1 implementation. Seeing a write on a socket another process
// holds takes the kernel: a listener the test stands up sees only its own
// connections, and the code under test's own report of a write is testimony.
type DeliveryWitness interface {
	// Delivered returns the sends made on behalf of traceID. Implementations
	// must err toward over-reporting: an absence claim built on this must
	// never pass because the witness was unsure.
	Delivered(traceID string) []DeliveryEvent
}

// DeliveryCoverage says what a capture might have missed even when healthy,
// counted by the kernel for the session cgroups.
type DeliveryCoverage struct {
	// Sends is the sends attributed to a session, every trace together.
	Sends uint64
	// UnknownPeers is how many of them have no peer the witness could read.
	UnknownPeers uint64
	// OtherFamilySends is sends from a session cgroup on sockets that are not
	// inet (AF_UNIX, netlink, ...). They have no address and are not reported,
	// so a peer reached that way is not in Delivered.
	OtherFamilySends uint64
	// Lost is failed ring-buffer reservations, host-wide. Above zero, Health
	// fails as well.
	Lost uint64
}
