package witness

import (
	"fmt"
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
	// Broadcast says the socket had SO_BROADCAST set. Only the route can say an
	// address like 172.17.255.255 is a subnet's broadcast, and a send that names its
	// address has no route yet, so the option stands for it: see Fanout. It alone
	// means little: Go sets it on every socket it makes.
	Broadcast bool
	// BroadcastRoute says the send went out on a broadcast route the socket held.
	// A connected socket keeps the route it found, so this holds with the option
	// cleared since, and for a broadcast address of any shape.
	BroadcastRoute bool
	// AnyPeer asks a match whether it would take this send if the send reached
	// everyone listening on its port. A witness never sets it; see AnyMember.
	AnyPeer bool
}

// Fanout reports whether the send may reach sockets other than its Peer: Peer is
// a multicast group or the limited broadcast address, or the socket's route says
// it is a broadcast address, or it may be a subnet's. Who was listening, the kernel
// does not say at the send, so a claim about one of them cannot be settled either
// way.
//
// A subnet's usual broadcast address has every host bit set, and a subnet with one
// has at least two, so with Broadcast only an IPv4 address ending in those two is
// taken for one. A host setting can name any other address (ip addr ... brd). Only
// BroadcastRoute shows that, so a send that named such an address is not Fanout.
//
//subpoena:enforcement_point
func (e DeliveryEvent) Fanout() bool {
	if e.BroadcastRoute {
		return true //subpoena:enforcement
	}
	a := e.Peer.Addr().Unmap()
	if a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	return e.Broadcast && a.Is4() && a.As4()[3]&3 == 3
}

// AnyMember is e as a send that reached everyone listening on its port, to ask a
// match whether a Fanout send could be one it is about. harness.DeliveryTo reads
// AnyPeer. A match of your own that does not cannot be asked, so it sees only Peer.
func (e DeliveryEvent) AnyMember() DeliveryEvent {
	e.AnyPeer = true
	return e
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
	// RecursionMisses is program runs the kernel skipped, host-wide, each maybe a
	// send or a dial that was never reported. Above zero, Health fails.
	RecursionMisses uint64
	// LeftSession is tasks that left a session cgroup during the capture. Above
	// zero, Health fails: what they did next is in no session.
	LeftSession uint64
	// TooDeep is attempts and moves in cgroup paths too long to walk to the top,
	// host-wide. Above zero, Health fails.
	TooDeep uint64
	// Unattributed is attempts from under the session root in no session. Above
	// zero, Health fails.
	Unattributed uint64
}

// String is the coverage in one line, as a stop record carries it.
func (c DeliveryCoverage) String() string {
	return fmt.Sprintf("%d send(s) reported, %d with an unknown peer; %d send(s) on sockets that are not inet, not reported; %d kernel event(s) lost; %d recursion miss(es); %d task(s) left a session; %d too deep to attribute; %d under the root in no session",
		c.Sends, c.UnknownPeers, c.OtherFamilySends, c.Lost, c.RecursionMisses, c.LeftSession, c.TooDeep, c.Unattributed)
}
