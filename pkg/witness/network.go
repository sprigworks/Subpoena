package witness

import (
	"net/netip"
	"time"
)

// Op is the socket operation a network witness saw.
type Op string

const (
	// OpConnect is a connect() on an inet socket: a TCP handshake starting, or
	// a UDP socket fixing its peer.
	OpConnect Op = "connect"
	// OpSendmsg is a send with an explicit destination (sendto, sendmsg,
	// sendmmsg): unconnected UDP, or TCP Fast Open.
	OpSendmsg Op = "sendmsg"
)

// NetworkEvent is one observed outbound connection attempt. It records the
// attempt, not its outcome: a refused or unreachable connect still counts,
// because "the code tried" contradicts "the code was denied".
type NetworkEvent struct {
	PID         int
	Comm        string // task name, if the witness reports one
	Op          Op
	Protocol    string         // "tcp", "udp", or another IP protocol name or number
	Dest        netip.AddrPort // IPv4-mapped IPv6 addresses are unmapped
	Cgroup      string         // cgroup path, if readable
	CgroupID    uint64         // kernel cgroup ID, if the witness reports one (0 otherwise)
	TraceID     string         // set when Attribution is ByCgroup
	Attribution Attribution
	SeenAt      time.Time
}

// NetworkWitness reports outbound connection attempts attributable to a trace.
// It is the network sibling of Witness, under the same rules: independent of
// the application, over-reporting rather than under-reporting, and able to
// certify absence only through HealthReporter.
//
// Destinations are addresses, not host names. A rule about a name ("never
// reach example.com") needs the test to pin what the name resolves to.
type NetworkWitness interface {
	// Dialed returns the connection attempts made on behalf of traceID.
	// Implementations must err toward over-reporting: an absence claim built on
	// this must never pass because the witness was unsure.
	Dialed(traceID string) []NetworkEvent
}
