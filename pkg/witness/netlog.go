package witness

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// NetLine is one line of subpoena-witness -net-out output: one outbound
// connection attempt. The JSON field names are an interface (other
// languages' readers use them); the schema is
// docs/witness-network-event.schema.json, and docs/ports.md says what each
// field means. The network file has its own start and stop records (Record).
type NetLine struct {
	Time     time.Time `json:"time"`
	Op       string    `json:"op"`
	Protocol string    `json:"protocol"`
	// Dest is "ip:port", "[ip]:port" for IPv6, an IPv4-mapped address
	// unmapped: netip.AddrPort's String.
	Dest        string `json:"dest"`
	PID         int    `json:"pid"`
	HostPID     int    `json:"host_pid"`
	Comm        string `json:"comm"`
	SockType    int    `json:"sock_type"`
	CgroupID    uint64 `json:"cgroup_id"`
	Cgroup      string `json:"cgroup"`
	TraceID     string `json:"trace_id,omitempty"`
	Attribution string `json:"attribution,omitempty"`
}

// NetworkLog is a network witness file read back: a NetworkWitness over what
// subpoena-witness -net-out wrote.
type NetworkLog struct {
	lines  []NetLine
	events []NetworkEvent // lines[i], decoded
	health error
}

var (
	_ NetworkWitness = (*NetworkLog)(nil)
	_ HealthReporter = (*NetworkLog)(nil)
)

// netKeys are the field names of NetLine and Record.
var netKeys = jsonNames(NetLine{}, Record{})

// ReadNetworkLog reads subpoena-witness -net-out JSON lines, under ReadLog's
// rules: the same read errors, and the same capture windows and faults. A
// dest that is not an IP address and port is a read error too; an
// IPv4-mapped address is read as IPv4.
//
//subpoena:enforcement_point
func ReadNetworkLog(r io.Reader) (*NetworkLog, error) {
	l := &NetworkLog{}
	c := &capture{known: netKeys, noun: "a connection attempt"}
	err := c.scan(r, func(n int, b []byte) (time.Time, error) {
		var ln NetLine
		if err := json.Unmarshal(b, &ln); err != nil {
			return time.Time{}, fmt.Errorf("witness: line %d: %w", n, err)
		}
		dest, err := parseDest(ln.Dest)
		if err != nil {
			return time.Time{}, fmt.Errorf("witness: line %d: %w", n, err) //subpoena:enforcement
		}
		l.lines = append(l.lines, ln)
		l.events = append(l.events, NetworkEvent{
			PID: ln.PID, Comm: ln.Comm, Op: Op(ln.Op), Protocol: ln.Protocol, Dest: dest,
			Cgroup: ln.Cgroup, CgroupID: ln.CgroupID, TraceID: ln.TraceID,
			Attribution: Attribution(ln.Attribution), SeenAt: ln.Time,
		})
		return ln.Time, nil
	})
	if err != nil {
		return nil, err
	}
	l.health = c.health
	return l, nil
}

// parseDest reads "ip:port" or "[ipv6]:port". A zone is refused: the witness
// never writes one, and other languages' address types differ on it.
func parseDest(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err == nil && ap.Addr().Zone() != "" {
		err = fmt.Errorf("has a zone")
	}
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("dest %q is not ip:port ([ip]:port for IPv6): %v", s, err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// Health reports the first capture fault in the file, as Log.Health does.
// Absence can rest on the file only when Health is nil.
//
//subpoena:enforcement_point
func (l *NetworkLog) Health() error {
	if l.health != nil {
		return l.health //subpoena:enforcement
	}
	return nil
}

// Len returns the number of attempts read.
func (l *NetworkLog) Len() int { return len(l.lines) }

// Lines returns the attempts read, in file order.
func (l *NetworkLog) Lines() []NetLine { return append([]NetLine(nil), l.lines...) }

// Dialed returns every attempt whose trace ID, read by the kernel side from
// its cgroup, is traceID. Nothing the application controls is consulted. The
// empty trace ID matches nothing.
func (l *NetworkLog) Dialed(traceID string) []NetworkEvent {
	if traceID == "" {
		return nil
	}
	traceID = strings.ToLower(traceID) // as netbpf.Witness.Dialed
	var out []NetworkEvent
	for _, e := range l.events {
		if strings.ToLower(e.TraceID) == traceID {
			out = append(out, e)
		}
	}
	return out
}
