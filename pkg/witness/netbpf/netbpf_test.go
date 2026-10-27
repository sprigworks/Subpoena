//subpoena:impl_derived
//subpoena:pure_logic

// Attribution and bookkeeping, fed synthetic kernel events: no eBPF, no
// privileges. kernel_linux_test.go loads the real programs.
package netbpf

import (
	"net/netip"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

const (
	tidA = "0af7651916cd43dd8448eb211c80319c"
	tidB = "4bf92f3577b34da6a3ce929d0e0e4736"
)

var dest = netip.MustParseAddrPort("192.0.2.7:443")

func dialEv(pid int, cg string) Event {
	return Event{Op: witness.OpConnect, PID: pid, Comm: "curl", Protocol: "tcp", Dest: dest, Cgroup: cg, CgroupID: 42}
}

func TestSessionCgroupAttributesByTrace(t *testing.T) {
	w := New(Config{CgroupRoot: "/sys/fs/cgroup/subpoena"})
	w.handle(dialEv(10, "system.slice/docker-x.scope/subpoena/"+tidA))
	w.handle(dialEv(11, "subpoena/"+tidB))
	w.handle(dialEv(12, "user.slice/session-1.scope")) // not a session: not kept
	w.handle(dialEv(13, "other/"+tidA))                // trace-shaped name under another root: not a session
	w.handle(dialEv(14, "subpoena/"+tidA+"/escape"))   // a child of the session cgroup is still the session

	got := w.Dialed(tidA)
	if len(got) != 2 || got[0].PID != 10 || got[1].PID != 14 {
		t.Fatalf("Dialed(A) = %+v", got)
	}
	e := got[0]
	if e.Attribution != witness.ByCgroup || e.TraceID != tidA || e.Op != witness.OpConnect ||
		e.Protocol != "tcp" || e.Dest != dest || e.Comm != "curl" || e.CgroupID != 42 {
		t.Fatalf("event fields not carried over: %+v", e)
	}
	if got := w.Dialed(tidB); len(got) != 1 || got[0].PID != 11 {
		t.Fatalf("Dialed(B) = %+v", got)
	}
	if got := w.Dialed("4BF92F3577B34DA6A3CE929D0E0E4736"); len(got) != 1 {
		t.Fatalf("trace ID case matters: %+v", got)
	}
	if n := len(w.Events()); n != 3 {
		t.Fatalf("kept %d events, want only the 3 attributed ones", n)
	}
}

func TestOnEventSeesEverythingAndNoRetainKeepsNothing(t *testing.T) {
	var seen []Event
	w := New(Config{CgroupRoot: "/x/subpoena", NoRetain: true, OnEvent: func(e Event) { seen = append(seen, e) }})
	w.handle(dialEv(10, "subpoena/"+tidA))
	w.handle(dialEv(11, "user.slice"))
	if len(seen) != 2 || seen[0].TraceID != tidA || seen[1].Attribution != "" {
		t.Fatalf("OnEvent saw %+v", seen)
	}
	if len(w.Events()) != 0 || len(w.Dialed(tidA)) != 0 {
		t.Fatal("NoRetain kept events")
	}
}

func TestHealthRequiresFinalRetainedCapture(t *testing.T) {
	w := New(Config{})
	if w.Health() == nil {
		t.Fatal("unstarted capture must be unhealthy")
	}
	w.finished = true
	if w.Health() != nil {
		t.Fatal("completed capture should be healthy")
	}
	w.cfg.NoRetain = true
	if w.Health() == nil {
		t.Fatal("NoRetain must not certify empty Dialed")
	}
}

func TestProtocolName(t *testing.T) {
	for p, want := range map[uint32]string{6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 99: "99"} {
		if got := protocolName(p); got != want {
			t.Errorf("protocolName(%d) = %q, want %q", p, got, want)
		}
	}
}
