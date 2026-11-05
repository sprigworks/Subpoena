//subpoena:impl_derived
//subpoena:pure_logic

package witness

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSinkholeRecordsArrivalsForEveryTrace(t *testing.T) {
	s, err := NewSinkhole()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", s.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := s.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	for _, trace := range []string{"a", "b"} {
		got := s.Dialed(trace)
		if len(got) != 3 {
			t.Fatalf("Dialed(%s) = %d events, want 3", trace, len(got))
		}
		for _, e := range got {
			if e.Dest != s.Addr() || e.Op != OpConnect || e.Protocol != "tcp" || e.Attribution != ByDestination {
				t.Fatalf("event %+v", e)
			}
		}
	}
}

// Many connections that hang up at once, right before Stop: every completed
// one is counted, whether the accept loop or Stop's drain picked it up.
// (TestSinkholeDrainCountsQueuedConnections covers the drain alone.)
func TestSinkholeCountsEveryConnectionBeforeStop(t *testing.T) {
	s, err := NewSinkhole()
	if err != nil {
		t.Fatal(err)
	}
	const n = 200
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := len(s.Dialed("")); got != n {
		t.Fatalf("saw %d of %d connections", got, n)
	}
}

func TestSinkholeDrainCountsQueuedConnections(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for i := 0; i < 5; i++ { // nobody accepts: all five sit in the queue
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	n, err := drainAccepts(ln)
	if err != nil || n != 5 {
		t.Fatalf("drainAccepts = %d, %v; want 5", n, err)
	}
	if n, err := drainAccepts(ln); err != nil || n != 0 {
		t.Fatalf("second drain = %d, %v; want an empty queue", n, err)
	}
}

func TestSinkholeHealthNeedsStop(t *testing.T) {
	s, err := NewSinkhole()
	if err != nil {
		t.Fatal(err)
	}
	if s.Health() == nil {
		t.Fatal("a running sinkhole must not certify absence")
	}
	s.Stop()
	if s.Health() != nil || s.Stop() != nil {
		t.Fatal("stopped sinkhole should be healthy, and Stop repeatable")
	}
}

// A failed drain means queued connections may have gone unseen: Stop and
// Health must both say so, and stay saying so, even though Dialed is empty.
func TestSinkholeFailedDrainCannotCertifyAbsence(t *testing.T) {
	broken := errors.New("accept queue unreadable")
	drain = func(*net.TCPListener) (int, error) { return 0, broken }
	t.Cleanup(func() { drain = drainAccepts })
	s, err := NewSinkhole()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); !errors.Is(err, broken) {
		t.Fatalf("Stop = %v, want the drain failure", err)
	}
	if err := s.Health(); !errors.Is(err, broken) {
		t.Fatalf("Health = %v, want the drain failure", err)
	}
	if len(s.Dialed("")) != 0 {
		t.Fatal("no arrivals were recorded")
	}
	if err := s.Stop(); !errors.Is(err, broken) {
		t.Fatalf("second Stop = %v, erased the failure", err)
	}
}

// A sinkhole at a chosen address records arrivals there, over IPv6 too.
func TestSinkholeAtChosenAddress(t *testing.T) {
	for _, want := range []string{"127.0.0.2", "::1"} {
		t.Run(want, func(t *testing.T) {
			addr := netip.MustParseAddr(want)
			s, err := NewSinkholeAt(netip.AddrPortFrom(addr, 0))
			if err != nil {
				t.Skipf("address unavailable here: %v", err)
			}
			if got := s.Addr().Addr(); got != addr || s.Addr().Port() == 0 {
				t.Fatalf("listening on %v, want %v and a real port", s.Addr(), addr)
			}
			c, err := net.Dial("tcp", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			if err := s.Stop(); err != nil {
				t.Fatal(err)
			}
			if got := s.Dialed("any"); len(got) != 1 || got[0].Dest != s.Addr() {
				t.Fatalf("want one arrival at %v, got %+v", s.Addr(), got)
			}
		})
	}
}

// An address the host doesn't have is an error, not a sinkhole that sees nothing.
func TestSinkholeAtUnavailableAddressFails(t *testing.T) {
	if s, err := NewSinkholeAt(netip.MustParseAddrPort("192.0.2.1:0")); err == nil {
		s.Stop()
		t.Fatal("want an error binding an address this host does not have")
	}
}
