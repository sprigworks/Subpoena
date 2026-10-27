package witness

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ByDestination means the event was seen arriving at a destination the test
// controls, not tied to any trace. Like lineage it is returned for every trace:
// the safe direction for an absence claim, exact when one trace is in flight.
const ByDestination Attribution = "destination"

// Sinkhole is a tier-1 network witness: a TCP listener the test stands up as a
// destination the code under test must never reach, then points that code at.
// Every connection that arrives is recorded and closed. It needs no root and no
// kernel support, and it is independent of the application: the application
// cannot unsay a connection the listener accepted.
//
// It sees only its own address. "Nothing reached the sinkhole" is the claim it
// can certify; "nothing reached anywhere" needs netbpf. Arrivals carry no PID
// or cgroup, so Dialed returns every arrival for every trace (ByDestination).
type Sinkhole struct {
	ln   *net.TCPListener
	addr netip.AddrPort
	done chan struct{}

	mu       sync.Mutex
	events   []NetworkEvent
	err      error
	finished bool
}

var (
	_ NetworkWitness = (*Sinkhole)(nil)
	_ HealthReporter = (*Sinkhole)(nil)
)

// NewSinkhole listens on a free loopback port and starts recording.
func NewSinkhole() (*Sinkhole, error) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("sinkhole: %w", err)
	}
	s := &Sinkhole{ln: ln, addr: ln.Addr().(*net.TCPAddr).AddrPort(), done: make(chan struct{})}
	go s.accept()
	return s, nil
}

// Addr is where the sinkhole listens. Point the code under test at it.
func (s *Sinkhole) Addr() netip.AddrPort { return s.addr }

func (s *Sinkhole) accept() {
	defer close(s.done)
	for {
		c, err := s.ln.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.fail(fmt.Errorf("sinkhole: accept: %w", err))
			}
			return
		}
		s.record()
		c.Close()
	}
}

func (s *Sinkhole) record() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, NetworkEvent{
		Op:          OpConnect,
		Protocol:    "tcp",
		Dest:        s.addr,
		Attribution: ByDestination,
		SeenAt:      time.Now(),
	})
}

func (s *Sinkhole) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

// Stop drains connections the kernel has completed but not yet handed over,
// then closes the listener. A connection that finished its handshake before
// Stop is recorded even if its client has already hung up; one arriving
// during Stop may be refused unseen, so stop only after the code under test is
// done. Call it before asking Dialed or Health; later calls return the same
// result.
func (s *Sinkhole) Stop() error {
	s.mu.Lock()
	if s.finished {
		defer s.mu.Unlock()
		return s.err
	}
	s.mu.Unlock()
	n, drainErr := drainAccepts(s.ln)
	for i := 0; i < n; i++ {
		s.record()
	}
	if drainErr != nil {
		s.fail(fmt.Errorf("sinkhole: drain (queued connections may be unseen): %w", drainErr))
	}
	s.ln.Close()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	return s.err
}

// Dialed returns every connection that reached the sinkhole, whatever the
// trace: arrivals cannot be told apart by trace.
func (s *Sinkhole) Dialed(string) []NetworkEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]NetworkEvent(nil), s.events...)
}

// Health reports whether the capture is complete: stopped, drained, and no
// accept error along the way.
func (s *Sinkhole) Health() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if !s.finished {
		return errors.New("sinkhole: capture has not stopped")
	}
	return nil
}
