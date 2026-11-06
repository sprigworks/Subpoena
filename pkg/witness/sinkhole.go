package witness

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// ByDestination means the event was seen arriving at a destination the test
// controls, not tied to any trace. Like lineage it is returned for every trace:
// the safe direction for an absence claim, exact when one trace is in flight.
const ByDestination Attribution = "destination"

// ByMark means an answering Sinkhole read the trace from the request's
// MarkHeader. The header comes through the code under test, so a mark can only
// narrow an arrival to a trace: an arrival with no mark stays ByDestination and
// is returned for every trace.
const ByMark Attribution = "mark"

// MarkHeader is the request header an answering Sinkhole reads a trace ID from.
// The test sends it on the request it drives through the code under test.
const MarkHeader = "X-Subpoena-Mark"

// answerRead bounds how long an answering Sinkhole waits on one connection. The
// arrival is already recorded by then.
const answerRead = 2 * time.Second

const answer200 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

// Sinkhole is a tier-1 network witness: a TCP listener the test stands up as a
// destination the code under test must never reach, then points that code at.
// Every connection that arrives is recorded and closed. It needs no root and no
// kernel support, and it is independent of the application: the application
// cannot unsay a connection the listener accepted.
//
// It sees only its own address. "Nothing reached the sinkhole" is the claim it
// can certify; "nothing reached anywhere" needs netbpf. Arrivals carry no PID
// or cgroup, so Dialed returns every arrival for every trace (ByDestination).
//
// A proxy turns a closed connection into a 502, which can hide what the proxy
// did next. NewAnsweringSinkhole stands in for an upstream that must answer: it
// replies 200 with an empty body, and records the request line and headers.
type Sinkhole struct {
	ln     *net.TCPListener
	addr   netip.AddrPort
	done   chan struct{}
	answer bool
	conns  sync.WaitGroup

	mu       sync.Mutex
	events   []NetworkEvent
	err      error
	finished bool
}

var (
	_ NetworkWitness = (*Sinkhole)(nil)
	_ HealthReporter = (*Sinkhole)(nil)
)

// drain is drainAccepts, replaceable in tests to inject a failed drain.
var drain = drainAccepts

// DrainAccepts accepts and closes every connection already queued on ln, without
// waiting, and says how many there were. It is for a witness with its own
// listener: a connection in the queue at Stop arrived, and nothing has read it.
func DrainAccepts(ln *net.TCPListener) (int, error) { return drainAccepts(ln) }

// NewSinkhole listens on a free port on 127.0.0.1 and starts recording.
func NewSinkhole() (*Sinkhole, error) {
	return NewSinkholeAt(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0))
}

// NewSinkholeAt listens on addr and starts recording; port 0 picks a free one.
// Use it when the claim is about a particular address: ::1 for an IPv6 path,
// or a second loopback address when 127.0.0.1 is one the code may reach.
func NewSinkholeAt(addr netip.AddrPort) (*Sinkhole, error) {
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
	if err != nil {
		return nil, fmt.Errorf("sinkhole: %w", err)
	}
	s := &Sinkhole{ln: ln, addr: ln.Addr().(*net.TCPAddr).AddrPort(), done: make(chan struct{})}
	go s.accept()
	return s, nil
}

// NewAnsweringSinkhole is NewSinkhole for an upstream that must answer. Every
// arrival is recorded before a byte is read, so a client that sends nothing, or
// something that is not HTTP, still counts. Each connection gets one 200 with
// an empty body, and is closed.
func NewAnsweringSinkhole() (*Sinkhole, error) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("sinkhole: %w", err)
	}
	s := &Sinkhole{ln: ln, addr: ln.Addr().(*net.TCPAddr).AddrPort(), done: make(chan struct{}), answer: true}
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
		i := s.record()
		if s.answer {
			s.conns.Add(1)
			go s.serve(c, i)
			continue
		}
		c.Close()
	}
}

// serve reads one request, fills in event i, answers and closes. A request it
// cannot read leaves the arrival as it is, which holds for every trace.
func (s *Sinkhole) serve(c *net.TCPConn, i int) {
	defer s.conns.Done()
	defer c.Close()
	c.SetDeadline(time.Now().Add(answerRead))
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return
	}
	s.mu.Lock()
	e := &s.events[i]
	e.Request = req.Method + " " + req.RequestURI + " " + req.Proto
	e.Headers = req.Header
	if mark := req.Header.Get(MarkHeader); mark != "" {
		e.TraceID, e.Attribution = mark, ByMark
	}
	s.mu.Unlock()
	io.WriteString(c, answer200)
	io.Copy(io.Discard, req.Body) // closing on unread bytes can reset the answer away
}

func (s *Sinkhole) record() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, NetworkEvent{
		Op:          OpConnect,
		Protocol:    "tcp",
		Dest:        s.addr,
		Attribution: ByDestination,
		SeenAt:      time.Now(),
	})
	return len(s.events) - 1
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
	n, drainErr := drain(s.ln)
	for i := 0; i < n; i++ {
		s.record()
	}
	if drainErr != nil {
		s.fail(fmt.Errorf("sinkhole: drain (queued connections may be unseen): %w", drainErr))
	}
	s.ln.Close()
	<-s.done
	s.conns.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	return s.err
}

// Dialed returns every connection that reached the sinkhole, leaving out only
// an arrival marked with a different trace. An arrival with no mark cannot be
// told apart by trace, so it is returned for every trace.
func (s *Sinkhole) Dialed(traceID string) []NetworkEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []NetworkEvent
	for _, e := range s.events {
		if e.Attribution != ByMark || e.TraceID == traceID {
			out = append(out, e)
		}
	}
	return out
}

// Health reports whether the capture is complete: stopped, drained, and no
// accept error along the way.
//
//subpoena:enforcement_point
func (s *Sinkhole) Health() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err //subpoena:enforcement
	}
	if !s.finished {
		return errors.New("sinkhole: capture has not stopped") //subpoena:enforcement
	}
	return nil
}
