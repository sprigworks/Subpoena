// Package dbproxy is a database witness: a wire-protocol proxy for PostgreSQL and
// MySQL. A test points the application's DSN at its loopback listener, and it
// forwards to the real server, logging statements and commits per connection.
//
// It has no ORM awareness and nothing inside the database. It reads two things:
// the statements on the wire, and the server's replies, which decide what was
// committed. The application cannot unsay a reply the server gave. It has no
// SQLite or MongoDB support: neither speaks these protocols, and SQLite has no
// socket at all.
//
// A connection goes through a session, a state machine with one step per protocol
// message in each direction. What cannot be read is never read as absence: an
// unknown frame, a connection dropped with a transaction open, a connection it
// could not proxy and a client that insists on TLS all fail Health, and a
// statement it cannot parse counts against every table.
package dbproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// Engine names a wire protocol.
type Engine string

const (
	Postgres Engine = "postgres"
	MySQL    Engine = "mysql"
)

const (
	// maxFrame is the largest message it will hold in memory to read. A longer
	// one it must read is a capture fault; one it need not read streams through.
	maxFrame = 64 << 20

	dialTimeout = 5 * time.Second

	// settleTimeout bounds how long Stop waits for replies already on their way.
	settleTimeout = time.Second
)

var (
	// errBlind ends parsing on a connection; its bytes go on as a raw copy.
	errBlind = errors.New("dbproxy: connection unreadable")
	// errClose ends a connection that must not go on.
	errClose = errors.New("dbproxy: connection closed by the witness")
)

// drain is witness.DrainAccepts, replaceable in tests to inject a failed drain.
var drain = witness.DrainAccepts

// session follows one connection. Each step moves one protocol message, and
// returns io.EOF or a read error at the end of its direction, errBlind if the
// rest must be copied raw, and errClose if the connection must end. The two
// directions run concurrently.
type session interface {
	client(r *bufio.Reader, up, back io.Writer) error
	server(r *bufio.Reader, back io.Writer) error
	// inFlight reports whether a reply is owed.
	inFlight() bool
	// finish settles the connection after both directions have ended.
	finish()
}

// Config says what to proxy.
type Config struct {
	Engine   Engine
	Upstream string // host:port of the real server
	// Listen is the address to listen on. Zero: a free port on 127.0.0.1.
	Listen netip.AddrPort
	// Output, if set, receives the capture as witness-file JSON lines
	// (docs/witness-event.schema.json): for a reader in another process, such as
	// Python's. Mark does not take back lines already written.
	Output io.Writer
}

// Proxy is a database witness. Start it with New, point the application at Addr,
// Stop it, then ask it. Attribution is by destination: Committed returns every
// write for every trace, which is exact when the harness drives one request at a
// time, and the safe direction when it does not.
type Proxy struct {
	cfg  Config
	ln   *net.TCPListener
	addr netip.AddrPort
	cap  *capture
	done chan struct{}
	stop sync.Once

	mu     sync.Mutex
	nextID int
	open   map[int]*link
	conns  sync.WaitGroup
}

// link is one proxied connection.
type link struct {
	client, up net.Conn
	s          session
}

var (
	_ witness.DBWitness      = (*Proxy)(nil)
	_ witness.HealthReporter = (*Proxy)(nil)
)

// New listens and starts proxying.
func New(cfg Config) (*Proxy, error) {
	if cfg.Engine != Postgres && cfg.Engine != MySQL {
		return nil, fmt.Errorf("dbproxy: unknown engine %q", cfg.Engine)
	}
	if cfg.Upstream == "" {
		return nil, errors.New("dbproxy: no upstream address")
	}
	listen := cfg.Listen
	if !listen.IsValid() {
		listen = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
	}
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(listen))
	if err != nil {
		return nil, fmt.Errorf("dbproxy: %w", err)
	}
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	p := &Proxy{
		cfg: cfg, ln: ln, addr: addr, done: make(chan struct{}), open: map[int]*link{},
		cap: &capture{engine: string(cfg.Engine), dest: addr},
	}
	if err := p.cap.open(cfg.Output); err != nil {
		ln.Close()
		return nil, fmt.Errorf("dbproxy: writing the witness file: %w", err)
	}
	go p.accept()
	return p, nil
}

// Addr is where the witness listens. Point the application's DSN here, with TLS
// off or preferred, not required.
func (p *Proxy) Addr() netip.AddrPort { return p.addr }

// Mark ends the setup phase: writes that committed before it are not reported
// by Committed, so a test can run migrations and seed rows through the proxy
// first. A transaction still open at Mark is not setup; its writes count when it
// commits. Capture faults are never forgotten.
func (p *Proxy) Mark() { p.cap.setMark() }

//subpoena:enforcement_point
func (p *Proxy) accept() {
	defer close(p.done)
	for {
		c, err := p.ln.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.cap.fault("accept: %v", err) //subpoena:enforcement
			}
			return
		}
		p.mu.Lock()
		p.nextID++
		id := p.nextID
		p.conns.Add(1)
		p.mu.Unlock()
		go p.serve(c, id)
	}
}

func (p *Proxy) newSession(id int) session {
	if p.cfg.Engine == MySQL {
		return newMySQLSession(p.cap, id)
	}
	return newPostgresSession(p.cap, id)
}

// serve proxies one connection until both directions end.
//
//subpoena:enforcement_point
func (p *Proxy) serve(client *net.TCPConn, id int) {
	defer p.conns.Done()
	defer client.Close()
	up, err := net.DialTimeout("tcp", p.cfg.Upstream, dialTimeout)
	if err != nil {
		p.cap.fault("connection %d could not be proxied: %v", id, err) //subpoena:enforcement
		return
	}
	defer up.Close()
	s := p.newSession(id)
	p.mu.Lock()
	p.open[id] = &link{client, up, s}
	p.mu.Unlock()

	served := make(chan struct{})
	go func() {
		defer close(served)
		defer client.Close() // the server has gone
		r := bufio.NewReaderSize(up, 64<<10)
		back := &lenientWriter{w: client}
		pump(func() error { return s.server(r, back) }, back, r)
	}()
	r := bufio.NewReaderSize(client, 64<<10)
	back := &lenientWriter{w: client}
	pump(func() error { return s.client(r, up, back) }, up, r)
	// Keep reading the server: a statement sent just before the client left is
	// still answered, and the answer says whether it committed.
	if t, ok := up.(*net.TCPConn); ok {
		t.CloseWrite()
	}
	<-served
	s.finish()
	p.mu.Lock()
	delete(p.open, id)
	p.mu.Unlock()
}

func pump(step func() error, dst io.Writer, src io.Reader) {
	for {
		switch err := step(); {
		case err == nil:
		case errors.Is(err, errBlind):
			io.Copy(dst, src)
			return
		default:
			return
		}
	}
}

// lenientWriter stops writing after the first failure and reports none: a client
// that left must not stop the witness reading what the server answers.
type lenientWriter struct {
	w    io.Writer
	gone bool
}

func (l *lenientWriter) Write(b []byte) (int, error) {
	if !l.gone {
		if _, err := l.w.Write(b); err != nil {
			l.gone = true
		}
	}
	return len(b), nil
}

// Stop ends the capture: it drains connections the kernel has completed but not
// handed over, waits briefly for replies on their way, and closes everything. A
// connection left in a transaction is a fault; an idle pooled one is not. Stop
// only after the code under test is done. Later calls return the same result.
//
//subpoena:enforcement_point
func (p *Proxy) Stop() error {
	p.stop.Do(func() {
		n, err := drain(p.ln)
		if n != 0 {
			p.cap.fault("%d connections reached the listener as it stopped and were not proxied", n) //subpoena:enforcement
		}
		if err != nil {
			p.cap.fault("draining the listener (queued connections may be unseen): %v", err) //subpoena:enforcement
		}
		p.ln.Close()
		<-p.done
		p.settle()
		p.mu.Lock()
		for _, l := range p.open {
			l.client.Close()
			l.up.Close()
		}
		p.mu.Unlock()
		p.conns.Wait()
		p.cap.close()
	})
	return p.Health()
}

// settle waits, up to settleTimeout, for replies already owed.
func (p *Proxy) settle() {
	for deadline := time.Now().Add(settleTimeout); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		busy := false
		p.mu.Lock()
		for _, l := range p.open {
			busy = busy || l.s.inFlight()
		}
		p.mu.Unlock()
		if !busy {
			return
		}
	}
}

// Committed returns every committed write since Mark, zero-row ones included, for
// every trace: a socket has no trace on it. A rolled-back or refused write is not
// here, and a statement the witness could not read is, marked Opaque.
func (p *Proxy) Committed(traceID string) []witness.RowEvent { return p.cap.committed() }

// Statements returns every statement whose outcome is known, reads and rollbacks
// included, in the order their outcomes became known.
func (p *Proxy) Statements() []witness.RowEvent { return p.cap.snapshot() }

// Coverage reports what the capture saw and what it may have missed.
func (p *Proxy) Coverage() witness.DBCoverage { return p.cap.coverage() }

// Health reports whether absence can rest on the capture: stopped, and no fault
// on any connection. Faults are not per table. A connection it lost could have
// held any statement.
//
//subpoena:enforcement_point
func (p *Proxy) Health() error {
	if f := p.cap.faultList(); len(f) != 0 {
		return fmt.Errorf("dbproxy: %d capture faults, first: %s", len(f), f[0]) //subpoena:enforcement
	}
	if !p.cap.isStopped() {
		return errors.New("dbproxy: capture has not stopped") //subpoena:enforcement
	}
	return nil
}
