//subpoena:impl_derived
//subpoena:pure_logic

// The proxy over real sockets, with a scripted server standing in for the
// database: what a real one cannot be made to do on demand. No span is involved.
package dbproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

const traceID = "c0de00000000000000000000000000a1"

// upstream runs script once per connection, on a loopback listener.
func upstream(t *testing.T, script func(c net.Conn, r *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				script(c, bufio.NewReader(c))
			}()
		}
	}()
	return ln.Addr().String()
}

// readPG reads one typed message, or the startup packet if startup is set.
func readPG(r *bufio.Reader, startup bool) byte {
	var typ byte
	if !startup {
		typ, _ = r.ReadByte()
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0
	}
	n := int(h[0])<<24 | int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	io.CopyN(io.Discard, r, int64(n-4))
	return typ
}

// pgLogin answers a startup packet.
func pgLogin(c net.Conn, r *bufio.Reader) {
	readPG(r, true)
	c.Write(append(frame('R', []byte{0, 0, 0, 0}), pgReady('I')...))
}

// pgEcho logs a client in and answers every Query with tag.
func pgEcho(tag string) func(net.Conn, *bufio.Reader) {
	return func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		for {
			switch readPG(r, false) {
			case 'Q':
				c.Write(append(pgDone(tag), pgReady('I')...))
			default:
				return
			}
		}
	}
}

func start(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Stop() })
	return p
}

// pgClient connects and logs in.
func pgClient(t *testing.T, p *Proxy) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write(pgStartup(codeV3, 0))
	r := bufio.NewReader(c)
	readPG(r, false)
	readPG(r, false)
	return c, r
}

func query(t *testing.T, c net.Conn, r *bufio.Reader, sql string) {
	t.Helper()
	c.Write(pgQuery(sql))
	for {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		switch readPG(r, false) {
		case 'Z':
			return
		case 0:
			t.Fatal("connection lost")
		}
	}
}

func TestNewChecksItsConfig(t *testing.T) {
	if _, err := New(Config{Engine: "oracle", Upstream: "x:1"}); err == nil {
		t.Fatal("unknown engine")
	}
	if _, err := New(Config{Engine: Postgres}); err == nil {
		t.Fatal("no upstream")
	}
	if _, err := New(Config{Engine: Postgres, Upstream: "x:1", Listen: netip.MustParseAddrPort("192.0.2.1:1")}); err == nil {
		t.Fatal("an address that cannot be bound")
	}
	if _, err := New(Config{Engine: Postgres, Upstream: "x:1", Output: failWriter{}}); err == nil {
		t.Fatal("a witness file that cannot be started")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRunningWitnessIsNotHealthy(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, pgEcho("SELECT 1"))})
	if err := p.Health(); err == nil || !strings.Contains(err.Error(), "not stopped") {
		t.Fatalf("%v", err)
	}
	if v, _ := harness.NoRow(p, traceID, "users"); v != harness.Inconclusive {
		t.Fatalf("got %v", v)
	}
}

func TestCommittedWriteThroughTheProxy(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, pgEcho("INSERT 0 1"))})
	c, r := pgClient(t, p)
	query(t, c, r, "INSERT INTO users VALUES (1)")
	// The answer has reached the client, so the outcome must already be there.
	if got := p.Committed(traceID); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal("a second Stop returns the same result")
	}
	if v, _ := harness.NoRow(p, traceID, "users"); v != harness.Fail {
		t.Fatalf("got %v", v)
	}
	harness.RequireNoRow(t, p, traceID, "orders")
	if cov := p.Coverage(); cov.Connections != 1 || cov.Committed != 1 || cov.Statements != 1 {
		t.Fatalf("%+v", cov)
	}
	if got := p.Statements(); len(got) != 1 || got[0].Engine != "postgres" || got[0].Dest != p.Addr() {
		t.Fatalf("%+v", got)
	}
}

func TestEveryTraceSeesEveryWrite(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, pgEcho("INSERT 0 1"))})
	c, r := pgClient(t, p)
	query(t, c, r, "INSERT INTO users VALUES (1)")
	p.Stop()
	for _, id := range []string{"a", "b", ""} {
		if got := p.Committed(id); len(got) != 1 || got[0].Attribution != witness.ByDestination {
			t.Fatalf("trace %q: %+v", id, got)
		}
	}
}

func TestMarkHidesWhatCommittedBefore(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		tags := []string{"INSERT 0 1", "BEGIN", "INSERT 0 1", "COMMIT"}
		status := []byte{'I', 'T', 'T', 'I'}
		for i, tag := range tags {
			readPG(r, false)
			c.Write(append(pgDone(tag), pgReady(status[i])...))
		}
		readPG(r, false)
	})})
	c, r := pgClient(t, p)
	query(t, c, r, "INSERT INTO seed VALUES (1)")
	query(t, c, r, "BEGIN")
	query(t, c, r, "INSERT INTO open_at_mark VALUES (1)")
	p.Mark()
	query(t, c, r, "COMMIT")
	p.Stop()
	got := p.Committed(traceID)
	if len(got) != 1 || got[0].Tables[0] != "open_at_mark" {
		t.Fatalf("a transaction open at Mark is not setup: %+v", got)
	}
}

func TestUpstreamDownIsInconclusive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	p := start(t, Config{Engine: Postgres, Upstream: dead})
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the client must be cut off")
	}
	err = p.Stop()
	if err == nil || !strings.Contains(err.Error(), "could not be proxied") {
		t.Fatalf("%v", err)
	}
	if v, _ := harness.NoRow(p, traceID, "users"); v != harness.Inconclusive {
		t.Fatalf("got %v", v)
	}
}

// Unreadable bytes still reach the server, and its answer the client: a witness
// must not break the application it watches.
func TestUnreadableConnectionGoesOnRaw(t *testing.T) {
	seen := make(chan []byte, 1)
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		b := make([]byte, 7)
		io.ReadFull(r, b)
		seen <- b
		c.Write([]byte("reply"))
		io.Copy(io.Discard, r)
	})})
	c, r := pgClient(t, p)
	want := frame('@', []byte{1, 2})
	c.Write(want)
	select {
	case got := <-seen:
		if !bytes.Equal(got, want) {
			t.Fatalf("%q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the frame did not reach the server")
	}
	b := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(r, b); err != nil || string(b) != "reply" {
		t.Fatalf("%q, %v", b, err)
	}
	if err := p.Stop(); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("%v", err)
	}
}

// The client hangs up the moment it has sent. The server's answer still decides.
func TestClientGoneBeforeTheAnswer(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		readPG(r, false)
		time.Sleep(30 * time.Millisecond)
		c.Write(append(pgDone("INSERT 0 1"), pgReady('I')...))
		io.Copy(io.Discard, r)
	})})
	c, _ := pgClient(t, p)
	c.Write(pgQuery("INSERT INTO users VALUES (1)"))
	c.Close()
	time.Sleep(100 * time.Millisecond)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if v, _ := harness.NoRow(p, traceID, "users"); v != harness.Fail {
		t.Fatalf("got %v", v)
	}
}

// Stop waits for a reply on its way.
func TestStopWaitsForAReply(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		readPG(r, false)
		time.Sleep(50 * time.Millisecond)
		c.Write(append(pgDone("INSERT 0 1"), pgReady('I')...))
		io.Copy(io.Discard, r)
	})})
	c, _ := pgClient(t, p)
	c.Write(pgQuery("INSERT INTO users VALUES (1)"))
	time.Sleep(10 * time.Millisecond)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := p.Committed(traceID); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
}

// A reply that never comes: Stop gives up, and the capture says so.
func TestStopWithAReplyOwed(t *testing.T) {
	defer func(d time.Duration) { settleTimeout = d }(settleTimeout)
	settleTimeout = 20 * time.Millisecond
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		io.Copy(io.Discard, r)
	})})
	c, _ := pgClient(t, p)
	c.Write(pgQuery("INSERT INTO users VALUES (1)"))
	time.Sleep(10 * time.Millisecond)
	if err := p.Stop(); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("%v", err)
	}
	if cov := p.Coverage(); cov.Unknown != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestStopWithAnOpenTransaction(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		pgLogin(c, r)
		readPG(r, false)
		c.Write(append(pgDone("BEGIN"), pgReady('T')...))
		io.Copy(io.Discard, r)
	})})
	c, r := pgClient(t, p)
	query(t, c, r, "BEGIN")
	if err := p.Stop(); err == nil {
		t.Fatal("a transaction open at Stop has no seen outcome")
	}
}

func TestIdleConnectionAtStopIsClean(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, pgEcho("SELECT 1"))})
	pgClient(t, p)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestDrainFailureIsInconclusive(t *testing.T) {
	defer func(f func(*net.TCPListener) (int, error)) { drain = f }(drain)
	drain = func(*net.TCPListener) (int, error) { return 0, errors.New("injected") }
	p := start(t, Config{Engine: Postgres, Upstream: "127.0.0.1:1"})
	if err := p.Stop(); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("%v", err)
	}
}

func TestConnectionQueuedAtStopIsInconclusive(t *testing.T) {
	defer func(f func(*net.TCPListener) (int, error)) { drain = f }(drain)
	drain = func(*net.TCPListener) (int, error) { return 2, nil }
	p := start(t, Config{Engine: Postgres, Upstream: "127.0.0.1:1"})
	if err := p.Stop(); err == nil || !strings.Contains(err.Error(), "not proxied") {
		t.Fatalf("%v", err)
	}
}

func TestWitnessFile(t *testing.T) {
	var out bytes.Buffer
	p := start(t, Config{Engine: Postgres, Upstream: upstream(t, pgEcho("INSERT 0 1")), Output: &out})
	c, r := pgClient(t, p)
	query(t, c, r, "INSERT INTO users VALUES (1)")
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	l, err := witness.ReadLog(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if err := l.Health(); err != nil {
		t.Fatal(err)
	}
	if v, _ := harness.NoRow(l, traceID, "users"); v != harness.Fail {
		t.Fatalf("got %v", v)
	}
	harness.RequireNoRow(t, l, traceID, "orders")
}

// A capture fault reaches the file, so a reader in another process sees it.
func TestWitnessFileCarriesFaults(t *testing.T) {
	var out bytes.Buffer
	p := start(t, Config{Engine: Postgres, Upstream: "127.0.0.1:1", Output: &out})
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.Read(make([]byte, 1))
	p.Stop()
	l, err := witness.ReadLog(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := harness.NoRow(l, traceID, "users"); v != harness.Inconclusive {
		t.Fatalf("got %v", v)
	}
}

type limitWriter struct {
	left int
	out  bytes.Buffer
}

func (w *limitWriter) Write(b []byte) (int, error) {
	if w.left == 0 {
		return 0, errors.New("disk full")
	}
	w.left--
	return w.out.Write(b)
}

func TestWitnessFileWriteFailureIsInconclusive(t *testing.T) {
	for _, left := range []int{1, 2} { // the row line fails; the stop record fails
		p := start(t, Config{Engine: Postgres, Upstream: upstream(t, pgEcho("INSERT 0 1")), Output: &limitWriter{left: left}})
		c, r := pgClient(t, p)
		query(t, c, r, "INSERT INTO users VALUES (1)")
		if err := p.Stop(); err == nil || !strings.Contains(err.Error(), "witness file") {
			t.Fatalf("left %d: %v", left, err)
		}
	}
}

func TestCoverageSaysWhatItMayMiss(t *testing.T) {
	p := start(t, Config{Engine: Postgres, Upstream: "127.0.0.1:1"})
	if got := strings.Join(p.Coverage().Missed, "\n"); !strings.Contains(got, "not stopped") || !strings.Contains(got, "trigger") {
		t.Fatalf("%s", got)
	}
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.Read(make([]byte, 1))
	p.Stop()
	cov := p.Coverage()
	if len(cov.Faults) != 1 || !strings.Contains(strings.Join(cov.Missed, "\n"), "capture faults") {
		t.Fatalf("%+v", cov)
	}
}

func TestMySQLEngineThroughTheProxy(t *testing.T) {
	p := start(t, Config{Engine: MySQL, Upstream: upstream(t, func(c net.Conn, r *bufio.Reader) {
		c.Write(myGreeting(capProtocol41))
		for i := 0; i < 2; i++ {
			if _, err := readPacket(r); err != nil {
				return
			}
			c.Write(myOK(byte(2-i), byte(i), stAutocommit, 0))
		}
		io.Copy(io.Discard, r)
	})})
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	readPacket(r)
	c.Write(myResponse(capProtocol41))
	readPacket(r)
	c.Write(myQuery("INSERT INTO users VALUES (1)"))
	readPacket(r)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := p.Committed(traceID); len(got) != 1 || got[0].Engine != "mysql" {
		t.Fatalf("%+v", got)
	}
}
