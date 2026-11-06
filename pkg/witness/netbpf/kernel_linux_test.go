//go:build linux && (amd64 || arm64)

//subpoena:impl_derived

// The real programs in the real kernel. These tests need root (or CAP_BPF and
// CAP_PERFMON), BTF and a writable cgroup v2 hierarchy; they skip without them,
// unless SUBPOENA_EBPF_REQUIRE=1 (make test-ebpf) turns the skip into a
// failure. make test-ebpf runs them in a privileged container.
package netbpf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sprigworks/subpoena/pkg/cgroup"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SUBPOENA_EBPF_REQUIRE") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// sessionGroup makes a real session cgroup for tid under a fresh root.
func sessionGroup(t *testing.T, tid string) (*cgroup.Group, string) {
	t.Helper()
	parent := os.Getenv("SUBPOENA_CGROUP_REAL_ROOT")
	if parent == "" {
		parent = "/sys/fs/cgroup"
	}
	root := fmt.Sprintf("%s/subpoena-netbpf-%d", parent, os.Getpid())
	g, err := (&cgroup.Manager{Root: root}).Create(tid)
	if err != nil || !g.Real() {
		skipOrFail(t, "no writable cgroup v2 hierarchy at %s: %v", parent, err)
	}
	t.Cleanup(func() {
		for i := 0; i < 50 && g.Remove() != nil; i++ {
			time.Sleep(20 * time.Millisecond)
		}
		os.Remove(root)
	})
	return g, root
}

func start(t *testing.T, cfg Config) *Witness {
	t.Helper()
	w := New(cfg)
	if err := w.Start(); err != nil {
		skipOrFail(t, "cannot load the eBPF programs: %v", err)
	}
	t.Cleanup(func() { w.Stop() })
	return w
}

// The helper process: re-executed test binary that dials as told and exits.
// NETBPF_HELPER is "<op> <network> <addr>", op "connect" or "sendto".
func TestMain(m *testing.M) {
	if spec := os.Getenv("NETBPF_HELPER"); spec != "" {
		os.Exit(helper(spec))
	}
	os.Exit(m.Run())
}

func helper(spec string) int {
	f := strings.Fields(spec)
	switch f[0] {
	case "connect":
		c, err := net.DialTimeout(f[1], f[2], time.Second)
		if err != nil {
			// A refused connect is still an attempt; the witness must see it.
			fmt.Fprintln(os.Stderr, err)
			return 0
		}
		c.Close()
	case "sendto":
		c, err := net.ListenPacket(f[1], ":0")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer c.Close()
		to, err := net.ResolveUDPAddr(f[1], f[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := c.WriteTo([]byte("x"), to); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "udpsend": // a connected UDP socket: udpsend <addr> <count>
		c, err := net.Dial("udp4", f[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer c.Close()
		n, _ := strconv.Atoi(f[2])
		for i := 0; i < n; i++ {
			c.Write([]byte("x")) // a refused datagram still left
		}
	case "unixsend":
		c, err := net.Dial("unixgram", f[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer c.Close()
		if _, err := c.Write([]byte("x")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "broker":
		if err := broker(f[1], f[2], f[3], f[4] == "leak"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	default:
		return 2
	}
	return 0
}

const message = "publish:topic:payload"

// broker is a broker's shape in a process of its own: subscribers A and B
// connect, then a publisher. A byte from the publisher is a publish: the broker
// acks the publisher, writes the message to A (and with leak, to B) on the
// sockets it accepted, and hangs up. It writes the listener's port to stdout.
func broker(network, addr, how string, leak bool) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	var conns [3]*net.TCPConn
	for i := range conns {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		defer c.Close()
		conns[i] = c.(*net.TCPConn)
	}
	a, b, pub := conns[0], conns[1], conns[2]
	if _, err := pub.Read(make([]byte, 1)); err != nil {
		return err
	}
	if _, err := pub.Write([]byte("ack")); err != nil {
		return err
	}
	if err := deliver(a, how); err != nil {
		return err
	}
	if leak {
		return deliver(b, how)
	}
	return nil
}

// sendOn runs send on c's descriptor, waiting out EAGAIN.
func sendOn(c *net.TCPConn, send func(fd int) error) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	if err := rc.Write(func(fd uintptr) bool {
		sendErr = send(int(fd))
		return sendErr != syscall.EAGAIN
	}); err != nil {
		return err
	}
	return sendErr
}

// deliver writes message by one of the kernel's ways onto a socket.
func deliver(c *net.TCPConn, how string) error {
	switch how {
	case "write":
		_, err := c.Write([]byte(message))
		return err
	case "writev":
		b := net.Buffers{[]byte(message[:7]), []byte(message[7:])}
		_, err := b.WriteTo(c)
		return err
	case "sendmsg":
		return sendOn(c, func(fd int) error {
			_, err := syscall.SendmsgN(fd, []byte(message), nil, nil, 0)
			return err
		})
	case "sendfile":
		f, err := os.CreateTemp("", "netbpf-sendfile")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if _, err := f.WriteString(message); err != nil {
			return err
		}
		off := int64(0) // the syscall itself: Go's ReadFrom may fall back to write
		return sendOn(c, func(fd int) error {
			_, err := syscall.Sendfile(fd, int(f.Fd()), &off, len(message))
			return err
		})
	}
	return fmt.Errorf("no way %q", how)
}

func dial(t *testing.T, g *cgroup.Group, spec string) int {
	t.Helper()
	cmd, placeErr, err := g.Start(func() *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=^$")
		c.Env = append(os.Environ(), "NETBPF_HELPER="+spec)
		c.Stderr = os.Stderr
		return c
	})
	if err != nil || placeErr != nil {
		t.Fatalf("start helper %q: err=%v placeErr=%v", spec, err, placeErr)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper %q: %v", spec, err)
	}
	return cmd.Process.Pid
}

func find(events []witness.NetworkEvent, op witness.Op, proto string, dest netip.AddrPort) *witness.NetworkEvent {
	for i, e := range events {
		if e.Op == op && e.Protocol == proto && e.Dest == dest {
			return &events[i]
		}
	}
	return nil
}

// The kernel reports, by session cgroup: a TCP connect that succeeds, one that
// is refused, an unconnected UDP send, and an IPv6 connect; with the cgroup ID
// pkg/cgroup computes. Another trace sees none of it, and the test process's
// own dial (outside any session) is not attributed.
func TestKernelAttributesDialsBySessionCgroup(t *testing.T) {
	g, root := sessionGroup(t, tidA)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := netip.MustParseAddrPort(ln.Addr().String())
	// A port nothing listens on: bind, note it, close.
	l2, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := netip.MustParseAddrPort(l2.Addr().String())
	l2.Close()
	udp := netip.MustParseAddrPort("127.0.0.1:9") // discard; nothing needs to listen
	v6 := netip.MustParseAddrPort("[::1]:9")
	// Some containers have no IPv6 at all; then there is no v6 connect to see.
	hasV6 := false
	if l6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		hasV6 = true
		l6.Close()
	}

	w := start(t, Config{CgroupRoot: root})
	pid := dial(t, g, "connect tcp4 "+open.String())
	dial(t, g, "connect tcp4 "+refused.String())
	dial(t, g, "sendto udp4 "+udp.String())
	if hasV6 {
		dial(t, g, "connect tcp6 "+v6.String())
	}
	if c, err := net.Dial("tcp4", open.String()); err == nil { // this process: no session
		c.Close()
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := w.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}

	id, err := g.ID()
	if err != nil {
		t.Fatal(err)
	}
	got := w.Dialed(tidA)
	type want struct {
		op    witness.Op
		proto string
		dest  netip.AddrPort
	}
	wants := []want{
		{witness.OpConnect, "tcp", open},
		{witness.OpConnect, "tcp", refused},
		{witness.OpSendmsg, "udp", udp},
	}
	if hasV6 {
		wants = append(wants, want{witness.OpConnect, "tcp", v6})
	} else {
		t.Log("no IPv6 loopback here; the IPv6 connect was not exercised")
	}
	for _, c := range wants {
		e := find(got, c.op, c.proto, c.dest)
		if e == nil {
			t.Errorf("missing %s %s %s in %+v", c.op, c.proto, c.dest, got)
			continue
		}
		if e.Attribution != witness.ByCgroup || e.TraceID != tidA || e.CgroupID != id {
			t.Errorf("not attributed by session cgroup %d: %+v", id, e)
		}
		if !strings.HasSuffix(e.Cgroup, cgroup.RootBase(root)+"/"+tidA) {
			t.Errorf("cgroup path %q does not end in the session", e.Cgroup)
		}
	}
	if e := find(got, witness.OpConnect, "tcp", open); e != nil && e.PID != pid {
		t.Errorf("pid %d, want the helper %d", e.PID, pid)
	}
	for _, e := range got {
		if e.PID == os.Getpid() {
			t.Errorf("the test process's own dial was attributed: %+v", e)
		}
	}
	if other := w.Dialed(tidB); len(other) != 0 {
		t.Errorf("another trace sees this session's dials: %+v", other)
	}
}

// Stop delivers everything already in the ring buffer.
func TestStopDrainsTheRingBuffer(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	w := start(t, Config{CgroupRoot: root})
	const n = 20
	for i := 0; i < n; i++ {
		dial(t, g, "sendto udp4 127.0.0.1:9")
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := len(w.Dialed(tidB)); got != n {
		t.Fatalf("saw %d of %d sends", got, n)
	}
}

// Exercise the real per-CPU map ABI and Stop's final read on a privileged host.
func TestKernelLossCounterInvalidatesCapture(t *testing.T) {
	w := start(t, Config{})
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	counts := make([]uint64, cpus)
	counts[0] = 3
	if cpus > 1 {
		counts[cpus-1] = 4
	}
	if err := w.k.objs.Lost.Put(uint32(0), counts); err != nil {
		t.Fatal(err)
	}
	if err := w.Stop(); err == nil {
		t.Fatal("kernel loss must fail Stop")
	}
	if err := w.Health(); err == nil {
		t.Fatal("kernel loss must persist in Health")
	}
}

// startBroker runs the broker helper in the session cgroup and connects two
// subscribers, from outside it, and returns once both are in.
type brokerRun struct {
	cmd          *exec.Cmd
	port         int
	host         string
	subA, subB   net.Conn
	peerA, peerB netip.AddrPort
}

func startBroker(t *testing.T, g *cgroup.Group, network, listen, host, how, leak string) *brokerRun {
	t.Helper()
	var out io.ReadCloser
	cmd, placeErr, err := g.Start(func() *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=^$")
		c.Env = append(os.Environ(), fmt.Sprintf("NETBPF_HELPER=broker %s %s %s %s", network, listen, how, leak))
		c.Stderr = os.Stderr
		var perr error
		if out, perr = c.StdoutPipe(); perr != nil {
			t.Fatal(perr)
		}
		return c
	})
	if err != nil || placeErr != nil {
		t.Fatalf("start broker: err=%v placeErr=%v", err, placeErr)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("broker port: %v", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	b := &brokerRun{cmd: cmd, port: port, host: host}
	b.subA, b.peerA = b.connect(t)
	b.subB, b.peerB = b.connect(t)
	return b
}

func (b *brokerRun) connect(t *testing.T) (net.Conn, netip.AddrPort) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort(b.host, strconv.Itoa(b.port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, netip.MustParseAddrPort(c.LocalAddr().String())
}

// publish connects the publisher, publishes, and waits for the ack. It returns
// the publisher's address as the broker sees it.
func (b *brokerRun) publish(t *testing.T) netip.AddrPort {
	t.Helper()
	p, peer := b.connect(t)
	if _, err := p.Write([]byte("p")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(p, make([]byte, 3)); err != nil {
		t.Fatalf("no ack: %v", err)
	}
	return peer
}

func readAll(t *testing.T, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(got)
}

func toPeer(events []witness.DeliveryEvent, peer netip.AddrPort) []witness.DeliveryEvent {
	var out []witness.DeliveryEvent
	for _, e := range events {
		if e.Peer == peer {
			out = append(out, e)
		}
	}
	return out
}

// The case this witness exists for. A broker in a session cgroup writes to one
// subscriber on a socket it accepted before the witness even started. The
// witness sees that send, with the subscriber as the peer; it tells the
// publisher's ack apart; and "nothing went to the other subscriber" is a Pass
// the real subscriber's socket agrees with. No dial is involved, so Dialed sees
// none of it. Each way a process can write to a socket is run.
func TestKernelSeesDeliveryOnAnAcceptedSocket(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		network, listen, host, how string
		exactBytes                 bool
	}{
		{"write", "tcp4", "127.0.0.1:0", "127.0.0.1", "write", true},
		{"writev", "tcp4", "127.0.0.1:0", "127.0.0.1", "writev", true},
		{"sendmsg", "tcp4", "127.0.0.1:0", "127.0.0.1", "sendmsg", true},
		{"sendfile", "tcp4", "127.0.0.1:0", "127.0.0.1", "sendfile", false},
		{"dual-stack listener, IPv4 client", "tcp", ":0", "127.0.0.1", "write", true},
		{"ipv6", "tcp6", "[::1]:0", "::1", "write", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.network == "tcp6" {
				l6, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("no IPv6 loopback here: %v", err)
				}
				l6.Close()
			}
			g, root := sessionGroup(t, tidA)
			b := startBroker(t, g, tc.network, tc.listen, tc.host, tc.how, "clean")

			// Started after the subscribers are in: their handshakes are not in
			// the window, as a test of a real broker's SUBACK would want.
			var mu sync.Mutex
			var strays []Event
			w := start(t, Config{CgroupRoot: root, OnEvent: func(e Event) {
				if e.Op == witness.OpDeliver && e.Attribution == "" {
					mu.Lock()
					strays = append(strays, e)
					mu.Unlock()
				}
			}})
			pub := b.publish(t)
			if got := readAll(t, b.subA); got != message {
				t.Fatalf("subscriber A read %q", got)
			}
			if got := readAll(t, b.subB); got != "" {
				t.Fatalf("subscriber B read %q", got)
			}
			if err := w.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			if err := w.Health(); err != nil {
				t.Fatalf("Health: %v", err)
			}

			id, err := g.ID()
			if err != nil {
				t.Fatal(err)
			}
			got := w.Delivered(tidA)
			toA := toPeer(got, b.peerA)
			if len(toA) == 0 {
				t.Fatalf("no delivery to subscriber A %v in %+v", b.peerA, got)
			}
			var total uint64
			for _, e := range toA {
				total += e.Bytes
				if e.Op != witness.OpDeliver || e.Protocol != "tcp" || e.PID != b.cmd.Process.Pid ||
					e.Attribution != witness.ByCgroup || e.TraceID != tidA || e.CgroupID != id || int(e.Local.Port()) != b.port {
					t.Errorf("delivery fields: %+v", e)
				}
				if !strings.HasSuffix(e.Cgroup, cgroup.RootBase(root)+"/"+tidA) {
					t.Errorf("cgroup path %q does not end in the session", e.Cgroup)
				}
			}
			if tc.exactBytes && total != uint64(len(message)) {
				t.Errorf("%d bytes to A, want %d: %+v", total, len(message), toA)
			}
			if acks := toPeer(got, pub); len(acks) != 1 || acks[0].Bytes != 3 {
				t.Errorf("the ack to the publisher %v: %+v", pub, acks)
			}
			if n := len(toA) + 1; n != len(got) {
				t.Errorf("%d sends, want only A's and the ack: %+v", len(got), got)
			}
			if v, err := harness.NoDelivery(w, tidA, harness.DeliveryTo(b.peerB)); v != harness.Pass {
				t.Errorf("nothing went to B: %v, %v", v, err)
			}
			if v, _ := harness.NoDelivery(w, tidA, harness.DeliveryTo(b.peerA)); v != harness.Fail {
				t.Errorf("A was delivered to: %v", v)
			}
			if v, _ := harness.NoDelivery(w, tidB, nil); v != harness.Pass {
				t.Errorf("another trace sees this session's sends: %v", v)
			}
			if d := w.Dialed(tidA); len(d) != 0 {
				t.Errorf("no dial happened here: %+v", d)
			}
			// The subscribers and the publisher are this process, outside any
			// session: the kernel filter keeps their sends out.
			if len(strays) != 0 {
				t.Errorf("sends from outside any session reached user space: %+v", strays)
			}
		})
	}
}

// The mutant in the trial: the broker's guard forced open, so the denied
// subscriber gets the message. The socket says so, and so must the witness.
func TestKernelFailsWhenTheDeniedSubscriberIsDeliveredTo(t *testing.T) {
	g, root := sessionGroup(t, tidA)
	b := startBroker(t, g, "tcp4", "127.0.0.1:0", "127.0.0.1", "write", "leak")
	w := start(t, Config{CgroupRoot: root})
	b.publish(t)
	if got := readAll(t, b.subB); got != message {
		t.Fatalf("subscriber B read %q", got)
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	v, err := harness.NoDelivery(w, tidA, harness.DeliveryTo(b.peerB))
	if v != harness.Fail {
		t.Fatalf("got %v, %v", v, err)
	}
	if !strings.Contains(err.Error(), b.peerB.String()) {
		t.Fatalf("the failure must name the peer: %v", err)
	}
}

// A send on a connected UDP socket has a peer but no name; one with a name is
// delivery to that name, the same event Dialed reports.
func TestKernelSeesUDPDelivery(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	to := netip.MustParseAddrPort(pc.LocalAddr().String())

	w := start(t, Config{CgroupRoot: root})
	dial(t, g, "udpsend "+to.String()+" 1")
	dial(t, g, "sendto udp4 "+to.String())
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var connected, named int
	for _, e := range toPeer(w.Delivered(tidB), to) {
		if e.Protocol != "udp" || e.Bytes != 1 {
			t.Errorf("fields: %+v", e)
		}
		switch e.Op {
		case witness.OpDeliver:
			connected++
		case witness.OpSendmsg:
			named++
		}
	}
	if connected != 1 || named != 1 {
		t.Fatalf("connected %d, named %d, want 1 and 1: %+v", connected, named, w.Delivered(tidB))
	}
	if d := w.Dialed(tidB); len(d) != 2 { // the connect, and the named send
		t.Errorf("Dialed = %+v", d)
	}
}

// A cgroup below the session is still the session, as Go attributes it, so the
// kernel filter must let it through.
func TestKernelFilterKeepsAChildOfTheSession(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	child := filepath.Join(g.Dir(), "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		skipOrFail(t, "no child cgroup: %v", err)
	}
	defer func() {
		for i := 0; i < 50 && os.Remove(child) != nil; i++ {
			time.Sleep(20 * time.Millisecond)
		}
	}()
	dir, err := os.Open(child)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	w := start(t, Config{CgroupRoot: root})
	c := exec.Command(os.Args[0], "-test.run=^$")
	c.Env = append(os.Environ(), "NETBPF_HELPER=udpsend "+pc.LocalAddr().String()+" 1")
	c.Stderr = os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := w.Delivered(tidB); len(got) != 1 || !strings.HasSuffix(got[0].Cgroup, tidB+"/child") {
		t.Fatalf("Delivered = %+v", got)
	}
}

// A send on a socket that is not inet has no peer to report. It is counted, so
// a capture says what it did not look at.
func TestKernelCountsSendsItCannotAddress(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	sock := filepath.Join(t.TempDir(), "s")
	uc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	w := start(t, Config{CgroupRoot: root})
	dial(t, g, "unixsend "+sock)
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := w.Delivered(tidB); len(got) != 0 {
		t.Errorf("Delivered = %+v", got)
	}
	if c := w.DeliveryCoverage(); c.OtherFamilySends == 0 {
		t.Errorf("coverage = %+v", c)
	}
}

// Stop delivers every send already in the ring buffer.
func TestStopDrainsDeliveries(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	w := start(t, Config{CgroupRoot: root})
	const n = 2000
	dial(t, g, fmt.Sprintf("udpsend %s %d", pc.LocalAddr(), n))
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := len(w.Delivered(tidB)); got != n {
		t.Fatalf("saw %d of %d sends", got, n)
	}
}

// A real overflow, not a written counter: the reader is held while a session
// sends more than the ring buffer holds, so reservations really fail. Stop and
// Health say so, a sighting is still a Fail, and no absence passes.
func TestKernelRingOverflowFailsHealth(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	to := netip.MustParseAddrPort(pc.LocalAddr().String())

	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	w := start(t, Config{CgroupRoot: root, OnEvent: func(Event) { <-release }})
	dial(t, g, fmt.Sprintf("udpsend %s 20000", to))
	free()
	err = w.Stop()
	if err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("Stop = %v", err)
	}
	if w.Health() == nil {
		t.Fatal("kernel loss must persist in Health")
	}
	if c := w.DeliveryCoverage(); c.Lost == 0 {
		t.Fatalf("coverage = %+v", c)
	}
	nobody := netip.MustParseAddrPort("192.0.2.1:1")
	if v, _ := harness.NoDelivery(w, tidB, harness.DeliveryTo(nobody)); v != harness.Inconclusive {
		t.Fatalf("absence over a lossy capture: %v", v)
	}
	if v, _ := harness.NoDelivery(w, tidB, harness.DeliveryTo(to)); v != harness.Fail {
		t.Fatalf("what was seen still counts: %v", v)
	}
}

// A hook that will not attach, on real programs: no capture, and Health says why.
func TestKernelFailedAttachFailsHealth(t *testing.T) {
	// Only the loaded case tells this from a failed load.
	probe := New(Config{})
	if err := probe.Start(); err != nil {
		skipOrFail(t, "cannot load the eBPF programs: %v", err)
	}
	probe.Stop()
	failAttach(t, 3)
	w := New(Config{})
	err := w.Start()
	if err == nil || !strings.Contains(err.Error(), "attach handle_deliver") {
		t.Fatalf("Start = %v", err)
	}
	if h := w.Health(); h == nil || !strings.Contains(h.Error(), "attach handle_deliver") {
		t.Fatalf("Health = %v", h)
	}
	if v, _ := harness.NoDelivery(w, tidA, nil); v != harness.Inconclusive {
		t.Fatalf("no capture, no absence: %v", v)
	}
}
