//go:build linux && (amd64 || arm64)

//subpoena:impl_derived

// The real programs in the real kernel. These tests need root (or CAP_BPF and
// CAP_PERFMON), BTF and a writable cgroup v2 hierarchy; they skip without them,
// unless SUBPOENA_EBPF_REQUIRE=1 (make test-ebpf) turns the skip into a
// failure. make test-ebpf runs them in a privileged container.
package netbpf

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sprigworks/subpoena/pkg/cgroup"
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
	default:
		return 2
	}
	return 0
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
