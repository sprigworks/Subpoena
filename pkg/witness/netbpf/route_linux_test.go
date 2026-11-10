//go:build linux && (amd64 || arm64)

//subpoena:impl_derived

// Sends that go somewhere other than the peer or name they carry, in the real
// kernel: a source route, and a broadcast. See kernel_linux_test.go for what these
// tests need.
package netbpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

const (
	ipRetopts        = 7   // IP_RETOPTS
	ipv6Rthdr        = 57  // IPV6_RTHDR
	ipv6Flowinfo     = 11  // IPV6_FLOWINFO
	ipv6FlowlabelMgr = 32  // IPV6_FLOWLABEL_MGR
	ipv6FlowinfoSend = 33  // IPV6_FLOWINFO_SEND
	optLSRR          = 131 // IPOPT_LSRR
)

// lsrr is IP options routing a send through hop first.
func lsrr(hop netip.Addr) []byte {
	a := hop.As4()
	return append([]byte{optLSRR, 7, 4}, a[:]...)
}

func cmsg(level, typ int, data []byte) []byte {
	b := make([]byte, syscall.CmsgSpace(len(data)))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = int32(level), int32(typ)
	h.SetLen(syscall.CmsgLen(len(data)))
	copy(b[syscall.CmsgLen(0):], data)
	return b
}

// routedSend is the helper's "route" and "bcast" forms:
//
//	route <how> <hop> <to>   how: sticky, connected, retopts, tos, none
//	bcast <named|connected|cleared> <to>
func routedSend(f []string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	to := netip.MustParseAddrPort(f[len(f)-1])
	sa := &syscall.SockaddrInet4{Port: int(to.Port()), Addr: to.Addr().As4()}
	if f[0] == "bcast" {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
			return err
		}
		if f[1] != "named" {
			if err := syscall.Connect(fd, sa); err != nil {
				return err
			}
			if f[1] == "cleared" {
				if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0); err != nil {
					return err
				}
			}
			_, err := syscall.Write(fd, []byte("x"))
			return err
		}
		return syscall.Sendto(fd, []byte("x"), 0, sa)
	}
	opts := lsrr(netip.MustParseAddr(f[2]))
	switch f[1] {
	case "sticky", "connected":
		if err := syscall.SetsockoptString(fd, syscall.IPPROTO_IP, syscall.IP_OPTIONS, string(opts)); err != nil {
			return fmt.Errorf("IP_OPTIONS: %w", err)
		}
	}
	switch f[1] {
	case "connected":
		if err := syscall.Connect(fd, sa); err != nil {
			return err
		}
		_, err := syscall.Write(fd, []byte("x"))
		return err
	case "retopts":
		_, err := syscall.SendmsgN(fd, []byte("x"), cmsg(syscall.IPPROTO_IP, ipRetopts, opts), sa, 0)
		return err
	case "tos":
		_, err := syscall.SendmsgN(fd, []byte("x"), cmsg(syscall.IPPROTO_IP, syscall.IP_TOS, []byte{0}), sa, 0)
		return err
	}
	return syscall.Sendto(fd, []byte("x"), 0, sa)
}

// A source route takes a send to its first hop, whatever peer the send carries,
// and no privilege is needed to set one. The hop must be charged, or a rule on it
// passes while the packet goes there.
func TestKernelReportsASourceRoute(t *testing.T) {
	hop, to := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddrPort("127.0.0.3:41900")
	rule := netip.AddrPortFrom(hop, to.Port())
	for _, tc := range []struct {
		how     string
		want    harness.Verdict
		hop     bool // the first hop is reported
		unknown bool // an unknown peer is reported instead
	}{
		{how: "sticky", want: harness.Fail, hop: true},
		{how: "connected", want: harness.Fail, hop: true},
		{how: "retopts", want: harness.Fail, unknown: true},
		{how: "tos", want: harness.Pass},
		{how: "none", want: harness.Pass},
	} {
		t.Run(tc.how, func(t *testing.T) {
			g, root := sessionGroup(t, tidB)
			w := start(t, Config{CgroupRoot: root})
			dial(t, g, "route "+tc.how+" "+hop.String()+" "+to.String())
			if err := w.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			got := w.Delivered(tidB)
			if len(toPeer(got, to)) == 0 {
				t.Fatalf("the send's own peer is gone: %+v", got)
			}
			saw := slices.ContainsFunc(got, func(e witness.DeliveryEvent) bool { return e.Peer == netip.AddrPortFrom(hop, 0) })
			unknown := slices.ContainsFunc(got, witness.DeliveryEvent.PeerUnknown)
			if saw != tc.hop || unknown != tc.unknown {
				t.Fatalf("first hop %v (want %v), unknown peer %v (want %v): %+v", saw, tc.hop, unknown, tc.unknown, got)
			}
			if v, err := harness.NoDelivery(w, tidB, harness.DeliveryTo(rule)); v != tc.want {
				t.Fatalf("NoDelivery(%v) = %v (%v), want %v", rule, v, err, tc.want)
			}
		})
	}
}

// IPv6's source route: an unread address, on the socket or with the send.
func TestKernelReportsAnIPv6RoutingHeader(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	w := start(t, Config{CgroupRoot: root})
	dial(t, g, "rthdr [::1]:41901")
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := w.Delivered(tidB); !slices.ContainsFunc(got, witness.DeliveryEvent.PeerUnknown) {
		t.Fatalf("no unknown peer in %+v", got)
	}
}

// rthdrSend sets an IPv6 segment routing header, the routing header an unprivileged
// socket may set, and sends.
func rthdrSend(to string) error {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	seg := netip.MustParseAddr("::1").As16()
	srh := append([]byte{0, 2, 4, 0, 0, 0, 0, 0}, seg[:]...)
	if err := syscall.SetsockoptString(fd, syscall.IPPROTO_IPV6, ipv6Rthdr, string(srh)); err != nil {
		return fmt.Errorf("IPV6_RTHDR: %w", err)
	}
	a := netip.MustParseAddrPort(to)
	return syscall.Sendto(fd, []byte("x"), 0, &syscall.SockaddrInet6{Port: int(a.Port()), Addr: a.Addr().As16()})
}

// flowLabel is the helper's "flowlabel" form:
//
//	flowlabel <how> <hop> <to>   how: flowinfo, control, connected, plain, noroute
//
// It takes a label holding a routing header to hop, as an unprivileged socket may,
// and names the label in a send to to. plain sends with no label named, on a socket
// holding it; noroute holds a label with no options.
func flowLabel(how, hop, to string) error {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	// An exclusive label outlives its socket by its linger, so each run needs its own.
	label := 0x00010000 | uint32(os.Getpid())&0xffff
	dst := netip.MustParseAddrPort(to)
	req := make([]byte, 32) // struct in6_flowlabel_req
	a := dst.Addr().As16()
	copy(req, a[:])
	binary.BigEndian.PutUint32(req[16:], label)
	req[21] = 1                                // IPV6_FL_S_EXCL
	binary.NativeEndian.PutUint16(req[22:], 1) // IPV6_FL_F_CREATE
	binary.NativeEndian.PutUint16(req[24:], 60)
	binary.NativeEndian.PutUint16(req[26:], 60)
	if how != "noroute" {
		h := netip.MustParseAddr(hop).As16()
		req = append(req, cmsg(syscall.IPPROTO_IPV6, ipv6Rthdr, append([]byte{0, 2, 2, 1, 0, 0, 0, 0}, h[:]...))...)
	}
	if err := syscall.SetsockoptString(fd, syscall.IPPROTO_IPV6, ipv6FlowlabelMgr, string(req)); err != nil {
		return fmt.Errorf("IPV6_FLOWLABEL_MGR: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, ipv6FlowinfoSend, 1); err != nil {
		return fmt.Errorf("IPV6_FLOWINFO_SEND: %w", err)
	}
	// sin6_flowinfo has no field in syscall.SockaddrInet6.
	sa := syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Addr: a}
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], dst.Port())
	if how != "plain" && how != "control" {
		binary.BigEndian.PutUint32((*[4]byte)(unsafe.Pointer(&sa.Flowinfo))[:], label)
	}
	b := []byte("x")
	switch how {
	case "connected":
		if _, _, e := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 {
			return fmt.Errorf("connect: %w", e)
		}
		_, err = syscall.Write(fd, b)
		return err
	case "control":
		var flow [4]byte
		binary.BigEndian.PutUint32(flow[:], label)
		_, err = syscall.SendmsgN(fd, b, cmsg(syscall.IPPROTO_IPV6, ipv6Flowinfo, flow[:]), &syscall.SockaddrInet6{Port: int(dst.Port()), Addr: a}, 0)
		return err
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 {
		return fmt.Errorf("sendto: %w", e)
	}
	return nil
}

// A flow label can hold its own routing header, which is on neither the send nor
// the socket's options. Every way of naming the label must give an unknown peer.
func TestKernelReportsARoutingHeaderOnAFlowLabel(t *testing.T) {
	for _, tc := range []struct {
		how     string
		unknown bool
	}{
		{"flowinfo", true},
		{"control", true},
		{"connected", true},
		{"plain", true}, // over-reports: the socket could have named it
		{"noroute", false},
	} {
		t.Run(tc.how, func(t *testing.T) {
			g, root := sessionGroup(t, tidB)
			w := start(t, Config{CgroupRoot: root})
			dial(t, g, "flowlabel "+tc.how+" ::1 [::1]:41940")
			if err := w.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			got := w.Delivered(tidB)
			if len(got) == 0 {
				t.Fatal("no send seen")
			}
			if u := slices.ContainsFunc(got, witness.DeliveryEvent.PeerUnknown); u != tc.unknown {
				t.Fatalf("unknown peer %v, want %v: %+v", u, tc.unknown, got)
			}
			want := harness.Pass
			if tc.unknown {
				want = harness.Fail
			}
			rule := netip.MustParseAddrPort("[fd00:77::2]:41940") // no send names it
			if v, err := harness.NoDelivery(w, tidB, harness.DeliveryTo(rule)); v != want {
				t.Fatalf("NoDelivery(%v) = %v (%v), want %v", rule, v, err, want)
			}
		})
	}
}

// A subnet's broadcast address looks like any other, so the socket option must
// reach the event, and a subscriber on the port must not read as Pass.
func TestKernelReportsABroadcastSend(t *testing.T) {
	to := netip.MustParseAddrPort("127.255.255.255:41912")
	sub := netip.MustParseAddrPort("127.0.0.1:41912")
	other := netip.MustParseAddrPort("127.0.0.1:41999")
	for _, how := range []string{"named", "connected", "cleared"} {
		t.Run(how, func(t *testing.T) {
			g, root := sessionGroup(t, tidB)
			w := start(t, Config{CgroupRoot: root})
			dial(t, g, "bcast "+how+" "+to.String())
			if err := w.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			got := toPeer(w.Delivered(tidB), to)
			if len(got) != 1 || got[0].Broadcast != (how != "cleared") || got[0].BroadcastRoute != (how != "named") || !got[0].Fanout() {
				t.Fatalf("Delivered = %+v", w.Delivered(tidB))
			}
			if v, err := harness.NoDelivery(w, tidB, harness.DeliveryTo(sub)); v != harness.Inconclusive {
				t.Fatalf("the subscriber: %v (%v), want Inconclusive", v, err)
			}
			if v, err := harness.NoDelivery(w, tidB, harness.DeliveryTo(other)); v != harness.Pass {
				t.Fatalf("another port: %v (%v), want Pass", v, err)
			}
			if v, err := harness.NoDelivery(w, tidB, harness.DeliveryTo(to)); v != harness.Fail {
				t.Fatalf("the address itself: %v (%v), want Fail", v, err)
			}
		})
	}
	t.Run("no option", func(t *testing.T) {
		g, root := sessionGroup(t, tidB)
		w := start(t, Config{CgroupRoot: root})
		// Not through net: Go sets SO_BROADCAST on every socket it makes.
		dial(t, g, "route none 127.0.0.2 127.0.0.3:41912")
		if err := w.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if got := w.Delivered(tidB); len(got) != 1 || got[0].Broadcast {
			t.Fatalf("Delivered = %+v", got)
		}
	})
}

// Clearing the option on a connected socket is a way a hostile sender may choose:
// the broadcast still goes out, and a subscriber gets it. Only the route shows that.
func TestKernelASubscriberHearsAClearedBroadcast(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:41913")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	g, root := sessionGroup(t, tidB)
	w := start(t, Config{CgroupRoot: root})
	dial(t, g, "bcast cleared 127.255.255.255:41913")
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatalf("the fixture must really reach the subscriber: %v", err)
	}
	sub := netip.MustParseAddrPort("127.0.0.1:41913")
	if v, err := harness.NoDelivery(w, tidB, harness.DeliveryTo(sub)); v != harness.Inconclusive {
		t.Fatalf("the subscriber: %v (%v), want Inconclusive", v, err)
	}
}

// Under the session root means the root, not any cgroup with its last name.
func TestKernelACgroupElsewhereWithTheRootsNameIsNotUnderIt(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()
	_, root := sessionGroup(t, tidB)
	leaf := nest(t, filepath.Dir(root), "elsewhere-"+strconv.Itoa(os.Getpid()), filepath.Base(root))

	w := start(t, Config{CgroupRoot: root})
	sendFrom(t, leaf, addr)
	if err := w.Stop(); err != nil {
		t.Fatalf("a send from elsewhere: Stop = %v", err)
	}
	if n := w.DeliveryCoverage().Unattributed; n != 0 {
		t.Fatalf("Unattributed = %d", n)
	}

	w = start(t, Config{CgroupRoot: root})
	sendFrom(t, root, addr)
	if err := w.Stop(); err == nil || !strings.Contains(err.Error(), "in no session") {
		t.Fatalf("a send from the root itself: Stop = %v", err)
	}
}
