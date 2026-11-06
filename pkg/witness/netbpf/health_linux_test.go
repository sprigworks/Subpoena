//go:build linux && (amd64 || arm64)

//subpoena:impl_derived
//subpoena:pure_logic

package netbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// scriptedReader injects shutdown and read failures without kernel privileges.
type scriptedReader struct {
	records  []ringbuf.Record
	readErr  error
	flushErr error
	end      chan struct{}
	once     sync.Once
}

func (r *scriptedReader) Read() (ringbuf.Record, error) {
	if len(r.records) > 0 {
		v := r.records[0]
		r.records = r.records[1:]
		return v, nil
	}
	<-r.end
	return ringbuf.Record{}, r.readErr
}
func (r *scriptedReader) Flush() error {
	if r.flushErr != nil {
		return r.flushErr
	}
	r.once.Do(func() { close(r.end) })
	return nil
}
func (r *scriptedReader) Close() error { r.once.Do(func() { close(r.end) }); return nil }

func TestCaptureHealthAccountsForShutdownLoss(t *testing.T) {
	flushErr := errors.New("flush failed")
	mapErr := errors.New("loss counter unavailable")
	for _, tc := range []struct {
		name                      string
		readErr, flushErr, mapErr error
		otherErr                  error
		lost                      uint64
		malformed                 bool
		want                      string
	}{
		{name: "drained", readErr: ringbuf.ErrFlushed},
		{name: "ring full", readErr: ringbuf.ErrFlushed, lost: 7, want: "lost 7 kernel event(s)"},
		{name: "flush failed", readErr: ringbuf.ErrClosed, flushErr: flushErr, want: "flush failed"},
		{name: "unexpected close", readErr: ringbuf.ErrClosed, want: "read:"},
		{name: "read failed", readErr: errors.New("reader failed"), want: "reader failed"},
		{name: "counter unreadable", readErr: ringbuf.ErrFlushed, mapErr: mapErr, want: "loss counter unavailable"},
		{name: "other-sends counter unreadable", readErr: ringbuf.ErrFlushed, otherErr: mapErr, want: "loss counter unavailable"},
		{name: "bad record", readErr: ringbuf.ErrFlushed, malformed: true, want: "short record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &scriptedReader{readErr: tc.readErr, flushErr: tc.flushErr, end: make(chan struct{})}
			if tc.malformed {
				r.records = []ringbuf.Record{{RawSample: []byte{1}}}
			}
			w := New(Config{})
			k := &kernel{rd: r, done: make(chan struct{}), lost: func() (uint64, error) { return tc.lost, tc.mapErr },
				other: func() (uint64, error) { return 0, tc.otherErr }}
			w.k = k
			go w.read(k)
			err := w.Stop()
			if tc.want == "" {
				if err != nil || w.Health() != nil {
					t.Fatalf("drained capture unhealthy: %v / %v", err, w.Health())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || w.Health() == nil {
				t.Fatalf("want %q; Stop=%v Health=%v", tc.want, err, w.Health())
			}
			if tc.flushErr != nil && !errors.Is(err, flushErr) {
				t.Fatal("lost Flush error")
			}
			if tc.mapErr != nil && !errors.Is(err, mapErr) {
				t.Fatal("lost map error")
			}
			if w.Stop() == nil {
				t.Fatal("second Stop erased capture failure")
			}
		})
	}
}

// Stop keeps what the kernel counted for the coverage report.
func TestStopRecordsCoverage(t *testing.T) {
	r := &scriptedReader{readErr: ringbuf.ErrFlushed, end: make(chan struct{})}
	w := New(Config{})
	k := &kernel{rd: r, done: make(chan struct{}), lost: func() (uint64, error) { return 2, nil },
		other: func() (uint64, error) { return 5, nil }}
	w.k = k
	go w.read(k)
	if w.Stop() == nil {
		t.Fatal("kernel loss must fail Stop")
	}
	if c := w.DeliveryCoverage(); c.Lost != 2 || c.OtherFamilySends != 5 {
		t.Fatalf("coverage = %+v", c)
	}
}

type closeCounter struct {
	link.Link
	closed *int
}

func (c closeCounter) Close() error { *c.closed++; return nil }

func failAttach(t *testing.T, failOn int) (attempts, closed *int) {
	t.Helper()
	attempts, closed = new(int), new(int)
	old := attach
	t.Cleanup(func() { attach = old })
	attach = func(*ebpf.Program) (link.Link, error) {
		*attempts++
		if *attempts == failOn {
			return nil, errors.New("attach refused")
		}
		return closeCounter{closed: closed}, nil
	}
	return attempts, closed
}

// One hook that does not attach is no capture: the error names it, and what
// did attach comes off again.
func TestAttachAllStopsAtTheFirstFailure(t *testing.T) {
	attempts, closed := failAttach(t, 3)
	k := &kernel{}
	err := k.attachAll((&kernel{}).hooks())
	if err == nil || !strings.Contains(err.Error(), "handle_deliver") || !strings.Contains(err.Error(), "attach refused") {
		t.Fatalf("attachAll = %v", err)
	}
	if *attempts != 3 || len(k.links) != 2 {
		t.Fatalf("attempts %d, links %d", *attempts, len(k.links))
	}
	k.close()
	if *closed != 2 {
		t.Fatalf("closed %d of the 2 attached", *closed)
	}
}

// With no privileges the load fails, and with them the attach is made to:
// either way the reason outlives Start, and a later Stop does not clear it.
func TestFailedStartStaysInHealth(t *testing.T) {
	failAttach(t, 1)
	w := New(Config{})
	err := w.Start()
	if err == nil {
		t.Fatal("Start must fail")
	}
	if h := w.Health(); h == nil || h.Error() != err.Error() {
		t.Fatalf("Health = %v, want the Start failure %v", h, err)
	}
	if s := w.Stop(); s == nil || w.Health() == nil {
		t.Fatalf("Stop = %v, Health = %v: a witness that never attached has seen nothing", s, w.Health())
	}
}

func TestSessionBaseMustBeMatchableInTheKernel(t *testing.T) {
	b, err := sessionBase("subpoena")
	if err != nil || string(b[:9]) != "subpoena\x00" || len(b) != nameLen {
		t.Fatalf("sessionBase = %q, %v", b, err)
	}
	if _, err := sessionBase(strings.Repeat("x", nameLen-1)); err != nil {
		t.Fatalf("the longest name the kernel reads whole: %v", err)
	}
	for _, bad := range []string{"", "/", ".", strings.Repeat("x", nameLen)} {
		if _, err := sessionBase(bad); err == nil {
			t.Errorf("sessionBase(%q) must fail: no cgroup element can equal it", bad)
		}
	}
	w := New(Config{CgroupRoot: "/sys/fs/cgroup/" + strings.Repeat("x", nameLen)})
	if err := w.Start(); err == nil {
		w.Stop()
		t.Fatal("Start must refuse a root the kernel filter can never match")
	}
	if w.Health() == nil {
		t.Fatal("Health must fail")
	}
}

func TestGeneratedObjectContract(t *testing.T) {
	spec, err := loadNet()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lost", "other_sends"} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.PerCPUArray || m.MaxEntries != 1 || m.KeySize != 4 || m.ValueSize != 8 {
			t.Fatalf("generated map %s = %+v", name, m)
		}
	}
	if v := spec.Variables["session_base"]; v == nil || v.Size() != nameLen {
		t.Fatalf("session_base = %+v, want %d bytes", v, nameLen)
	}
	for name, section := range map[string]string{
		"handle_connect": "fentry/security_socket_connect",
		"handle_sendmsg": "fentry/security_socket_sendmsg",
		"handle_deliver": "fentry/security_socket_sendmsg",
	} {
		if p := spec.Programs[name]; p == nil || p.SectionName != section {
			t.Errorf("program %s = %+v, want section %s", name, p, section)
		}
	}
}

func encode(t *testing.T, r netEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, &r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// netPort stores port as the kernel copies it out of a sockaddr: network order.
func netPort(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

func TestDecode(t *testing.T) {
	at := time.Unix(1, 0)
	base := func() netEvent {
		var r netEvent
		r.Op, r.Pid, r.HostPid, r.CgroupId, r.SockType, r.Protocol = opConnect, 7, 1007, 99, 1, 6
		copy8(r.Comm[:], "curl")
		copy8(r.Cgroup[0][:], tidA)
		copy8(r.Cgroup[1][:], "subpoena")
		copy8(r.Cgroup[2][:], "") // hierarchy root
		r.Depth = 3
		return r
	}

	v4 := base()
	v4.Family, v4.Port = afInet, netPort(443)
	copy(v4.Addr[:], []byte{192, 0, 2, 7})
	e, err := decode(encode(t, v4), at)
	if err != nil {
		t.Fatal(err)
	}
	want := Event{Op: witness.OpConnect, PID: 7, HostPID: 1007, Comm: "curl", SockType: 1, Protocol: "tcp",
		Dest: netip.MustParseAddrPort("192.0.2.7:443"), CgroupID: 99, Cgroup: "subpoena/" + tidA, Time: at}
	if fmt.Sprintf("%+v", e) != fmt.Sprintf("%+v", want) {
		t.Fatalf("decode =\n %+v\nwant\n %+v", e, want)
	}

	v6 := base()
	v6.Op, v6.Family, v6.Port, v6.SockType, v6.Protocol = opSendmsg, afInet6, netPort(53), 2, 17
	v6.Addr = netip.MustParseAddr("2001:db8::1").As16()
	if e, err := decode(encode(t, v6), at); err != nil || e.Dest != netip.MustParseAddrPort("[2001:db8::1]:53") ||
		e.Op != witness.OpSendmsg || e.Protocol != "udp" {
		t.Fatalf("v6 decode = %+v, %v", e, err)
	}

	mapped := base()
	mapped.Family, mapped.Port = afInet6, netPort(80)
	mapped.Addr = netip.MustParseAddr("::ffff:192.0.2.7").As16()
	if e, err := decode(encode(t, mapped), at); err != nil || e.Dest != netip.MustParseAddrPort("192.0.2.7:80") {
		t.Fatalf("v4-mapped decode = %+v, %v", e, err)
	}

	// An accepted socket on a dual-stack listener: both ends are IPv4-mapped.
	// The peer port is as the socket holds it, network order; the local port
	// (skc_num) is host order.
	acc := base()
	acc.Op, acc.Family, acc.Port, acc.LocalPort, acc.Bytes = opDeliver, afInet6, netPort(40001), 1883, 12
	acc.Addr = netip.MustParseAddr("::ffff:127.0.0.1").As16()
	acc.LocalAddr = netip.MustParseAddr("::ffff:127.0.0.2").As16()
	if e, err := decode(encode(t, acc), at); err != nil || e.Op != witness.OpDeliver || e.Bytes != 12 ||
		e.Dest != netip.MustParseAddrPort("127.0.0.1:40001") || e.Local != netip.MustParseAddrPort("127.0.0.2:1883") {
		t.Fatalf("delivery decode = %+v, %v", e, err)
	}

	noPeer := base()
	noPeer.Op, noPeer.Family = opDeliver, afInet
	if e, err := decode(encode(t, noPeer), at); err != nil || e.Dest.IsValid() {
		t.Fatalf("a socket with no peer must decode to an unknown peer: %+v, %v", e, err)
	}
	half := base()
	half.Op, half.Family = opDeliver, afInet
	copy(half.Addr[:], []byte{192, 0, 2, 7}) // a connected raw socket has no port
	if e, err := decode(encode(t, half), at); err != nil || e.Dest != netip.MustParseAddrPort("192.0.2.7:0") {
		t.Fatalf("a peer with no port keeps its address: %+v, %v", e, err)
	}

	raw := encode(t, v4)
	if _, err := decode(raw[:10], at); err == nil {
		t.Fatal("short record must fail")
	}
	bad := v4
	bad.Op = 9
	if _, err := decode(encode(t, bad), at); err == nil {
		t.Fatal("unknown op must fail")
	}
	bad = v4
	bad.Family = 1
	if _, err := decode(encode(t, bad), at); err == nil {
		t.Fatal("unknown family must fail")
	}
}

func copy8(dst []int8, s string) {
	for i := 0; i < len(s) && i < len(dst); i++ {
		dst[i] = int8(s[i])
	}
}
