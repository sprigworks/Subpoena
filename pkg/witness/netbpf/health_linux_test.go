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
		{name: "bad record", readErr: ringbuf.ErrFlushed, malformed: true, want: "short record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &scriptedReader{readErr: tc.readErr, flushErr: tc.flushErr, end: make(chan struct{})}
			if tc.malformed {
				r.records = []ringbuf.Record{{RawSample: []byte{1}}}
			}
			w := New(Config{})
			k := &kernel{rd: r, done: make(chan struct{}), lost: func() (uint64, error) { return tc.lost, tc.mapErr }}
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

func TestGeneratedObjectContract(t *testing.T) {
	spec, err := loadNet()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["lost"]
	if m == nil || m.Type != ebpf.PerCPUArray || m.MaxEntries != 1 || m.KeySize != 4 || m.ValueSize != 8 {
		t.Fatalf("generated loss map = %+v", m)
	}
	for name, section := range map[string]string{
		"handle_connect": "fentry/security_socket_connect",
		"handle_sendmsg": "fentry/security_socket_sendmsg",
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
