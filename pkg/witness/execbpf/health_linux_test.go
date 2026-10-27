//go:build linux && (amd64 || arm64)

//subpoena:impl_derived
//subpoena:pure_logic

package execbpf

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
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
			} else {
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
			}
		})
	}
}

func TestHealthRequiresFinalRetainedCapture(t *testing.T) {
	w := New(Config{})
	if w.Health() == nil {
		t.Fatal("unstarted capture must be unhealthy")
	}
	w.finished = true
	if w.Health() != nil {
		t.Fatal("completed capture should be healthy")
	}
	w.cfg.NoRetain = true
	if w.Health() == nil {
		t.Fatal("NoRetain must not certify empty Spawned")
	}
}

func TestGeneratedLossMapContract(t *testing.T) {
	spec, err := loadExec()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["lost"]
	if m == nil || m.Type != ebpf.PerCPUArray || m.MaxEntries != 1 || m.KeySize != 4 || m.ValueSize != 8 {
		t.Fatalf("generated loss map = %+v", m)
	}
}
