//go:build linux && (amd64 || arm64)

package netbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// kernel is the loaded programs, their links and the ring-buffer reader.
type kernel struct {
	objs  netObjects
	links []link.Link
	rd    eventReader
	done  chan struct{}
	lost  func() (uint64, error) // read after detaching, before unloading
}

type eventReader interface {
	Read() (ringbuf.Record, error)
	Flush() error
	Close() error
}

const (
	opConnect = 1
	opSendmsg = 2

	afInet  = 2
	afInet6 = 10
)

// Start loads and attaches the programs. Attempts after Start returns are seen.
func (w *Witness) Start() error {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	if w.k != nil {
		return errors.New("netbpf: already started")
	}
	w.mu.Lock()
	w.events, w.healthErr, w.finished = nil, nil, false
	w.mu.Unlock()
	// Kernels before 5.11 charge eBPF memory to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("netbpf: %w", err)
	}
	spec, err := loadNet()
	if err != nil {
		return fmt.Errorf("netbpf: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &st); err != nil {
		return fmt.Errorf("netbpf: own PID namespace: %w", err)
	}
	v, ok := spec.Variables["pidns_inum"]
	if !ok {
		return errors.New("netbpf: object has no pidns_inum variable")
	}
	if err := v.Set(uint32(st.Ino)); err != nil {
		return fmt.Errorf("netbpf: set pidns_inum: %w", err)
	}
	k := &kernel{done: make(chan struct{})}
	if err := spec.LoadAndAssign(&k.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("netbpf: verifier: %+v", ve)
		}
		return fmt.Errorf("netbpf: load: %w", err)
	}
	for _, p := range []*ebpf.Program{k.objs.HandleConnect, k.objs.HandleSendmsg} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			k.close()
			return fmt.Errorf("netbpf: attach %s: %w", p, err)
		}
		k.links = append(k.links, l)
	}
	if k.rd, err = ringbuf.NewReader(k.objs.Events); err != nil {
		k.close()
		return fmt.Errorf("netbpf: %w", err)
	}
	k.lost = func() (uint64, error) {
		var perCPU []uint64
		if err := k.objs.Lost.Lookup(uint32(0), &perCPU); err != nil {
			return 0, fmt.Errorf("netbpf: read loss counter: %w", err)
		}
		var total uint64
		for _, n := range perCPU {
			total += n
		}
		return total, nil
	}
	w.k = k
	go w.read(k)
	return nil
}

func (w *Witness) read(k *kernel) {
	defer close(k.done)
	for {
		rec, err := k.rd.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrFlushed) {
				w.recordError(fmt.Errorf("netbpf: read: %w", err))
			}
			return
		}
		e, err := decode(rec.RawSample, time.Now())
		if err != nil {
			w.recordError(err)
			continue
		}
		w.handle(e)
	}
}

// Stop detaches the programs, drains buffered events and reads the loss
// counter. Capture errors persist in Health, including after repeated Stop calls.
func (w *Witness) Stop() error {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	k := w.k
	if k == nil {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.healthErr
	}
	w.k = nil
	var stopErr error
	for _, l := range k.links {
		if err := l.Close(); err != nil {
			stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: detach: %w", err))
		}
	}
	k.links = nil
	// Flush, not SetDeadline: SetDeadline takes the lock a blocked Read holds.
	// If Flush fails, Close may discard pending samples. Their exact count is
	// unknowable, so retain the error even when the kernel loss counter is zero.
	if err := k.rd.Flush(); err != nil {
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: flush (pending samples may be lost): %w", err))
		if err := k.rd.Close(); err != nil {
			stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: close reader: %w", err))
		}
	}
	<-k.done
	lost, err := k.lost()
	if err != nil {
		stopErr = errors.Join(stopErr, err)
	}
	if lost != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: lost %d kernel event(s)", lost))
	}
	k.close()
	w.mu.Lock()
	w.healthErr = errors.Join(w.healthErr, stopErr)
	w.finished = true
	err = w.healthErr
	w.mu.Unlock()
	return err
}

func (k *kernel) close() {
	for _, l := range k.links {
		l.Close()
	}
	if k.rd != nil {
		k.rd.Close()
	}
	k.objs.Close()
}

// decode converts one ring-buffer record.
func decode(raw []byte, at time.Time) (Event, error) {
	var r netEvent
	if n := binary.Size(r); len(raw) < n {
		return Event{}, fmt.Errorf("netbpf: short record: %d bytes, want %d", len(raw), n)
	}
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &r); err != nil {
		return Event{}, fmt.Errorf("netbpf: decode: %w", err)
	}
	e := Event{
		PID:      int(r.Pid),
		HostPID:  int(r.HostPid),
		Comm:     cstr(r.Comm[:]),
		SockType: int(r.SockType),
		Protocol: protocolName(r.Protocol),
		CgroupID: r.CgroupId,
		Time:     at,
	}
	switch r.Op {
	case opConnect:
		e.Op = witness.OpConnect
	case opSendmsg:
		e.Op = witness.OpSendmsg
	default:
		return Event{}, fmt.Errorf("netbpf: unknown op %d", r.Op)
	}
	// The kernel copied the port as it sits in the sockaddr: network order.
	var pb [2]byte
	binary.NativeEndian.PutUint16(pb[:], r.Port)
	port := binary.BigEndian.Uint16(pb[:])
	var addr netip.Addr
	switch r.Family {
	case afInet:
		addr = netip.AddrFrom4([4]byte(r.Addr[:4]))
	case afInet6:
		addr = netip.AddrFrom16(r.Addr).Unmap()
	default:
		return Event{}, fmt.Errorf("netbpf: unknown address family %d", r.Family)
	}
	e.Dest = netip.AddrPortFrom(addr, port)
	depth := int(r.Depth)
	if depth > len(r.Cgroup) {
		depth = len(r.Cgroup)
	}
	names := make([]string, depth)
	for i := range names {
		names[i] = cstr(r.Cgroup[i][:])
	}
	e.Cgroup = cgroupPath(names)
	return e, nil
}

func cstr(s []int8) string {
	b := make([]byte, len(s))
	for i, c := range s {
		b[i] = byte(c)
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
