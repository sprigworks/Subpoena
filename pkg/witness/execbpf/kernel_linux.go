//go:build linux && (amd64 || arm64)

package execbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// kernel is the loaded program, its links and the ring-buffer reader.
type kernel struct {
	objs  execObjects
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
	kindExec = 1
	kindFork = 2
)

// Start loads and attaches the program. Execs after Start returns are seen.
func (w *Witness) Start() error {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	if w.k != nil {
		return errors.New("execbpf: already started")
	}
	w.mu.Lock()
	w.events, w.healthErr, w.finished = nil, nil, false
	w.mu.Unlock()
	// Kernels before 5.11 charge eBPF memory to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("execbpf: %w", err)
	}
	spec, err := loadExec()
	if err != nil {
		return fmt.Errorf("execbpf: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &st); err != nil {
		return fmt.Errorf("execbpf: own PID namespace: %w", err)
	}
	vars := map[string]uint32{"pidns_inum": uint32(st.Ino)}
	if w.cfg.RootPID != 0 {
		vars["track_forks"] = 1
	}
	for name, val := range vars {
		v, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("execbpf: object has no %s variable", name)
		}
		if err := v.Set(val); err != nil {
			return fmt.Errorf("execbpf: set %s: %w", name, err)
		}
	}
	if w.ringBytes != 0 {
		m, ok := spec.Maps["events"]
		if !ok {
			return errors.New("execbpf: object has no events map")
		}
		m.MaxEntries = w.ringBytes
	}
	k := &kernel{done: make(chan struct{})}
	if err := spec.LoadAndAssign(&k.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("execbpf: verifier: %+v", ve)
		}
		return fmt.Errorf("execbpf: load: %w", err)
	}
	for _, p := range []*ebpf.Program{k.objs.HandleExec, k.objs.HandleFork} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			k.close()
			return fmt.Errorf("execbpf: attach %s: %w", p, err)
		}
		k.links = append(k.links, l)
	}
	if k.rd, err = ringbuf.NewReader(k.objs.Events); err != nil {
		k.close()
		return fmt.Errorf("execbpf: %w", err)
	}
	k.lost = func() (uint64, error) {
		var perCPU []uint64
		if err := k.objs.Lost.Lookup(uint32(0), &perCPU); err != nil {
			return 0, fmt.Errorf("execbpf: read loss counter: %w", err)
		}
		var total uint64
		for _, n := range perCPU {
			total += n
		}
		return total, nil
	}
	w.mu.Lock()
	w.events, w.healthErr, w.finished = nil, nil, false
	if w.cfg.RootPID != 0 {
		w.desc = map[int]bool{w.cfg.RootPID: true}
	}
	w.mu.Unlock()
	w.k = k
	go w.read(k)
	return nil
}

func (w *Witness) read(k *kernel) {
	defer close(k.done)
	if w.holdReads != nil {
		<-w.holdReads
	}
	for {
		rec, err := k.rd.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrFlushed) {
				w.recordError(fmt.Errorf("execbpf: read: %w", err))
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

// Stop detaches the program, drains buffered events and reads the loss counter.
// Capture errors persist in Health, including after repeated Stop calls.
//
//subpoena:enforcement_point
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
			stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: detach: %w", err))
		}
	}
	k.links = nil
	// Flush, not SetDeadline: SetDeadline takes the lock a blocked Read holds.
	// If Flush fails, Close may discard pending samples. Their exact count is
	// unknowable, so retain the error even when the kernel loss counter is zero.
	if err := k.rd.Flush(); err != nil {
		stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: flush (pending samples may be lost): %w", err))
		if err := k.rd.Close(); err != nil {
			stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: close reader: %w", err))
		}
	}
	<-k.done
	lost, err := k.lost()
	if err != nil {
		stopErr = errors.Join(stopErr, err)
	}
	if lost != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: lost %d kernel event(s)", lost)) //subpoena:enforcement
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
	var r execEvent
	if n := binary.Size(r); len(raw) < n {
		return Event{}, fmt.Errorf("execbpf: short record: %d bytes, want %d", len(raw), n)
	}
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &r); err != nil {
		return Event{}, fmt.Errorf("execbpf: decode: %w", err)
	}
	e := Event{
		PID:      int(r.Pid),
		PPID:     int(r.Ppid),
		HostPID:  int(r.HostPid),
		HostPPID: int(r.HostPpid),
		Comm:     cstr(r.Comm[:]),
		CgroupID: r.CgroupId,
		Time:     at,
	}
	switch r.Kind {
	case kindExec:
		e.Kind = KindExec
		e.Exe = cstr(r.Filename[:])
		n := int(r.ArgsLen)
		if n > len(r.Args) {
			n = len(r.Args)
		}
		e.Args = splitArgs(bytesOf(r.Args[:n]))
	case kindFork:
		e.Kind = KindFork
	default:
		return Event{}, fmt.Errorf("execbpf: unknown event kind %d", r.Kind)
	}
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

func bytesOf(s []int8) []byte {
	b := make([]byte, len(s))
	for i, c := range s {
		b[i] = byte(c)
	}
	return b
}

func cstr(s []int8) string {
	b := bytesOf(s)
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
