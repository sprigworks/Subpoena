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
	rd    *ringbuf.Reader
	done  chan struct{}
	err   error // first read error other than the final flush, set before done closes
}

const (
	kindExec = 1
	kindFork = 2
)

// Start loads and attaches the program. Execs after Start returns are seen.
func (w *Witness) Start() error {
	if w.k != nil {
		return errors.New("execbpf: already started")
	}
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
	w.k = k
	go w.read(k)
	return nil
}

func (w *Witness) read(k *kernel) {
	defer close(k.done)
	for {
		rec, err := k.rd.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrFlushed) && !errors.Is(err, ringbuf.ErrClosed) {
				k.err = err
			}
			return
		}
		e, err := decode(rec.RawSample, time.Now())
		if err != nil {
			k.err = err
			continue
		}
		w.handle(e)
	}
}

// Stop detaches the program, delivers every event already in the ring buffer,
// and unloads. It returns the first error the reader hit, if any.
func (w *Witness) Stop() error {
	k := w.k
	if k == nil {
		return nil
	}
	w.k = nil
	for _, l := range k.links {
		l.Close() // no new events after this
	}
	k.links = nil
	// Flush, not SetDeadline: SetDeadline takes the lock a blocked Read holds.
	// After Flush, Read returns every pending sample and then ErrFlushed.
	if err := k.rd.Flush(); err != nil {
		k.rd.Close() // unblocks Read with ErrClosed; pending samples are lost
	}
	<-k.done
	err := k.err
	k.close()
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
