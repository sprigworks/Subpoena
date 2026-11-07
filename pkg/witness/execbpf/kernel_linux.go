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
	left  func() (uint64, error) // the same, for tasks that left a session
	deep  func() (uint64, error) // the same, for cgroup paths too long to walk
	// misses is the invocations the kernel skipped, every program together. It
	// reads the programs, so it too must run before they are unloaded.
	misses func() (uint64, error)
}

type eventReader interface {
	Read() (ringbuf.Record, error)
	Flush() error
	Close() error
}

const (
	kindExec = 1
	kindFork = 2

	nameLen = 64 // NAME_LEN in bpf/exec.c
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
	base, err := sessionBase(w.base)
	if err != nil {
		return err
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
	vars := map[string]any{"pidns_inum": uint32(st.Ino), "session_base": base}
	if w.cfg.RootPID != 0 {
		vars["track_forks"] = uint32(1)
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
	for _, h := range k.hooks() {
		l, err := link.AttachTracing(link.TracingOptions{Program: h.prog})
		if err != nil {
			k.close()
			return fmt.Errorf("execbpf: attach %s: %w", h.name, err)
		}
		k.links = append(k.links, l)
	}
	if k.rd, err = ringbuf.NewReader(k.objs.Events); err != nil {
		k.close()
		return fmt.Errorf("execbpf: %w", err)
	}
	k.lost = func() (uint64, error) { return sum(k.objs.Lost, "loss") }
	k.left = func() (uint64, error) { return sum(k.objs.LeftSession, "left-session") }
	k.deep = func() (uint64, error) { return sum(k.objs.TooDeep, "too-deep") }
	k.misses = k.recursionMisses
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

// hook is one program to attach.
type hook struct {
	name string
	prog *ebpf.Program
}

func (k *kernel) hooks() []hook {
	return []hook{
		{"handle_exec", k.objs.HandleExec},
		{"handle_fork", k.objs.HandleFork},
		{"handle_attach", k.objs.HandleAttach},
	}
}

// recursionMisses adds up what the kernel counts for every program: invocations it
// skipped because a program was already active on that CPU, each maybe an exec or
// a move that was never reported, with no event and no ring-buffer loss. Linux
// before 5.12 has neither the guard nor the count, and reads as zero.
func (k *kernel) recursionMisses() (uint64, error) {
	var total uint64
	for _, h := range k.hooks() {
		st, err := h.prog.Stats()
		if err != nil {
			return 0, fmt.Errorf("execbpf: read recursion misses of %s: %w", h.name, err)
		}
		total += st.RecursionMisses
	}
	return total, nil
}

// sum adds up a per-CPU counter.
func sum(m *ebpf.Map, what string) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("execbpf: read %s counter: %w", what, err)
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

// sessionBase is the kernel filter's copy of the session root's last element. The
// kernel reads path elements up to nameLen-1 bytes long, so a longer name could
// never compare equal, and a task leaving its session would go uncounted. Refused
// here, like a root with no last element, or one no cgroup can have for a name.
//
//subpoena:enforcement_point
func sessionBase(base string) ([nameLen]byte, error) {
	var out [nameLen]byte
	if base == "" || base == "/" || base == "." || base == ".." || len(base) >= nameLen {
		return out, fmt.Errorf("execbpf: cgroup root element %q cannot be matched in the kernel", base) //subpoena:enforcement
	}
	copy(out[:], base)
	return out, nil
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
	misses, err := k.misses()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	if misses != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: the kernel skipped the programs %d time(s) (recursion misses): execs may have gone unseen", misses)) //subpoena:enforcement
	}
	left, err := k.left()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	if left != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: %d task(s) left a session cgroup during the capture, and what they did after is no session's", left)) //subpoena:enforcement
	}
	deep, err := k.deep()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	if deep != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("execbpf: %d exec(s) or move(s) in a cgroup path too long to walk, so nothing says whose they were", deep)) //subpoena:enforcement
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
