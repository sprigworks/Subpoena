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
	other func() (uint64, error) // the same, for sends on sockets that are not inet
	left  func() (uint64, error) // the same, for tasks that left a session
	deep  func() (uint64, error) // the same, for cgroup paths too long to walk
	// misses is the invocations the kernel skipped, every program together. It
	// reads the programs, so it too must run before they are unloaded.
	misses func() (uint64, error)
}

// hook is one program to attach.
type hook struct {
	name string
	prog *ebpf.Program
}

// attach attaches one program. A variable so a test can make it fail.
var attach = func(p *ebpf.Program) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{Program: p})
}

type eventReader interface {
	Read() (ringbuf.Record, error)
	Flush() error
	Close() error
}

const (
	opConnect = 1
	opSendmsg = 2
	opDeliver = 3

	broadcastOption = 1 // the event's broadcast bits, as bpf/net.c sets them
	broadcastRoute  = 2

	afInet  = 2
	afInet6 = 10

	nameLen = 64 // NAME_LEN in bpf/net.c
)

// Start loads and attaches the programs. Attempts after Start returns are seen.
// A failure stays in Health until the next Start: a witness that never attached
// has seen nothing.
//
//subpoena:enforcement_point
func (w *Witness) Start() error {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	if w.k != nil {
		return errors.New("netbpf: already started")
	}
	w.mu.Lock()
	w.events, w.deliveries, w.healthErr, w.finished, w.coverage = nil, nil, nil, false, witness.DeliveryCoverage{}
	w.unattributed = 0
	w.mu.Unlock()
	k, err := w.load()
	if err != nil {
		w.recordError(err) //subpoena:enforcement
		return err
	}
	w.k = k
	go w.read(k)
	return nil
}

// load loads the programs and attaches every hook, or none.
func (w *Witness) load() (*kernel, error) {
	base, err := sessionBase(w.base)
	if err != nil {
		return nil, err
	}
	// Kernels before 5.11 charge eBPF memory to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("netbpf: %w", err)
	}
	spec, err := loadNet()
	if err != nil {
		return nil, fmt.Errorf("netbpf: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &st); err != nil {
		return nil, fmt.Errorf("netbpf: own PID namespace: %w", err)
	}
	for name, value := range map[string]any{"pidns_inum": uint32(st.Ino), "session_base": base} {
		v, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("netbpf: object has no %s variable", name)
		}
		if err := v.Set(value); err != nil {
			return nil, fmt.Errorf("netbpf: set %s: %w", name, err)
		}
	}
	k := &kernel{done: make(chan struct{})}
	if err := spec.LoadAndAssign(&k.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("netbpf: verifier: %+v", ve)
		}
		return nil, fmt.Errorf("netbpf: load: %w", err)
	}
	if err := k.attachAll(k.hooks()); err != nil {
		k.close()
		return nil, err
	}
	if k.rd, err = ringbuf.NewReader(k.objs.Events); err != nil {
		k.close()
		return nil, fmt.Errorf("netbpf: %w", err)
	}
	k.lost = func() (uint64, error) { return sum(k.objs.Lost, "loss") }
	k.other = func() (uint64, error) { return sum(k.objs.OtherSends, "other-sends") }
	k.left = func() (uint64, error) { return sum(k.objs.LeftSession, "left-session") }
	k.deep = func() (uint64, error) { return sum(k.objs.TooDeep, "too-deep") }
	k.misses = k.recursionMisses
	return k, nil
}

func (k *kernel) hooks() []hook {
	return []hook{
		{"handle_connect", k.objs.HandleConnect},
		{"handle_sendmsg", k.objs.HandleSendmsg},
		{"handle_deliver", k.objs.HandleDeliver},
		{"handle_attach", k.objs.HandleAttach},
		{"handle_fork", k.objs.HandleFork},
	}
}

// recursionMisses adds up what the kernel counts for every program: invocations
// it skipped because the program was already active on that CPU. On a preempt=full
// kernel a task preempted inside a program holds that CPU's count up, so every send
// there goes unreported until it runs again, with no event and no ring-buffer loss.
// Linux before 5.12 has neither the guard nor the count, and reads as zero.
func (k *kernel) recursionMisses() (uint64, error) {
	var total uint64
	for _, h := range k.hooks() {
		st, err := h.prog.Stats()
		if err != nil {
			return 0, fmt.Errorf("netbpf: read recursion misses of %s: %w", h.name, err)
		}
		total += st.RecursionMisses
	}
	return total, nil
}

// attachAll attaches hooks in order and stops at the first failure, keeping
// what attached in k.links for k.close.
func (k *kernel) attachAll(hooks []hook) error {
	for _, h := range hooks {
		l, err := attach(h.prog)
		if err != nil {
			return fmt.Errorf("netbpf: attach %s: %w", h.name, err)
		}
		k.links = append(k.links, l)
	}
	return nil
}

// sum adds up a per-CPU counter.
func sum(m *ebpf.Map, what string) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("netbpf: read %s counter: %w", what, err)
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

// cgroupID is the kernel's ID of the cgroup at path: its inode on cgroup v2.
func cgroupID(path string) (uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, false
	}
	return st.Ino, true
}

// sessionBase is the kernel filter's copy of the session root's last element.
// The kernel reads path elements up to nameLen-1 bytes long, so a longer name
// could never compare equal, and a session's sends would vanish as if none were
// made. Refused here, like a root with no last element, or one no cgroup can
// have for a name.
//
//subpoena:enforcement_point
func sessionBase(base string) ([nameLen]byte, error) {
	var out [nameLen]byte
	if base == "" || base == "/" || base == "." || base == ".." || len(base) >= nameLen {
		return out, fmt.Errorf("netbpf: cgroup root element %q cannot be matched in the kernel", base) //subpoena:enforcement
	}
	copy(out[:], base)
	return out, nil
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

// Stop detaches the programs, drains buffered events and reads the kernel's
// counters of what it could not report. Capture errors persist in Health,
// including after repeated Stop calls.
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
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: lost %d kernel event(s)", lost)) //subpoena:enforcement
	}
	other, err := k.other()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	misses, err := k.misses()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	if misses != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: the kernel skipped the programs %d time(s) (recursion misses): sends and dials may have gone unseen", misses)) //subpoena:enforcement
	}
	left, err := k.left()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	if left != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: %d task(s) left a session cgroup during the capture, and what they did after is no session's", left)) //subpoena:enforcement
	}
	deep, err := k.deep()
	if err != nil {
		stopErr = errors.Join(stopErr, err) //subpoena:enforcement
	}
	if deep != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: %d attempt(s) or move(s) in a cgroup path too long to walk, so nothing says whose they were", deep)) //subpoena:enforcement
	}
	k.close()
	w.mu.Lock()
	if w.unattributed != 0 {
		stopErr = errors.Join(stopErr, fmt.Errorf("netbpf: %d attempt(s) from under the session root but in no session", w.unattributed)) //subpoena:enforcement
	}
	w.coverage.Lost, w.coverage.OtherFamilySends = lost, other
	w.coverage.RecursionMisses, w.coverage.LeftSession, w.coverage.TooDeep = misses, left, deep
	w.coverage.Unattributed = w.unattributed
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
		PID:            int(r.Pid),
		HostPID:        int(r.HostPid),
		Comm:           cstr(r.Comm[:]),
		Bytes:          r.Bytes,
		Broadcast:      r.Broadcast&broadcastOption != 0,
		BroadcastRoute: r.Broadcast&broadcastRoute != 0,
		RootID:         r.RootId,
		SockType:       int(r.SockType),
		Protocol:       protocolName(r.Protocol),
		CgroupID:       r.CgroupId,
		Time:           at,
	}
	switch r.Op {
	case opConnect:
		e.Op = witness.OpConnect
	case opSendmsg:
		e.Op = witness.OpSendmsg
	case opDeliver:
		e.Op = witness.OpDeliver
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
	// A connected send on a socket with no peer leaves zeros: unknown, not a
	// peer at 0.0.0.0 port 0.
	if r.Op == opDeliver && addr.IsUnspecified() && port == 0 {
		e.Dest = netip.AddrPort{}
	}
	if r.LocalAddr != [16]uint8{} || r.LocalPort != 0 {
		e.Local = netip.AddrPortFrom(netip.AddrFrom16(r.LocalAddr).Unmap(), r.LocalPort)
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
