//subpoena:impl_derived
//subpoena:pure_logic

// run with fake witnesses in place of the eBPF programs: the flags, the two
// files' records, the order of lines against the start record and the ready
// file, and failing when the network witness cannot start. No root, no
// telemetry; the kernel run is conformance/witness_kernel_linux_test.go.
package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness/execbpf"
	"github.com/sprigworks/subpoena/pkg/witness/netbpf"
)

const traceA = "c0de00000000000000000000000000a1"

// fake is a capturer. On Start it runs onStart (which may check what is on
// disk) and then emits its events from another goroutine, as the reader
// goroutine of a real witness does, while Start's caller still holds the
// sink's lock.
type fake struct {
	startErr, stopErr error
	onStart           func()
	emit              func()
	started, stopped  bool
	wg                sync.WaitGroup
}

func (f *fake) Start() error {
	if f.onStart != nil {
		f.onStart()
	}
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	if f.emit != nil {
		f.wg.Add(1)
		trying := make(chan struct{})
		go func() {
			defer f.wg.Done()
			close(trying)
			f.emit()
		}()
		<-trying
		time.Sleep(10 * time.Millisecond) // let the event reach the lock first
	}
	return nil
}

func (f *fake) Stop() error {
	f.wg.Wait()
	f.stopped = true
	return f.stopErr
}

var at = time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC)

func execEvent(tid string) execbpf.Event {
	e := execbpf.Event{Kind: execbpf.KindExec, Time: at, PID: 7, PPID: 1, HostPID: 4007, Comm: "rm", Exe: "/usr/bin/rm",
		Args: []string{"rm", "-f", "x"}, CgroupID: 91, Cgroup: "subpoena/" + tid}
	if tid != "" {
		e.TraceID, e.Attribution = tid, "cgroup"
	}
	return e
}

func netEvent(tid string, dest netip.AddrPort) netbpf.Event {
	e := netbpf.Event{Op: "sendmsg", Time: at, PID: 8, HostPID: 4008, Comm: "curl", SockType: 2,
		Protocol: "udp", Dest: dest, CgroupID: 92, Cgroup: "subpoena/" + tid}
	if tid != "" {
		e.TraceID, e.Attribution = tid, "cgroup"
	}
	return e
}

type rig struct {
	t                *testing.T
	o                options
	ew, nw           *fake
	execOn           func(execbpf.Event)
	netOn            func(netbpf.Event)
	netBuilt         bool
	sig              chan os.Signal
	done             chan error
	execLog, netLog  string
	readyBeforeStart bool
}

func newRig(t *testing.T) *rig {
	dir := t.TempDir()
	r := &rig{t: t, ew: &fake{}, nw: &fake{}, sig: make(chan os.Signal, 1), done: make(chan error, 1)}
	r.execLog, r.netLog = filepath.Join(dir, "exec.jsonl"), filepath.Join(dir, "net.jsonl")
	r.o = options{out: r.execLog, netOut: r.netLog, ready: filepath.Join(dir, "ready")}
	r.nw.onStart = func() {
		if _, err := os.Stat(r.o.ready); err == nil {
			r.readyBeforeStart = true
		}
	}
	return r
}

func (r *rig) witnesses() witnesses {
	return witnesses{
		exec: func(_ string, on func(execbpf.Event)) capturer { r.execOn = on; return r.ew },
		net:  func(_ string, on func(netbpf.Event)) capturer { r.netOn, r.netBuilt = on, true; return r.nw },
	}
}

// start runs the command until its ready file appears.
func (r *rig) start() {
	r.t.Helper()
	go func() { r.done <- run(r.o, r.witnesses(), r.sig) }()
	for i := 0; ; i++ {
		select {
		case err := <-r.done:
			r.t.Fatalf("run returned before ready: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
		if _, err := os.Stat(r.o.ready); err == nil {
			return
		}
		if i > 1000 {
			r.t.Fatal("no ready file")
		}
	}
}

func (r *rig) stop() error {
	r.sig <- syscall.SIGTERM
	return <-r.done
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestBothFilesHaveTheirOwnWindow(t *testing.T) {
	r := newRig(t)
	r.ew.emit = func() { r.execOn(execEvent(traceA)) }
	r.nw.emit = func() {
		r.netOn(netEvent(traceA, netip.MustParseAddrPort("[::ffff:192.0.2.1]:9")))
		r.netOn(netEvent(traceA, netip.MustParseAddrPort("[2001:db8::1]:443")))
		r.netOn(netEvent("", netip.MustParseAddrPort("10.0.0.1:53"))) // no session: not written
	}
	r.start()
	if r.readyBeforeStart {
		t.Fatal("the ready file was written before the network witness started")
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if !r.ew.stopped || !r.nw.stopped {
		t.Fatal("both witnesses must be stopped")
	}
	if _, err := os.Stat(r.o.ready); err == nil {
		t.Error("the ready file outlives the run")
	}
	ex := lines(t, r.execLog)
	if len(ex) != 3 || !strings.Contains(ex[0], `"record":"start"`) || !strings.Contains(ex[2], `"record":"stop","healthy":true}`) {
		t.Fatalf("exec file: %q", ex)
	}
	// The exec line, byte for byte as released readers and LogQL expect it.
	want := `{"time":"2026-10-28T12:00:01Z","pid":7,"ppid":1,"host_pid":4007,"comm":"rm","exe":"/usr/bin/rm","command":"rm -f x","args":["rm","-f","x"],"cgroup_id":91,"cgroup":"subpoena/` + traceA + `","trace_id":"` + traceA + `","attribution":"cgroup"}`
	if ex[1] != want {
		t.Fatalf("exec line:\n got  %s\n want %s", ex[1], want)
	}
	nl := lines(t, r.netLog)
	if len(nl) != 4 || !strings.Contains(nl[0], `"record":"start"`) || !strings.Contains(nl[3], `"record":"stop","healthy":true}`) {
		t.Fatalf("network file: %q", nl)
	}
	want = `{"time":"2026-10-28T12:00:01Z","op":"sendmsg","protocol":"udp","dest":"192.0.2.1:9","pid":8,"host_pid":4008,"comm":"curl","sock_type":2,"cgroup_id":92,"cgroup":"subpoena/` + traceA + `","trace_id":"` + traceA + `","attribution":"cgroup"}`
	if nl[1] != want {
		t.Fatalf("network line:\n got  %s\n want %s", nl[1], want)
	}
	if !strings.Contains(nl[2], `"dest":"[2001:db8::1]:443"`) {
		t.Fatalf("IPv6 dest: %s", nl[2])
	}
}

func TestAllWritesUnattributedEvents(t *testing.T) {
	r := newRig(t)
	r.o.all = true
	r.ew.emit = func() { r.execOn(execEvent("")) }
	r.nw.emit = func() { r.netOn(netEvent("", netip.MustParseAddrPort("10.0.0.1:53"))) }
	r.start()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if ex, nl := lines(t, r.execLog), lines(t, r.netLog); len(ex) != 3 || len(nl) != 3 || strings.Contains(nl[1], "trace_id") {
		t.Fatalf("-all: exec %q, network %q", ex, nl)
	}
}

func TestWithoutNetOutTheNetworkWitnessIsNotRun(t *testing.T) {
	r := newRig(t)
	r.o.netOut = ""
	r.start()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if r.netBuilt || r.nw.started {
		t.Fatal("the network witness ran without -net-out")
	}
	if _, err := os.Stat(r.netLog); err == nil {
		t.Fatal("a network file was written without -net-out")
	}
	if ex := lines(t, r.execLog); len(ex) != 2 {
		t.Fatalf("exec file: %q", ex)
	}
}

// -net-out asked for network evidence: if the network witness cannot start,
// the command fails rather than run exec-only.
func TestNetworkWitnessThatCannotStartFailsTheCommand(t *testing.T) {
	r := newRig(t)
	r.nw.startErr = errors.New("netbpf: needs Linux on amd64 or arm64")
	err := run(r.o, r.witnesses(), r.sig)
	if err == nil || !strings.Contains(err.Error(), "network witness: netbpf: needs Linux") {
		t.Fatalf("run: %v", err)
	}
	if !r.ew.stopped {
		t.Error("the exec witness was left running")
	}
	if _, err := os.Stat(r.o.ready); err == nil {
		t.Error("ready written though the network witness never attached")
	}
}

// Lost kernel events in the network capture make its stop unhealthy, and
// only its stop.
func TestNetworkLossMakesOnlyTheNetworkStopUnhealthy(t *testing.T) {
	r := newRig(t)
	r.nw.stopErr = errors.New("netbpf: lost 2 kernel event(s)")
	r.start()
	if err := r.stop(); err == nil || !strings.Contains(err.Error(), "lost 2") {
		t.Fatalf("run: %v", err)
	}
	if ex := lines(t, r.execLog); !strings.Contains(ex[len(ex)-1], `"healthy":true`) {
		t.Errorf("exec stop: %s", ex[len(ex)-1])
	}
	nl := lines(t, r.netLog)
	if last := nl[len(nl)-1]; !strings.Contains(last, `"record":"stop","healthy":false,"error":"netbpf: lost 2 kernel event(s)"`) {
		t.Errorf("network stop: %s", last)
	}
}

func TestNetOutMustDifferFromOut(t *testing.T) {
	for _, o := range []options{{out: "-", netOut: "-"}, {out: "/tmp/x.jsonl", netOut: "/tmp/./x.jsonl"}} {
		r := newRig(t)
		if err := run(o, r.witnesses(), r.sig); err == nil || !strings.Contains(err.Error(), "different files") {
			t.Errorf("%+v: %v", o, err)
		}
		if r.ew.started || r.nw.started {
			t.Errorf("%+v: a witness started", o)
		}
	}
}
