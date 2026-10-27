//go:build linux && (amd64 || arm64)

//subpoena:impl_derived

// The real program in the real kernel. These tests need root (or CAP_BPF and
// CAP_PERFMON), BTF and a writable cgroup v2 hierarchy; they skip without them,
// unless SUBPOENA_EBPF_REQUIRE=1 (make test-ebpf) turns the skip into a
// failure. make test-ebpf runs them in a privileged container.
package execbpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sprigworks/subpoena/pkg/cgroup"
	"github.com/sprigworks/subpoena/pkg/witness"
)

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SUBPOENA_EBPF_REQUIRE") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// sessionGroup makes a real session cgroup for tid under a fresh root.
func sessionGroup(t *testing.T, tid string) (*cgroup.Group, string) {
	t.Helper()
	parent := os.Getenv("SUBPOENA_CGROUP_REAL_ROOT")
	if parent == "" {
		parent = "/sys/fs/cgroup"
	}
	root := fmt.Sprintf("%s/subpoena-ebpf-%d", parent, os.Getpid())
	g, err := (&cgroup.Manager{Root: root}).Create(tid)
	if err != nil || !g.Real() {
		skipOrFail(t, "no writable cgroup v2 hierarchy at %s: %v", parent, err)
	}
	t.Cleanup(func() {
		for i := 0; i < 50 && g.Remove() != nil; i++ {
			time.Sleep(20 * time.Millisecond)
		}
		os.Remove(root)
	})
	return g, root
}

func start(t *testing.T, cfg Config) *Witness {
	t.Helper()
	w := New(cfg)
	if err := w.Start(); err != nil {
		skipOrFail(t, "cannot load the eBPF program: %v", err)
	}
	t.Cleanup(func() { w.Stop() })
	return w
}

func run(t *testing.T, g *cgroup.Group, name string, args ...string) int {
	t.Helper()
	cmd, placeErr, err := g.Start(func() *exec.Cmd { return exec.Command(name, args...) })
	if err != nil || placeErr != nil {
		t.Fatalf("start %s: err=%v placeErr=%v", name, err, placeErr)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cmd.Process.Pid
}

// The kernel reports execs in a session cgroup with the trace, the cgroup ID
// pkg/cgroup computes, the executable and the arguments, including a process
// that exits at once (ProcWitness, which polls, can miss those).
func TestKernelAttributesExecsBySessionCgroup(t *testing.T) {
	g, root := sessionGroup(t, tidA)
	w := start(t, Config{CgroupRoot: root})

	sleepPID := run(t, g, "sleep", "0.05")
	truePID := run(t, g, "true")
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	id, err := g.ID()
	if err != nil {
		t.Fatal(err)
	}
	got := w.Spawned(tidA)
	if len(got) != 2 {
		t.Fatalf("Spawned = %+v, want the sleep and the true", got)
	}
	want := map[int]string{sleepPID: "sleep 0.05", truePID: "true"}
	for _, e := range got {
		if want[e.PID] != e.Command {
			t.Errorf("unexpected event %+v (want one of %v)", e, want)
		}
		if e.Attribution != witness.ByCgroup || e.TraceID != tidA {
			t.Errorf("not attributed by cgroup: %+v", e)
		}
		if e.CgroupID != id {
			t.Errorf("kernel cgroup ID %d != pkg/cgroup Group.ID() %d", e.CgroupID, id)
		}
		if !strings.HasSuffix(e.Cgroup, cgroup.RootBase(root)+"/"+tidA) {
			t.Errorf("cgroup path %q does not end in the session", e.Cgroup)
		}
		if base := e.Exe[strings.LastIndex(e.Exe, "/")+1:]; base != strings.Fields(e.Command)[0] {
			t.Errorf("exe %q does not match command %q", e.Exe, e.Command)
		}
		if e.PPID != os.Getpid() {
			t.Errorf("ppid %d, want the test process %d", e.PPID, os.Getpid())
		}
	}
	if other := w.Spawned(tidB); len(other) != 0 {
		t.Errorf("another trace sees this session's execs: %+v", other)
	}
}

// With a RootPID, a descendant outside any session cgroup is reported by
// lineage, through a fork that never execs (the shell's subshell).
func TestKernelLineageThroughForks(t *testing.T) {
	w := start(t, Config{CgroupRoot: "/nonexistent/subpoena", RootPID: os.Getpid()})
	cmd := exec.Command("sh", "-c", "(sleep 0.01; true) & wait")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var cmds []string
	for _, e := range w.Spawned(tidA) {
		if e.Attribution != witness.ByLineage {
			t.Errorf("want lineage: %+v", e)
		}
		cmds = append(cmds, e.Command)
	}
	joined := strings.Join(cmds, " | ")
	for _, want := range []string{"sh -c", "sleep 0.01", "true"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lineage missed %q; saw %s", want, joined)
		}
	}
}

// Stop delivers everything already in the ring buffer: a burst of execs right
// before Stop is not lost.
func TestStopDrainsTheRingBuffer(t *testing.T) {
	g, root := sessionGroup(t, tidB)
	w := start(t, Config{CgroupRoot: root})
	const n = 50
	for i := 0; i < n; i++ {
		run(t, g, "true")
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := len(w.Spawned(tidB)); got != n {
		t.Fatalf("saw %d of %d execs", got, n)
	}
}

func TestDecode(t *testing.T) {
	var r execEvent
	r.Kind, r.Pid, r.Ppid, r.HostPid, r.HostPpid, r.CgroupId = kindExec, 7, 1, 1007, 1001, 99
	copy8(r.Comm[:], "sleep")
	copy8(r.Filename[:], "/usr/bin/sleep")
	args := "sleep\x000.1\x00"
	copy8(r.Args[:], args)
	r.ArgsLen = uint32(len(args))
	copy8(r.Cgroup[0][:], tidA)
	copy8(r.Cgroup[1][:], "subpoena")
	copy8(r.Cgroup[2][:], "") // hierarchy root
	r.Depth = 3
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, &r); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1, 0)
	e, err := decode(buf.Bytes(), at)
	if err != nil {
		t.Fatal(err)
	}
	want := Event{Kind: KindExec, PID: 7, PPID: 1, HostPID: 1007, HostPPID: 1001, Comm: "sleep", Exe: "/usr/bin/sleep",
		Args: []string{"sleep", "0.1"}, CgroupID: 99, Cgroup: "subpoena/" + tidA, Time: at}
	if fmt.Sprintf("%+v", e) != fmt.Sprintf("%+v", want) {
		t.Fatalf("decode =\n %+v\nwant\n %+v", e, want)
	}
	if _, err := decode(buf.Bytes()[:10], at); err == nil {
		t.Fatal("short record must fail")
	}
	r.Kind = 9
	buf.Reset()
	binary.Write(&buf, binary.NativeEndian, &r)
	if _, err := decode(buf.Bytes(), at); err == nil {
		t.Fatal("unknown kind must fail")
	}
}

func copy8(dst []int8, s string) {
	for i := 0; i < len(s) && i < len(dst); i++ {
		dst[i] = int8(s[i])
	}
}

// Exercise the real per-CPU map ABI and Stop's final read on a privileged host.
func TestKernelLossCounterInvalidatesCapture(t *testing.T) {
	w := start(t, Config{})
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	counts := make([]uint64, cpus)
	counts[0] = 3
	if cpus > 1 {
		counts[cpus-1] = 4
	}
	if err := w.k.objs.Lost.Put(uint32(0), counts); err != nil {
		t.Fatal(err)
	}
	if err := w.Stop(); err == nil {
		t.Fatal("kernel loss must fail Stop")
	}
	if err := w.Health(); err == nil {
		t.Fatal("kernel loss must persist in Health")
	}
}
