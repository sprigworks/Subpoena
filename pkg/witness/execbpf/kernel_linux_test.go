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
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/sprigworks/subpoena/pkg/cgroup"
	"github.com/sprigworks/subpoena/pkg/harness"
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

// A full ring buffer drops events in the kernel. The drops must surface:
// Stop reports them, Health keeps them, and an absence claim on the window is
// Inconclusive, not Pass. The buffer is shrunk to one page and the reader is
// held while a burst of execs runs, so reservations fail.
func TestRingBufferDropsMakeCaptureInconclusive(t *testing.T) {
	w := New(Config{})
	w.ringBytes = uint32(os.Getpagesize())
	w.holdReads = make(chan struct{})
	if err := w.Start(); err != nil {
		skipOrFail(t, "cannot load the eBPF program: %v", err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			close(w.holdReads)
		}
		w.Stop()
	})
	for i := 0; i < 200; i++ {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatal(err)
		}
	}
	close(w.holdReads)
	released = true
	err := w.Stop()
	if err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("200 execs into a one-page buffer with the reader held: want Stop to report lost events, got %v", err)
	}
	if h := w.Health(); h == nil || !strings.Contains(h.Error(), "lost") {
		t.Fatalf("Health must keep the loss, got %v", h)
	}
	if v, verr := harness.NoSpawn(w, "c0de0000000000000000000000000001"); v != harness.Inconclusive {
		t.Fatalf("absence over a lossy window: want Inconclusive, got %v (%v)", v, verr)
	}
}

// The helper process: forks a child into another cgroup, which runs true.
func TestMain(m *testing.M) {
	if dir := os.Getenv("EXECBPF_FORKOUT"); dir != "" {
		os.Exit(forkOut(dir))
	}
	os.Exit(m.Run())
}

func forkOut(dir string) int {
	fd, err := os.Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer fd.Close()
	c := exec.Command("true")
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if err := c.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// A task that leaves its session takes its execs with it, so nothing may read as
// absence afterwards, wherever it went.
func TestKernelALeavingTaskFailsHealth(t *testing.T) {
	leave := func(dir string) (string, []string) {
		return "sh", []string{"-c", "echo $$ > " + dir + "/cgroup.procs; exec true"}
	}
	for _, tc := range []struct {
		name string
		dir  func(g *cgroup.Group, root string) string
		fork bool
		want bool // Health fails
	}{
		{name: "moved to the session root", dir: func(_ *cgroup.Group, root string) string { return root }, want: true},
		{name: "moved above the root", dir: func(_ *cgroup.Group, root string) string { return filepath.Dir(root) }, want: true},
		{name: "moved to another session", dir: func(_ *cgroup.Group, root string) string { return filepath.Join(root, tidB) }, want: true},
		{name: "child made above the root", dir: func(_ *cgroup.Group, root string) string { return filepath.Dir(root) }, fork: true, want: true},
		{name: "moved within the session", dir: func(g *cgroup.Group, _ string) string { return filepath.Join(g.Dir(), "child") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, root := sessionGroup(t, tidA)
			nest(t, root, tidB)
			nest(t, g.Dir(), "child")
			w := start(t, Config{CgroupRoot: root})
			if tc.fork {
				cmd, placeErr, err := g.Start(func() *exec.Cmd {
					c := exec.Command(os.Args[0], "-test.run=^$")
					c.Env = append(os.Environ(), "EXECBPF_FORKOUT="+tc.dir(g, root))
					c.Stderr = os.Stderr
					return c
				})
				if err != nil || placeErr != nil {
					t.Fatalf("start: %v %v", err, placeErr)
				}
				if err := cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			} else {
				name, args := leave(tc.dir(g, root))
				run(t, g, name, args...)
			}
			err := w.Stop()
			v, verr := harness.NoSpawn(w, tidB+"0")
			if !tc.want {
				if err != nil || v != harness.Pass {
					t.Fatalf("a move inside the session: Stop=%v, verdict=%v (%v)", err, v, verr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "left a session") {
				t.Fatalf("Stop = %v", err)
			}
			if v != harness.Inconclusive {
				t.Fatalf("verdict = %v (%v), want Inconclusive", v, verr)
			}
		})
	}
}

// nest makes dir/names[0]/names[1]/... and returns the innermost.
func nest(t *testing.T, dir string, names ...string) string {
	t.Helper()
	for _, n := range names {
		dir = filepath.Join(dir, n)
		if err := os.Mkdir(dir, 0o755); err != nil {
			skipOrFail(t, "no nested cgroup: %v", err)
		}
		d := dir
		t.Cleanup(func() {
			for i := 0; i < 50 && os.Remove(d) != nil; i++ {
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
	return dir
}

func runIn(t *testing.T, dir string) {
	t.Helper()
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	c := exec.Command("true")
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
}

// The application owns everything below its session. However it nests, the exec
// stays the session's: past the 8 elements kept the session root must be what
// stays, and a path that ends like another session must change nothing.
func TestKernelNestingCannotMoveAnExec(t *testing.T) {
	levels := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "n"
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"a forged session within reach", []string{"a"}},
		{"a forged session past the path kept", []string{"a", "b", "c", "d", "e"}},
		{"far past the path kept", levels(14)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, root := sessionGroup(t, tidA)
			leaf := nest(t, g.Dir(), append(tc.extra, filepath.Base(root), tidB)...)
			w := start(t, Config{CgroupRoot: root})
			runIn(t, leaf)
			if err := w.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			if got := w.Spawned(tidB); len(got) != 0 {
				t.Fatalf("charged to the forged trace: %+v", got)
			}
			if got := w.Spawned(tidA); len(got) != 1 {
				t.Fatalf("Spawned for the real trace = %+v", got)
			}
		})
	}
	t.Run("too deep to walk", func(t *testing.T) {
		g, root := sessionGroup(t, tidA)
		leaf := nest(t, g.Dir(), levels(40)...)
		w := start(t, Config{CgroupRoot: root})
		runIn(t, leaf)
		if err := w.Stop(); err == nil || !strings.Contains(err.Error(), "too long to walk") {
			t.Fatalf("Stop = %v", err)
		}
		if v, err := harness.NoSpawn(w, tidA); v != harness.Inconclusive {
			t.Fatalf("verdict = %v (%v), want Inconclusive", v, err)
		}
	})
}
