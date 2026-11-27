//go:build linux && (amd64 || arm64)

//subpoena:impl_derived
//subpoena:pure_logic

// The witness file contract (docs/ports.md W3–W5) on real evidence: run the
// real subpoena-witness against the real kernel, spawn processes in one real
// session cgroup and none in another, and turn the file it wrote into cases in
// the witness.yaml format: the file as written, and the same file damaged the
// ways a capture fails (killed before the stop record, a stop record reporting
// lost kernel events, cut mid-line, two windows). The expectations come from what the test did, not
// from a reader. The Go reader runs the cases here; a port's reader runs the
// same file (make test-witness-parity runs Python's), so a reader that only
// agrees with hand-written fixtures cannot pass.
//
// Needs root, BTF and a writable cgroup v2 hierarchy; it skips without them
// unless SUBPOENA_EBPF_REQUIRE=1 turns the skip into a failure. The cases are
// written to $SUBPOENA_WITNESS_CAPTURE_OUT/witness-capture.yaml when set.
package conformance

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sprigworks/subpoena/pkg/cgroup"
)

const (
	captureTraceA = "ca97000000000000000000000000a1a1" // spawns
	captureTraceB = "ca97000000000000000000000000b2b2" // spawns nothing
)

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SUBPOENA_EBPF_REQUIRE") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

type captureCase struct {
	Name      string            `yaml:"name"`
	Lines     []string          `yaml:"lines"`
	ReadError string            `yaml:"read_error,omitempty"`
	Health    string            `yaml:"health,omitempty"`
	Spawned   map[string][]int  `yaml:"spawned,omitempty"`
	NoSpawn   map[string]string `yaml:"no_spawn,omitempty"`
}

func TestKernelWitnessCapture(t *testing.T) {
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root to load the eBPF program")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "subpoena-witness")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "../cmd/subpoena-witness").CombinedOutput(); err != nil {
		t.Fatalf("build subpoena-witness: %v\n%s", err, out)
	}

	parent := os.Getenv("SUBPOENA_CGROUP_REAL_ROOT")
	if parent == "" {
		parent = "/sys/fs/cgroup"
	}
	root := fmt.Sprintf("%s/subpoena-capture-%d", parent, os.Getpid())
	m := &cgroup.Manager{Root: root}
	var groups []*cgroup.Group
	t.Cleanup(func() {
		for _, g := range groups {
			for i := 0; i < 50 && g.Remove() != nil; i++ {
				time.Sleep(20 * time.Millisecond)
			}
		}
		os.Remove(root)
	})
	session := func(tid string) *cgroup.Group {
		g, err := m.Create(tid)
		if err != nil || !g.Real() {
			skipOrFail(t, "no writable cgroup v2 hierarchy at %s: %v", parent, err)
		}
		groups = append(groups, g)
		return g
	}
	ga := session(captureTraceA)
	session(captureTraceB)

	logPath, ready := filepath.Join(tmp, "capture.jsonl"), filepath.Join(tmp, "ready")
	var stderr bytes.Buffer
	w := exec.Command(bin, "-cgroup-root", root, "-out", logPath, "-ready", ready)
	w.Stderr = &stderr
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- w.Wait() }()
	t.Cleanup(func() { w.Process.Kill() })
	deadline := time.After(20 * time.Second)
	for attached := false; !attached; {
		select {
		case err := <-exited:
			skipOrFail(t, "subpoena-witness exited before attaching: %v\n%s", err, stderr.String())
		case <-deadline:
			t.Fatalf("subpoena-witness did not attach in 20s\n%s", stderr.String())
		case <-time.After(20 * time.Millisecond):
			_, err := os.Stat(ready)
			attached = err == nil
		}
	}

	run := func(name string, args ...string) int {
		cmd, placeErr, err := ga.Start(func() *exec.Cmd { return exec.Command(name, args...) })
		if err != nil || placeErr != nil {
			t.Fatalf("start %s: err=%v placeErr=%v", name, err, placeErr)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return cmd.Process.Pid
	}
	pids := []int{run("true"), run("sleep", "0.01")}
	if err := exec.Command("true").Run(); err != nil { // outside any session: not written
		t.Fatal(err)
	}

	if err := w.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("subpoena-witness: %v\n%s", err, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("subpoena-witness did not stop in 20s\n%s", stderr.String())
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	// start, one line per exec in session A, stop. Checked on the raw file
	// so the cases below cannot rest on a reader's interpretation.
	if len(lines) != 2+len(pids) || !strings.Contains(lines[0], `"record":"start"`) ||
		!strings.Contains(lines[len(lines)-1], `"record":"stop"`) || !strings.Contains(lines[len(lines)-1], `"healthy":true`) {
		t.Fatalf("want start, %d execs, healthy stop (an exec missing from the session may mean the kernel lacks CLONE_INTO_CGROUP, so pkg/cgroup placed it after exec); the witness wrote:\n%s", len(pids), data)
	}
	execs := lines[1 : len(lines)-1]
	for i, l := range execs {
		if !strings.Contains(l, fmt.Sprintf(`"pid":%d,`, pids[i])) || !strings.Contains(l, `"trace_id":"`+captureTraceA+`"`) {
			t.Fatalf("exec line %d is not pid %d in trace A: %s", i+1, pids[i], l)
		}
	}

	stopLost := `{"time":"2026-11-01T00:00:00Z","record":"stop","healthy":false,"error":"execbpf: lost 1 kernel event(s)"}`
	join := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	spawned := map[string][]int{"A": pids, "B": {}}
	cases := []captureCase{
		{Name: "capture_healthy", Lines: lines, Health: "ok", Spawned: spawned,
			NoSpawn: map[string]string{"A": "Fail", "B": "Pass"}},
		{Name: "capture_killed_before_stop", Lines: lines[:len(lines)-1], Health: "never stopped", Spawned: spawned,
			NoSpawn: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_execs_only", Lines: execs, Health: "no start or stop records", Spawned: spawned,
			NoSpawn: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_lost_events", Lines: join(lines[:len(lines)-1], []string{stopLost}), Health: "lost 1 kernel event(s)",
			Spawned: spawned, NoSpawn: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_two_windows", Lines: join(lines, lines), Health: "2 capture windows",
			NoSpawn: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_cut_mid_line", Lines: join(lines[:1], []string{execs[0][:len(execs[0])/2]}, lines[2:]), ReadError: "line 2"},
	}
	doc, err := yaml.Marshal(map[string]any{
		"traces": map[string]string{"A": captureTraceA, "B": captureTraceB},
		"cases":  cases,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc = append([]byte("# Written by TestKernelWitnessCapture from real subpoena-witness output; see witness.yaml for the format.\n"), doc...)
	if dir := os.Getenv("SUBPOENA_WITNESS_CAPTURE_OUT"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "witness-capture.yaml"), doc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runWitnessCases(t, doc, len(cases))
}
