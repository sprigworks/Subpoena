//go:build linux && (amd64 || arm64)

//subpoena:impl_derived
//subpoena:pure_logic

// The witness file contracts (docs/ports.md W3–W6) on real evidence: run the
// real subpoena-witness, with -net-out, against the real kernel; in one real
// session cgroup spawn processes and make two network attempts that reach no
// listener (a UDP send to 192.0.2.1:9, a TCP connect to a closed loopback
// port), in another do neither; and turn the two files it wrote into cases in
// the witness.yaml and witness-network.yaml formats: each file as written,
// and the same file damaged the ways a capture fails (killed before the stop
// record, a stop record reporting lost kernel events, cut mid-line, two
// windows). The expectations come from what the test did, not from a reader.
// The Go readers run the cases here; a port's readers run the same files
// (make test-witness-parity runs Python's), so a reader that only agrees with
// hand-written fixtures cannot pass.
//
// Needs root, BTF and a writable cgroup v2 hierarchy; it skips without them
// unless SUBPOENA_EBPF_REQUIRE=1 turns the skip into a failure. The cases are
// written to witness-capture.yaml and witness-network-capture.yaml in
// $SUBPOENA_WITNESS_CAPTURE_OUT when set.
package conformance

import (
	"bytes"
	"fmt"
	"net"
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

// netHelperEnv makes the test binary, re-executed inside session A's cgroup,
// make the network attempts and exit: a UDP send to 192.0.2.1:9 (TEST-NET-1,
// so nothing answers) and a TCP connect to the closed loopback port the
// variable names, refused at once. Neither goes through any sinkhole.
const netHelperEnv = "SUBPOENA_WITNESS_NET_HELPER"

func TestMain(m *testing.M) {
	if port := os.Getenv(netHelperEnv); port != "" {
		os.Exit(netHelper(port))
	}
	os.Exit(m.Run())
}

func netHelper(port string) int {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "net helper:", err)
		return 2
	}
	// The kernel hook runs before routing, so the attempt is seen even if
	// the send fails (no route).
	pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9})
	pc.Close()
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:"+port, 5*time.Second); err == nil {
		c.Close()
		fmt.Fprintln(os.Stderr, "net helper: the closed port accepted")
		return 3
	}
	return 0
}

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

type netCaptureCase struct {
	Name      string              `yaml:"name"`
	Lines     []string            `yaml:"lines"`
	ReadError string              `yaml:"read_error,omitempty"`
	Health    string              `yaml:"health,omitempty"`
	Dialed    map[string][]string `yaml:"dialed,omitempty"`
	NoDial    map[string]string   `yaml:"no_dial,omitempty"`
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

	logPath, netPath, ready := filepath.Join(tmp, "capture.jsonl"), filepath.Join(tmp, "network.jsonl"), filepath.Join(tmp, "ready")
	var stderr bytes.Buffer
	w := exec.Command(bin, "-cgroup-root", root, "-out", logPath, "-net-out", netPath, "-ready", ready)
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

	start := func(mk func() *exec.Cmd) int {
		var out bytes.Buffer
		cmd, placeErr, err := ga.Start(func() *exec.Cmd {
			c := mk()
			c.Stdout, c.Stderr = &out, &out
			return c
		})
		if err != nil || placeErr != nil {
			t.Fatalf("start %v: err=%v placeErr=%v", cmd, err, placeErr)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%v: %v\n%s", cmd, err, out.Bytes())
		}
		return cmd.Process.Pid
	}
	run := func(name string, args ...string) int {
		return start(func() *exec.Cmd { return exec.Command(name, args...) })
	}
	// A loopback port with no listener: bound, then closed.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pids := []int{run("true"), run("sleep", "0.01")}
	helper := start(func() *exec.Cmd {
		c := exec.Command(self)
		c.Env = append(os.Environ(), fmt.Sprintf("%s=%d", netHelperEnv, closedPort))
		return c
	})
	dests := []string{"192.0.2.1:9", fmt.Sprintf("127.0.0.1:%d", closedPort)}
	// The helper is an exec in session A too.
	pids = append(pids, helper)
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
	lines := nonEmpty(data)
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
	t.Run("exec", func(t *testing.T) { runWitnessCases(t, doc, len(cases)) })

	// The network file: start, the helper's two attempts in order, stop.
	netData, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatal(err)
	}
	nlines := nonEmpty(netData)
	if len(nlines) != 2+len(dests) || !strings.Contains(nlines[0], `"record":"start"`) ||
		!strings.Contains(nlines[len(nlines)-1], `"record":"stop"`) || !strings.Contains(nlines[len(nlines)-1], `"healthy":true`) {
		t.Fatalf("want start, %d attempts, healthy stop; the witness wrote:\n%s", len(dests), netData)
	}
	attempts := nlines[1 : len(nlines)-1]
	for i, op := range []string{"sendmsg", "connect"} {
		l := attempts[i]
		for _, want := range []string{`"op":"` + op + `"`, `"dest":"` + dests[i] + `"`, fmt.Sprintf(`"pid":%d,`, helper), `"trace_id":"` + captureTraceA + `"`} {
			if !strings.Contains(l, want) {
				t.Fatalf("attempt %d lacks %s: %s", i+1, want, l)
			}
		}
	}
	netStopLost := `{"time":"2026-11-01T00:00:00Z","record":"stop","healthy":false,"error":"netbpf: lost 1 kernel event(s)"}`
	dialed := map[string][]string{"A": dests, "B": {}}
	netCases := []netCaptureCase{
		{Name: "capture_healthy", Lines: nlines, Health: "ok", Dialed: dialed,
			NoDial: map[string]string{"A": "Fail", "B": "Pass"}},
		{Name: "capture_killed_before_stop", Lines: nlines[:len(nlines)-1], Health: "never stopped", Dialed: dialed,
			NoDial: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_attempts_only", Lines: attempts, Health: "no start or stop records", Dialed: dialed,
			NoDial: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_lost_events", Lines: join(nlines[:len(nlines)-1], []string{netStopLost}), Health: "lost 1 kernel event(s)",
			Dialed: dialed, NoDial: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_two_windows", Lines: join(nlines, nlines), Health: "2 capture windows",
			Dialed: map[string][]string{"A": join(dests, dests), "B": {}}, NoDial: map[string]string{"A": "Fail", "B": "Inconclusive"}},
		{Name: "capture_cut_mid_line", Lines: join(nlines[:1], []string{attempts[0][:len(attempts[0])/2]}, nlines[2:]), ReadError: "line 2"},
	}
	netDoc, err := yaml.Marshal(map[string]any{
		"traces": map[string]string{"A": captureTraceA, "B": captureTraceB},
		"cases":  netCases,
	})
	if err != nil {
		t.Fatal(err)
	}
	netDoc = append([]byte("# Written by TestKernelWitnessCapture from real subpoena-witness -net-out output; see witness-network.yaml for the format.\n"), netDoc...)
	if dir := os.Getenv("SUBPOENA_WITNESS_CAPTURE_OUT"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "witness-network-capture.yaml"), netDoc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("network", func(t *testing.T) { runWitnessNetworkCases(t, netDoc, len(netCases)) })
}

func nonEmpty(data []byte) []string {
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
