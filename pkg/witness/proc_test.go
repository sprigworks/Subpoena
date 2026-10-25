//subpoena:impl_derived

package witness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const tid = "0123456789abcdef0123456789abcdef"
const otherTid = "fedcba9876543210fedcba9876543210"

// fakeProc writes a minimal procfs entry.
func fakeProc(t *testing.T, root string, pid, ppid int, start, cmdline, cgroup string) {
	t.Helper()
	d := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	// comm deliberately contains a space and parenthesis to exercise parsing.
	stat := strconv.Itoa(pid) + " (my (proc)) S " + strconv.Itoa(ppid) +
		" 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 " + start + " 0 0\n"
	must(t, os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "cmdline"), []byte(cmdline), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "cgroup"), []byte(cgroup), 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newFake(t *testing.T) (*ProcWitness, string) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "1", "init", "0::/")
	fakeProc(t, root, 100, 1, "10", "gateway", "0::/")
	fakeProc(t, root, 200, 1, "11", "unrelated", "0::/")
	w := &ProcWitness{ProcRoot: root, RootPID: 100}
	must(t, w.Start())
	t.Cleanup(w.Stop)
	return w, root
}

func TestFakeLineageOnly(t *testing.T) {
	w, root := newFake(t)
	w.Stop() // drive polling by hand for determinism
	w.mu.Lock()
	w.tracked = map[procKey]*ProcessEvent{}
	w.mu.Unlock()

	fakeProc(t, root, 300, 100, "20", "echo\x00hi\x00", "0::/") // child of gateway
	fakeProc(t, root, 301, 300, "21", "grandchild\x00", "0::/") // grandchild
	fakeProc(t, root, 302, 200, "22", "stranger\x00", "0::/")   // child of unrelated
	w.Poll()

	evs := w.Events()
	if len(evs) != 2 {
		t.Fatalf("want child+grandchild, got %+v", evs)
	}
	if evs[0].Command != "echo hi" || evs[0].PPID != 100 || evs[0].Attribution != ByLineage {
		t.Fatalf("unexpected first event %+v", evs[0])
	}
	if got := w.Spawned(tid); len(got) != 2 {
		t.Fatalf("lineage events are returned for any trace, got %d", len(got))
	}
}

func TestFakeBaselineExcluded(t *testing.T) {
	w, root := newFake(t)
	w.Stop()
	w.mu.Lock()
	w.tracked = map[procKey]*ProcessEvent{}
	w.mu.Unlock()
	// Pre-existing child of the gateway, present before Start.
	// (Added after Start in this fake, so recreate the witness to test baseline.)
	fakeProc(t, root, 400, 100, "30", "old\x00", "0::/")
	w2 := &ProcWitness{ProcRoot: root, RootPID: 100}
	must(t, w2.Start())
	defer w2.Stop()
	w2.Poll()
	if evs := w2.Events(); len(evs) != 0 {
		t.Fatalf("baseline process reported: %+v", evs)
	}
}

func TestFakePIDReuseIsNewProcess(t *testing.T) {
	w, root := newFake(t)
	w.Stop()
	w.mu.Lock()
	w.tracked = map[procKey]*ProcessEvent{}
	w.mu.Unlock()
	fakeProc(t, root, 500, 100, "40", "a\x00", "0::/")
	w.Poll()
	fakeProc(t, root, 500, 100, "41", "b\x00", "0::/") // same PID, new start time
	w.Poll()
	evs := w.Events()
	if len(evs) != 2 || evs[0].Command != "a" || evs[1].Command != "b" {
		t.Fatalf("PID reuse not handled: %+v", evs)
	}
}

func TestFakeCgroupCorrelation(t *testing.T) {
	w, root := newFake(t)
	w.Stop()
	w.mu.Lock()
	w.tracked = map[procKey]*ProcessEvent{}
	w.mu.Unlock()
	fakeProc(t, root, 600, 100, "50", "mine\x00", "0::/sessions/"+tid+"\n")
	fakeProc(t, root, 601, 100, "51", "theirs\x00", "0::/sessions/"+otherTid+"\n")
	fakeProc(t, root, 602, 100, "52", "plain\x00", "0::/\n")
	w.Poll()

	got := w.Spawned(tid)
	cmds := map[string]ProcessEvent{}
	for _, e := range got {
		cmds[e.Command] = e
	}
	if _, ok := cmds["theirs"]; ok {
		t.Fatal("process in another trace's cgroup must be excluded")
	}
	if e, ok := cmds["mine"]; !ok || e.Attribution != ByCgroup || e.TraceID != tid {
		t.Fatalf("cgroup-correlated event missing or mislabeled: %+v", cmds)
	}
	if e, ok := cmds["plain"]; !ok || e.Attribution != ByLineage {
		t.Fatalf("lineage-only event must be returned conservatively: %+v", cmds)
	}
	if len(w.Spawned(otherTid)) != 2 { // theirs + plain
		t.Fatalf("other trace sees %d", len(w.Spawned(otherTid)))
	}
}

func TestParseStat(t *testing.T) {
	ppid, start, ok := parseStat("12 (a b) c) S 7 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0\n")
	if !ok || ppid != 7 || start != "999" {
		t.Fatalf("got %d %q %v", ppid, start, ok)
	}
	if _, _, ok := parseStat("garbage"); ok {
		t.Fatal("garbage must not parse")
	}
}

// TestLiveProc exercises the real /proc: a child of this test process must be seen.
func TestLiveProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no procfs")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	w := NewProcWitness(os.Getpid())
	must(t, w.Start())
	defer w.Stop()

	cmd := exec.Command(sleep, "0.2")
	must(t, cmd.Start())
	defer cmd.Wait()

	deadline := time.Now().Add(2 * time.Second)
	// The first sighting can be the fork child still showing its parent's
	// command line; wait for a poll to observe the exec.
	for time.Now().Before(deadline) {
		if evs := w.Events(); len(evs) > 0 && evs[0].Command == sleep+" 0.2" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	evs := w.Spawned(tid)
	if len(evs) != 1 {
		t.Fatalf("want exactly the sleep child (pid %d), got %d events: %s", cmd.Process.Pid, len(evs), brief(evs))
	}
	if evs[0].PID != cmd.Process.Pid || evs[0].Command != sleep+" 0.2" || evs[0].Exe == "" || evs[0].PPID != os.Getpid() {
		t.Fatalf("unexpected event pid=%d ppid=%d exe=%q cmd=%q (want pid %d, me %d)", evs[0].PID, evs[0].PPID, evs[0].Exe, evs[0].Command, cmd.Process.Pid, os.Getpid())
	}
}

func TestStartTwiceFails(t *testing.T) {
	w, _ := newFake(t)
	if err := w.Start(); err == nil {
		t.Fatal("second Start must fail")
	}
}

func brief(evs []ProcessEvent) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "[pid=%d ppid=%d exe=%q cmd=%q] ", e.PID, e.PPID, e.Exe, e.Command)
	}
	return b.String()
}
