//subpoena:impl_derived

package witness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/cgroup"
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

// ---- cgroup-preferred correlation ----

const sessionBase = "subpoena"

func session(id string) string { return "0::/" + sessionBase + "/" + id + "\n" }

func freshFake(t *testing.T, mutate func(w *ProcWitness)) (*ProcWitness, string) {
	t.Helper()
	w, root := newFake(t)
	w.Stop()
	if mutate != nil {
		mutate(w)
	}
	w.mu.Lock()
	w.tracked = map[procKey]*ProcessEvent{}
	w.mu.Unlock()
	return w, root
}

func byCmd(evs []ProcessEvent) map[string]ProcessEvent {
	m := map[string]ProcessEvent{}
	for _, e := range evs {
		m[e.Command] = e
	}
	return m
}

func TestSessionCgroupBeatsLineage(t *testing.T) {
	w, root := freshFake(t, func(w *ProcWitness) { w.CgroupRoot = "/sys/fs/cgroup/" + sessionBase })
	fakeProc(t, root, 700, 100, "60", "inside\x00", session(tid))         // descendant, in the session cgroup
	fakeProc(t, root, 701, 100, "61", "elsewhere\x00", session(otherTid)) // descendant, in another session
	fakeProc(t, root, 702, 100, "62", "outside\x00", "0::/\n")            // descendant, no session cgroup
	// Reparented to init, so lineage cannot see it; the cgroup still can.
	fakeProc(t, root, 703, 1, "63", "escaped\x00", session(tid))
	// Not a descendant and in no session cgroup: not ours.
	fakeProc(t, root, 704, 1, "64", "stranger\x00", "0::/\n")
	w.Poll()

	all := byCmd(w.Events())
	if _, seen := all["stranger"]; seen {
		t.Fatal("a process in neither lineage nor a session cgroup must not be reported")
	}
	if e, ok := all["escaped"]; !ok || e.Attribution != ByCgroup || e.TraceID != tid {
		t.Fatalf("reparented process in the session cgroup must be found by cgroup: %+v", all["escaped"])
	}

	got := byCmd(w.Spawned(tid))
	if e, ok := got["inside"]; !ok || e.Attribution != ByCgroup || e.TraceID != tid {
		t.Fatalf("inside: %+v", got)
	}
	if _, ok := got["escaped"]; !ok {
		t.Fatalf("escaped missing for its own trace: %v", got)
	}
	if _, ok := got["elsewhere"]; ok {
		t.Fatal("another session's process leaked into this trace")
	}
	if e, ok := got["outside"]; !ok || e.Attribution != ByLineage {
		t.Fatalf("lineage-only descendant must still be returned (an absence claim must not pass on a gap): %+v", got)
	}

	other := byCmd(w.Spawned(otherTid))
	if _, ok := other["elsewhere"]; !ok {
		t.Fatalf("other trace lost its own process: %v", other)
	}
	if _, ok := other["inside"]; ok {
		t.Fatal("this trace's process leaked into another")
	}
}

func TestLineageFallbackWithoutAnySessionCgroup(t *testing.T) {
	w, root := freshFake(t, nil)
	fakeProc(t, root, 710, 100, "70", "plain\x00", "0::/\n")
	w.Poll()
	evs := w.Spawned(tid)
	if len(evs) != 1 || evs[0].Attribution != ByLineage || evs[0].TraceID != "" {
		t.Fatalf("fallback broken: %+v", evs)
	}
}

func TestProcessMovedIntoSessionCgroupIsReattributed(t *testing.T) {
	w, root := freshFake(t, nil)
	fakeProc(t, root, 720, 100, "80", "late\x00", "0::/\n")
	w.Poll()
	if e := w.Events()[0]; e.Attribution != ByLineage {
		t.Fatalf("first sighting: %+v", e)
	}
	// The fallback placement path writes the PID after start.
	must(t, os.WriteFile(filepath.Join(root, "720", "cgroup"), []byte(session(otherTid)), 0o644))
	w.Poll()
	if e := w.Events()[0]; e.Attribution != ByCgroup || e.TraceID != otherTid {
		t.Fatalf("after the move: %+v", e)
	}
	if len(w.Spawned(tid)) != 0 {
		t.Fatal("process now belongs to another trace")
	}
}

func TestCgroupRootBaseComesFromFieldOrEnvironment(t *testing.T) {
	w, root := freshFake(t, func(w *ProcWitness) { w.CgroupRoot = "/custom/lab" })
	fakeProc(t, root, 730, 1, "90", "lab\x00", "0::/lab/"+tid+"\n")
	fakeProc(t, root, 731, 1, "91", "default\x00", session(tid)) // "subpoena" is not this witness's base
	w.Poll()
	if got := byCmd(w.Events()); len(got) != 1 || got["lab"].TraceID != tid {
		t.Fatalf("field base: %+v", got)
	}

	t.Setenv(cgroup.EnvRoot, "/x/envbase")
	w2, root2 := freshFake(t, nil)
	fakeProc(t, root2, 740, 1, "92", "envproc\x00", "0::/envbase/"+tid+"\n")
	w2.Poll()
	if got := byCmd(w2.Events()); got["envproc"].TraceID != tid {
		t.Fatalf("env base: %+v", got)
	}
}

// ---- a process that exits before the scan finishes ----

// TestProcessReapedDuringScanKeepsItsDetails: with thousands of processes (and
// the race detector) one scan of /proc can outlast a short-lived child. Its
// stat is read mid-scan; if cmdline, exe and cgroup are read only after the
// scan, the child is already gone and the event is left with Command "". The
// details must be read when the process is first seen.
func TestProcessReapedDuringScanKeepsItsDetails(t *testing.T) {
	w, root := freshFake(t, func(w *ProcWitness) { w.CgroupRoot = "/sys/fs/cgroup/" + sessionBase })
	fakeProc(t, root, 800, 100, "100", "/bin/sleep\x000.15\x00", session(tid))
	must(t, os.Symlink("/bin/sleep", filepath.Join(root, "800", "exe")))
	w.afterScan = func() { must(t, os.RemoveAll(filepath.Join(root, "800"))) }
	w.Poll()

	evs := w.Spawned(tid)
	if len(evs) != 1 {
		t.Fatalf("a process seen must not be dropped: %s", brief(evs))
	}
	e := evs[0]
	if e.Command != "/bin/sleep 0.15" || e.Exe != "/bin/sleep" || e.Attribution != ByCgroup || e.TraceID != tid {
		t.Fatalf("details lost to the exit: %+v", e)
	}
}

// TestForkChildIsUpdatedOnExec: a child first seen between fork and exec shows
// its parent's command line; a later poll that sees the exec must replace it,
// and a poll after the exit must not erase what was seen.
func TestForkChildIsUpdatedOnExec(t *testing.T) {
	w, root := freshFake(t, nil)
	fakeProc(t, root, 810, 100, "110", "gateway\x00", "0::/\n")
	w.Poll()
	must(t, os.WriteFile(filepath.Join(root, "810", "cmdline"), []byte("/bin/sleep\x000.15\x00"), 0o644))
	must(t, os.Symlink("/bin/sleep", filepath.Join(root, "810", "exe")))
	w.Poll()
	// Exited but not yet reaped: a zombie has an empty cmdline and no exe.
	must(t, os.WriteFile(filepath.Join(root, "810", "cmdline"), nil, 0o644))
	must(t, os.Remove(filepath.Join(root, "810", "exe")))
	w.Poll()

	evs := w.Events()
	if len(evs) != 1 || evs[0].Command != "/bin/sleep 0.15" || evs[0].Exe != "/bin/sleep" {
		t.Fatalf("exec not recorded, or erased by the exit: %s", brief(evs))
	}
}

// ---- the children fast path ----

// fakeChildren writes /proc/<pid>/task/<pid>/children.
func fakeChildren(t *testing.T, root string, pid int, kids ...int) {
	t.Helper()
	d := filepath.Join(root, strconv.Itoa(pid), "task", strconv.Itoa(pid))
	must(t, os.MkdirAll(d, 0o755))
	var b strings.Builder
	for _, k := range kids {
		fmt.Fprintf(&b, "%d ", k)
	}
	must(t, os.WriteFile(filepath.Join(d, "children"), []byte(b.String()), 0o644))
}

// TestChildSeenWhileFullScanStalls: on a busy machine one scan of /proc can
// take longer than a short-lived child lives, so the child starts and is
// reaped between two scans. The root's children must still be noticed every
// tick, independently of the full scan.
func TestChildSeenWhileFullScanStalls(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "1", "init", "0::/")
	fakeProc(t, root, 100, 1, "10", "gateway", "0::/")
	fakeChildren(t, root, 100)
	scanning := make(chan struct{}, 1)
	release := make(chan struct{})
	w := &ProcWitness{ProcRoot: root, RootPID: 100, Interval: time.Millisecond}
	w.afterScan = func() {
		select {
		case scanning <- struct{}{}:
		default:
		}
		<-release
	}
	must(t, w.Start())
	<-scanning // the first scan saw no child and is now stalled

	fakeProc(t, root, 900, 100, "200", "/bin/sleep\x000.15\x00", "0::/")
	must(t, os.Symlink("/bin/sleep", filepath.Join(root, "900", "exe")))
	fakeProc(t, root, 901, 900, "201", "grandchild\x00", "0::/")
	fakeChildren(t, root, 900, 901)
	fakeChildren(t, root, 100, 900)
	deadline := time.Now().Add(2 * time.Second)
	for len(w.Events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// Reaped before the stalled scan ends.
	fakeChildren(t, root, 100)
	must(t, os.RemoveAll(filepath.Join(root, "900")))
	must(t, os.RemoveAll(filepath.Join(root, "901")))
	close(release)
	w.Stop()

	got := byCmd(w.Spawned(tid))
	if e, ok := got["/bin/sleep 0.15"]; !ok || e.PPID != 100 || e.Exe != "/bin/sleep" {
		t.Fatalf("child missed while the full scan stalled: %s", brief(w.Events()))
	}
	if e, ok := got["grandchild"]; !ok || e.PPID != 900 {
		t.Fatalf("grandchild missed: %s", brief(w.Events()))
	}
	if len(got) != 2 {
		t.Fatalf("want child and grandchild only: %s", brief(w.Events()))
	}
}

// TestChildrenPathSkipsBaselineButWalksThroughIt: a process that existed at
// Start is never reported, but a new child of it is.
func TestChildrenPathSkipsBaselineButWalksThroughIt(t *testing.T) {
	w, root := freshFake(t, nil)
	fakeProc(t, root, 910, 100, "5", "old\x00", "0::/") // start time before Start's baseline
	w.mu.Lock()
	w.baseline[procKey{910, "5"}] = true
	w.mu.Unlock()
	fakeProc(t, root, 911, 910, "210", "new\x00", "0::/")
	fakeChildren(t, root, 100, 910)
	fakeChildren(t, root, 910, 911)
	w.pollChildren()
	if got := byCmd(w.Events()); len(got) != 1 || got["new"].PID != 911 {
		t.Fatalf("got %s", brief(w.Events()))
	}
}

// A /proc large enough to be split across readers must give the result a
// serial scan would: lineage that crosses chunks is still followed, a stat
// longer than the read buffer still parses, and the reported fault is the
// first one in listing order.
func TestParallelScanMatchesSerialScan(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	w, root := freshFake(t, nil)
	for pid := 1000; pid < 1000+4*scanChunk; pid++ {
		fakeProc(t, root, pid, 1, strconv.Itoa(pid), "stranger\x00", "0::/")
	}
	fakeProc(t, root, 1010, 100, "1010", "child\x00", "0::/")
	fakeProc(t, root, 1990, 1010, "1990", "grandchild\x00", "0::/")
	long := filepath.Join(root, "1995")
	must(t, os.WriteFile(filepath.Join(long, "stat"), []byte("1995 ("+strings.Repeat("x", 3000)+") S 100"+
		" 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 1995 0 0\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(long, "cmdline"), []byte("long\x00"), 0o644))
	for _, pid := range []string{"1900", "1200"} {
		must(t, os.WriteFile(filepath.Join(root, pid, "stat"), []byte("malformed"), 0o644))
	}
	w.Poll()
	got := byCmd(w.Events())
	if len(got) != 3 || got["child"].PID != 1010 || got["grandchild"].PID != 1990 || got["long"].PID != 1995 {
		t.Fatalf("got %s", brief(w.Events()))
	}
	if err := w.Health(); err == nil || !strings.Contains(err.Error(), "PID 1200") {
		t.Fatalf("want the first fault in listing order (PID 1200), got %v", err)
	}
}

// Coverage counts both pollers and reports the longest gap between full
// scans: the window in which a process outside the children tree can slip by.
func TestCoverageReportsFullScanGap(t *testing.T) {
	w, _ := freshFake(t, nil)
	before := w.Coverage()
	if before.FullScans == 0 || before.ChildrenWalks == 0 {
		t.Fatalf("Start and Stop poll with both pollers; got %+v", before)
	}
	w.Poll()
	time.Sleep(30 * time.Millisecond)
	w.Poll()
	w.pollChildren()
	got := w.Coverage()
	if got.FullScans != before.FullScans+2 || got.ChildrenWalks != before.ChildrenWalks+1 {
		t.Fatalf("want 2 more full scans and 1 more walk than %+v, got %+v", before, got)
	}
	if got.MaxFullScanGap < 30*time.Millisecond {
		t.Fatalf("a 30ms pause between full scans must show in MaxFullScanGap, got %v", got.MaxFullScanGap)
	}
}

// Scans that fail after the last good one leave its window open until Stop:
// Coverage must count it, though no later scan closed it.
func TestCoverageCountsTheWindowLeftOpenByFailedScans(t *testing.T) {
	w, root := freshFake(t, func(w *ProcWitness) { w.Interval = time.Hour })
	must(t, w.Start())
	must(t, os.Rename(root, root+".gone"))
	defer os.Rename(root+".gone", root)
	time.Sleep(50 * time.Millisecond)
	w.Poll()
	w.Stop()
	if c := w.Coverage(); c.MaxFullScanGap < 50*time.Millisecond {
		t.Fatalf("a 50ms window closed by no scan must show in MaxFullScanGap, got %+v", c)
	}
}

// A new Start resets coverage.
func TestCoverageResetsOnStart(t *testing.T) {
	w, _ := freshFake(t, nil)
	for i := 0; i < 100; i++ {
		w.Poll()
	}
	must(t, w.Start())
	w.Stop()
	if c := w.Coverage(); c.FullScans >= 100 {
		t.Fatalf("coverage carried over from the previous capture: %+v", c)
	}
}
