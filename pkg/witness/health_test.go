//subpoena:impl_derived
//subpoena:pure_logic

package witness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcHealthPreservesFailedPolls(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proc")
	must(t, os.Mkdir(root, 0755))
	fakeChildren(t, root, 0)
	w := &ProcWitness{ProcRoot: root, Interval: time.Hour}
	if err := w.Health(); err == nil {
		t.Fatal("unstarted witness cannot certify absence")
	}
	must(t, w.Start())
	if err := w.Health(); err == nil {
		t.Fatal("running witness must finish capture first")
	}
	w.Stop()
	must(t, w.Health())
	// Drive two failed polls, then recover. Recovery must not erase the gap.
	must(t, os.RemoveAll(root))
	w.Poll()
	w.Poll()
	must(t, os.Mkdir(root, 0755))
	fakeChildren(t, root, 0)
	w.Poll()
	err := w.Health()
	if err == nil || !strings.Contains(err.Error(), "2 failed scan(s)") || !errors.Is(w.firstScanErr, os.ErrNotExist) {
		t.Fatalf("failed polls not retained: %v", err)
	}
	w.Stop()
	if w.Health() == nil {
		t.Fatal("repeated Stop erased the capture gap")
	}
	// An explicitly new capture starts a fresh observation window.
	must(t, w.Start())
	w.Stop()
	must(t, w.Health())
}

func TestProcHealthRecordsFinalPollFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proc")
	must(t, os.Mkdir(root, 0755))
	w := &ProcWitness{ProcRoot: root, Interval: time.Hour}
	must(t, w.Start())
	must(t, os.Remove(root))
	w.Stop()
	if err := w.Health(); err == nil {
		t.Fatal("final poll failure must invalidate absence")
	}
}

func TestProcStartFailureIsUnhealthy(t *testing.T) {
	w := &ProcWitness{ProcRoot: filepath.Join(t.TempDir(), "missing")}
	if err := w.Start(); err == nil {
		t.Fatal("want scan failure")
	}
	w.Stop()
	if err := w.Health(); err == nil {
		t.Fatal("failed Start cannot certify absence")
	}
}

func TestProcPartialScanCannotCertifyAbsence(t *testing.T) {
	w, root := freshFake(t, nil)
	fakeProc(t, root, 300, 100, "20", "child", "0::/")
	must(t, os.Mkdir(filepath.Join(root, "400"), 0755))
	must(t, os.WriteFile(filepath.Join(root, "400", "stat"), []byte("malformed"), 0644))
	w.Poll()
	if w.Health() == nil {
		t.Fatal("malformed proc entry silently skipped")
	}
	if got := w.Spawned(tid); len(got) != 1 || got[0].PID != 300 {
		t.Fatalf("partial scan lost a positive observation: %+v", got)
	}
}

// TestProcHealthFailsWithoutChildrenWalk: without CONFIG_PROC_CHILDREN the
// root's children lists do not exist, and only full scans see its
// descendants. A witness that blind must not certify absence.
func TestProcHealthFailsWithoutChildrenWalk(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 100, 1, "10", "gateway", "0::/")
	must(t, os.MkdirAll(filepath.Join(root, "100", "task", "100"), 0o755))
	w := &ProcWitness{ProcRoot: root, RootPID: 100, Interval: time.Hour}
	must(t, w.Start())
	w.Stop()
	if err := w.Health(); !errors.Is(err, ErrChildrenWalkUnavailable) {
		t.Fatalf("health = %v, want ErrChildrenWalkUnavailable", err)
	}

	// The same witness with the children list present is healthy, and a
	// fresh Start re-probes rather than keeping the old fault.
	fakeChildren(t, root, 100)
	must(t, w.Start())
	w.Stop()
	must(t, w.Health())
}

func TestProcHealthFailsWhenRootIsGone(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 100, 1, "10", "gateway", "0::/")
	w := &ProcWitness{ProcRoot: root, RootPID: 999, Interval: time.Hour}
	must(t, w.Start())
	w.Stop()
	if err := w.Health(); !errors.Is(err, ErrChildrenWalkUnavailable) {
		t.Fatalf("health = %v, want ErrChildrenWalkUnavailable", err)
	}
}
