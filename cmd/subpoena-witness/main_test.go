//subpoena:spec_derived
//subpoena:pure_logic

// The -file-root mode, from docs/ports.md W7: the file another language reads.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

func TestFileRootWritesAFileAReaderTrusts(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	out, ready := filepath.Join(dir, "events"), filepath.Join(dir, "ready")
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- runFiles([]string{root}, out, ready, stop) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never attached")
		}
		time.Sleep(time.Millisecond)
	}
	made := filepath.Join(root, "made")
	if err := os.WriteFile(made, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	stop <- os.Interrupt
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	log, err := witness.ReadLog(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	got := log.Wrote("any")
	if len(got) == 0 || got[0].Path != made || got[0].Op != witness.FileCreate {
		t.Fatalf("events %+v", got)
	}
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatal("the ready file must go with the witness")
	}
	if !log.CapturedFiles() || log.CapturedExecs() || log.CapturedRows() || log.CapturedDeliveries() {
		t.Fatal("the file witness's file must name file, and only file")
	}
	if v, err := harness.NoSpawn(log, "c0de00000000000000000000000000a1"); v != harness.Inconclusive {
		t.Fatalf("NoSpawn over a file witness's file = %v (%v), want Inconclusive", v, err)
	}
}

// Round 2 review 6, M5: the file as a SIGKILL would leave it, in a run after a
// clean one. While the witness runs the second window is open, so what is read
// then is what a killed witness leaves.
func TestAKilledRunNeverLeavesAFileThatReadsHealthy(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	out, ready := filepath.Join(dir, "events"), filepath.Join(dir, "ready")
	run := func() (stop chan os.Signal, done chan error) {
		stop, done = make(chan os.Signal, 1), make(chan error, 1)
		go func() { done <- runFiles([]string{root}, out, ready, stop) }()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				return stop, done
			}
			if time.Now().After(deadline) {
				t.Fatal("never attached")
			}
			time.Sleep(time.Millisecond)
		}
	}
	stop, done := run()
	stop <- os.Interrupt
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stop, done = run()
	defer func() {
		stop <- os.Interrupt
		<-done
	}()
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	log, err := witness.ReadLog(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Health(); err == nil || !strings.Contains(err.Error(), "still open") && !strings.Contains(err.Error(), "never stopped") {
		t.Fatalf("Health = %v, want the open window", err)
	}
}

func TestAnUnwritableOutIsRefusedBeforeTheWitnessIsReady(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	ready := filepath.Join(dir, "ready")
	stop := make(chan os.Signal)
	done := make(chan error, 1)
	go func() { done <- runFiles([]string{root}, filepath.Join(dir, "no", "such", "dir"), ready, stop) }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the witness ran with nowhere to write")
	}
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatal("it said it was ready")
	}
}

// A witness that writes its output inside a root sees its own file, and a claim
// about the root reads that as a change.
func TestOwnFileUnderAWatchedRootIsRefused(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(elsewhere, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(elsewhere, "file")
	if err := os.Symlink(filepath.Join(root, "real"), fileLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ out, ready string }{
		"out in the root":       {out: filepath.Join(root, "w.jsonl")},
		"out below the root":    {out: filepath.Join(sub, "w.jsonl")},
		"out through a symlink": {out: filepath.Join(link, "w.jsonl")},
		"out a symlink into it": {out: fileLink},
		"ready in the root":     {out: filepath.Join(elsewhere, "w.jsonl"), ready: filepath.Join(root, "ready")},
		"out spelled with a ..": {out: filepath.Join(sub, "..", "w.jsonl")},
	} {
		t.Run(name, func(t *testing.T) {
			stop := make(chan os.Signal, 1)
			stop <- os.Interrupt
			err := runFiles([]string{root}, tc.out, tc.ready, stop)
			if err == nil || !strings.Contains(err.Error(), "its own file") {
				t.Fatalf("runFiles = %v", err)
			}
		})
	}
	beside := filepath.Join(elsewhere, "w.jsonl")
	os.Remove(beside)
	if err := ownFileWatched([]string{root}, beside, "", "-"); err != nil {
		t.Fatalf("a file outside the root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "w.jsonl")); !os.IsNotExist(err) {
		t.Fatal("a refused run must not have made its file")
	}
}

// Review 7 L2: a consumer that stops reading must not hold -file-root past SIGTERM.
func TestFileRootDoesNotHangOnAStalledOutput(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	fifo, ready := filepath.Join(dir, "fifo"), filepath.Join(dir, "ready")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Held open and never read: the pipe fills and the writer blocks.
	hold, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- runFiles([]string{root}, fifo, ready, stop) }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never attached")
		}
	}
	for i := 0; i < 4000; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-with-a-long-enough-name-%d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stop <- syscall.SIGTERM
	select {
	case err := <-done:
		if !errors.Is(err, errStalled) {
			t.Fatalf("runFiles = %v, want a stall", err)
		}
	case <-time.After(3*stallLimit + 5*time.Second):
		t.Fatal("still running after SIGTERM with the output stalled")
	}
}
