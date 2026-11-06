//subpoena:spec_derived
//subpoena:pure_logic

// The -file-root mode, from docs/ports.md W7: the file another language reads.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
