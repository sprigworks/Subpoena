//subpoena:spec_derived
//subpoena:pure_logic

// The -file-root mode, from docs/ports.md W7: the file another language reads.
package main

import (
	"os"
	"path/filepath"
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
