//subpoena:impl_derived
//subpoena:pure_logic

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

func TestRunDBWritesACaptureWindow(t *testing.T) {
	dir := t.TempDir()
	out, ready := filepath.Join(dir, "w.jsonl"), filepath.Join(dir, "ready")
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- runDB([]string{"-engine", "postgres", "-upstream", "127.0.0.1:1", "-out", out, "-ready", ready}, stop)
	}()
	var addr []byte
	for deadline := time.Now().Add(5 * time.Second); len(addr) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
		addr, _ = os.ReadFile(ready)
	}
	if !strings.HasPrefix(string(addr), "127.0.0.1:") {
		t.Fatalf("ready file: %q", addr)
	}
	stop <- syscall.SIGTERM
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	l, err := witness.ReadLog(f)
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireNoRow(t, l, "trace", "users")
	if !l.CapturedRows() || l.CapturedExecs() || l.CapturedFiles() || l.CapturedDeliveries() {
		t.Fatal("the database witness's file must name row, and only row")
	}
}

func TestRunDBRefusesBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-engine", "oracle", "-upstream", "x:1", "-out", filepath.Join(t.TempDir(), "w")},
		{"-engine", "postgres", "-out", filepath.Join(t.TempDir(), "w")},
		{"-engine", "postgres", "-upstream", "x:1", "-listen", "nonsense"},
	} {
		if err := runDB(args, nil); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
