//subpoena:impl_derived
//subpoena:pure_logic

// FileWatch.WriteLog through ReadLog, written after the implementation.
// conformance/witness.yaml holds the reader's cases.
package witness

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A capture written by WriteLog reads back as the same claim: events, roots,
// health, and the coverage note.
func TestFileWatchLogRoundTrips(t *testing.T) {
	root := t.TempDir()
	w, err := NewFileWatch(root)
	if err != nil {
		t.Fatal(err)
	}
	var early bytes.Buffer
	if err := w.WriteLog(&early); err == nil {
		t.Fatal("a running capture has no stop record to write")
	}
	f := filepath.Join(root, "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f, f+"2"); err != nil {
		t.Fatal(err)
	}
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := w.WriteLog(&b); err != nil {
		t.Fatal(err)
	}
	log, err := ReadLog(&b)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !log.Covers(f) || log.Covers(root+"-sibling") || log.Covers("relative") {
		t.Fatal("Covers")
	}
	if log.Coverage() == "" {
		t.Fatal("no coverage note")
	}
	got, want := log.Wrote("any"), w.Wrote("any")
	if len(got) != len(want) {
		t.Fatalf("%d events, want %d", len(got), len(want))
	}
	for i := range got {
		if !got[i].SeenAt.Equal(want[i].SeenAt) {
			t.Fatalf("event %d: %v, %v", i, got[i].SeenAt, want[i].SeenAt)
		}
		got[i].SeenAt, want[i].SeenAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Fatalf("event %d:\n %+v\n %+v", i, got[i], want[i])
		}
	}
}

// A gap travels with the file.
func TestAnUnhealthyCaptureWritesAnUnhealthyStop(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := NewFileWatch(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	var b bytes.Buffer
	if err := w.WriteLog(&b); err != nil {
		t.Fatal(err)
	}
	log, err := ReadLog(&b)
	if err != nil {
		t.Fatal(err)
	}
	if h := log.Health(); h == nil || !strings.Contains(h.Error(), string(GapRoot)) {
		t.Fatalf("Health = %v", h)
	}
}
