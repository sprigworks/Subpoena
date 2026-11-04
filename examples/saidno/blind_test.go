//go:build blind

//subpoena:spec_derived

package saidno_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"

	"github.com/sprigworks/subpoena/examples/saidno"
)

// blindRun runs a denied request while one witness has lost its view of /proc.
// A second, healthy witness confirms the command really ran.
func blindRun(t *testing.T) (*witness.ProcWitness, string) {
	t.Helper()
	link := filepath.Join(t.TempDir(), "proc")
	if err := os.Symlink("/proc", link); err != nil {
		t.Fatal(err)
	}
	h := harness.New()
	blind := &witness.ProcWitness{RootPID: os.Getpid(), ProcRoot: link}
	healthy := witness.NewProcWitness(os.Getpid())
	for _, w := range []*witness.ProcWitness{blind, healthy} {
		if err := w.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(w.Stop)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	g := saidno.New(h.Tracer("saidno-test"), slog.New(slog.DiscardHandler))

	g.Run(context.Background(), request("intern"))

	blind.Stop()
	healthy.Stop()
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := tr.TraceIDs()[0]
	if len(healthy.Spawned(id)) == 0 {
		t.Fatal("the healthy witness saw nothing, so this run doesn't show the bug")
	}
	return blind, id
}

// Reading the witness without its capture health: it saw nothing, so this passes.
func TestBlindNoHealthCheck(t *testing.T) {
	w, id := blindRun(t)
	if got := w.Spawned(id); len(got) != 0 {
		t.Fatalf("saw %v", got)
	}
}

// Subpoena's check: seeing nothing proves nothing unless capture was healthy.
func TestBlindHarnessCheck(t *testing.T) {
	w, id := blindRun(t)
	harness.RequireNoSpawn(t, w, id)
}
