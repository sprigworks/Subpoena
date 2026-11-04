//subpoena:spec_derived

package saidno_test

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"

	"github.com/sprigworks/subpoena/examples/saidno"
)

// The witness suite asks something other than the gateway: a process observer
// the gateway doesn't control.
func TestWitnessDeniedRequestRunsNothing(t *testing.T) {
	h := harness.New()
	w := witness.NewProcWitness(os.Getpid())
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	harness.WatchSpawns(t, w, "", harness.SpawnRule{Never: []string{tool}})
	g := saidno.New(h.Tracer("saidno-test"), slog.New(slog.DiscardHandler))

	resp := g.Run(context.Background(), request("intern"))

	w.Stop()
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireNoSpawn(t, w, tr.TraceIDs()[0])
	if resp.Status != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.Status)
	}
}

// Control: an allowed request runs and the witness sees it, so the absence
// above is not vacuous.
func TestWitnessAllowedRequestIsSeen(t *testing.T) {
	h := harness.New()
	w := witness.NewProcWitness(os.Getpid())
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	g := saidno.New(h.Tracer("saidno-test"), slog.New(slog.DiscardHandler))

	resp := g.Run(context.Background(), request(saidno.Operator))

	if resp.Status != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.Status)
	}
	w.Stop()
	if err := w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Spawned(tr.TraceIDs()[0]); len(got) == 0 {
		t.Fatal("the witness saw no process for an allowed request")
	}
}
