package harness

import (
	"fmt"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoSpawn checks the independent witness after its observation window has
// ended. An observed process contradicts absence even if capture was unhealthy.
// With no observations, missing or bad health makes the claim Inconclusive.
// The caller must Collect before combining this with telemetry assertions.
func NoSpawn(w witness.Witness, traceID string) (Verdict, error) {
	if spawned := w.Spawned(traceID); len(spawned) != 0 {
		return Fail, fmt.Errorf("witness saw processes for %s: %+v", traceID, spawned)
	}
	h, ok := w.(witness.HealthReporter)
	if !ok {
		return Inconclusive, fmt.Errorf("witness does not report capture health")
	}
	if err := h.Health(); err != nil {
		return Inconclusive, err
	}
	return Pass, nil
}

// RequireNoSpawn fails the test unless a healthy witness reports no processes.
// Unlike telemetry absence, this checks side effects independently of spans.
func RequireNoSpawn(tb testing.TB, w witness.Witness, traceID string) {
	tb.Helper()
	v, err := NoSpawn(w, traceID)
	if v != Pass {
		tb.Fatalf("no spawn for %s: %s: %v", traceID, v, err)
	}
}
