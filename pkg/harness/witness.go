package harness

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoSpawn checks the independent witness after its observation window has
// ended. An observed process contradicts absence even if capture was unhealthy.
// With no observations, missing or bad health makes the claim Inconclusive, and
// so does a witness file with no exec capture in it.
// The caller must Collect before combining this with telemetry assertions.
//
//subpoena:enforcement_point
func NoSpawn(w witness.Witness, traceID string) (Verdict, error) {
	if spawned := w.Spawned(traceID); len(spawned) != 0 {
		return Fail, fmt.Errorf("witness saw processes for %s: %+v", traceID, spawned) //subpoena:enforcement
	}
	if err := execCapture(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	if err := captureHealth(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	return Pass, nil
}

// execCapture is the fault of a witness file whose start record names no exec
// hook: it has no exec lines because nothing looked. A witness that is no file
// has its hook by being what it is.
//
//subpoena:enforcement_point
func execCapture(w any) error {
	if c, ok := w.(interface{ CapturedExecs() bool }); ok && !c.CapturedExecs() {
		return errors.New("the witness file's start record names no exec capture, so a process could not have been seen (read the file subpoena-witness's exec witness wrote)") //subpoena:enforcement
	}
	return nil
}

// errNoHealth is the capture fault of a witness that does not report health.
var errNoHealth = errors.New("witness does not report capture health")

// captureHealth is w's capture health; a witness that does not report it
// counts as unhealthy. Missing and bad health are one fault, so removing the
// check that acts on it is a real bypass, not a nil dereference.
func captureHealth(w any) error {
	h, ok := w.(witness.HealthReporter)
	if !ok {
		return errNoHealth
	}
	return h.Health()
}

// RequireNoSpawn fails the test unless a healthy witness reports no processes.
// Unlike telemetry absence, this checks side effects independently of spans.
func RequireNoSpawn(tb testing.TB, w witness.Witness, traceID string) {
	tb.Helper()
	v, err := NoSpawn(w, traceID)
	if v != Pass {
		tb.Fatalf("%s", noSpawnMessage(tb, traceID, v, err))
	}
}
