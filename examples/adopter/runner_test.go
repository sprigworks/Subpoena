//subpoena:spec_derived

package jobrunner_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"

	"example.com/jobrunner"
	"example.com/jobrunner/generated/go/semconv"
	"example.com/jobrunner/invariants"
)

// sleepArg: the job's process must outlive the witness polling interval.
const sleepArg = "0.15"

func rig(t *testing.T) (*harness.Harness, *jobrunner.Runner, *witness.ProcWitness) {
	t.Helper()
	h := harness.New()
	w := witness.NewProcWitness(os.Getpid())
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	return h, jobrunner.New(h.Tracer("jobrunner-test")), w
}

var (
	rejected = fmt.Sprintf(`{ name = %q && span.%s = false }`, semconv.SpanCiJobAdmit, semconv.AttrCiAdmissionAllowed)
	anyExec  = fmt.Sprintf(`{ name = %q }`, semconv.SpanCiJobExec)
)

// An untrusted job asking for secrets is rejected, and nothing runs: the
// invariant holds in the trace, and the witness saw no process.
func TestUntrustedJobWithSecretsNeverRuns(t *testing.T) {
	h, r, w := rig(t)
	_, err := r.Submit(context.Background(), jobrunner.Job{ID: "job-1", WantsSecrets: true, Command: "sleep", Args: []string{sleepArg}})
	if !errors.Is(err, jobrunner.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
	w.Stop()
	if err := w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, rejected)
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoRunWithSecretsAfterReject))
	harness.RequireAbsent(t, tr, anyExec)
	harness.RequireNoSpawn(t, w, tr.TraceIDs()[0])
}

// Control: a trusted job with secrets, and an untrusted one without, run, and
// the witness sees them, so the absence above is not vacuous.
func TestAdmittedJobsRunAndAreWitnessed(t *testing.T) {
	for _, j := range []jobrunner.Job{
		{ID: "job-2", Trusted: true, WantsSecrets: true},
		{ID: "job-3", Trusted: false, WantsSecrets: false},
	} {
		t.Run(j.ID, func(t *testing.T) {
			h, r, w := rig(t)
			j.Command, j.Args = "sleep", []string{sleepArg}
			if _, err := r.Submit(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			w.Stop()
			if err := w.Health(); err != nil {
				t.Fatalf("witness capture incomplete: %v", err)
			}
			tr, err := h.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			harness.RequireExists(t, tr, anyExec)
			harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoRunWithSecretsAfterReject))
			if got := w.Spawned(tr.TraceIDs()[0]); len(got) == 0 {
				t.Fatal("the witness saw no process for an admitted job")
			}
		})
	}
}
