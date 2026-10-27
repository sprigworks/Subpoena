//subpoena:spec_derived

package quickstart_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"

	"example.com/quickstart"
)

// sleepArg: the purge process must outlive the witness polling interval.
const sleepArg = "0.15"

func rig(t *testing.T) (*harness.Harness, *quickstart.Handler, *witness.ProcWitness) {
	t.Helper()
	h := harness.New()
	w := witness.NewProcWitness(os.Getpid())
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	return h, quickstart.New(h.Tracer("quickstart-test")), w
}

// Inline TraceQL: the rule written where it is used.
var (
	refused    = fmt.Sprintf(`{ name = %q && span.%s = false }`, quickstart.SpanDeleteAuth, quickstart.AttrAllowed)
	anyPurge   = fmt.Sprintf(`{ name = %q }`, quickstart.SpanDeletePurge)
	purgeAfter = refused + ` >> ` + anyPurge
)

// A non-admin delete is refused and the purge never runs: the denial span
// exists, no purge span follows it, and the witness saw no process.
func TestNonAdminDeleteNeverPurges(t *testing.T) {
	h, d, w := rig(t)
	err := d.Delete(context.Background(), quickstart.Request{AccountID: "acct-1", Command: "sleep", Args: []string{sleepArg}})
	if !errors.Is(err, quickstart.ErrRefused) {
		t.Fatalf("want ErrRefused, got %v", err)
	}
	w.Stop()
	if err := w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, refused)
	harness.RequireAbsent(t, tr, purgeAfter)
	harness.RequireAbsent(t, tr, anyPurge)
	harness.RequireNoSpawn(t, w, tr.TraceIDs()[0])
}

// Control: an admin delete runs, and the witness sees the process, so the
// absence above is not vacuous.
func TestAdminDeletePurgesAndIsWitnessed(t *testing.T) {
	h, d, w := rig(t)
	if err := d.Delete(context.Background(), quickstart.Request{AccountID: "acct-2", IsAdmin: true, Command: "sleep", Args: []string{sleepArg}}); err != nil {
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
	harness.RequireExists(t, tr, anyPurge)
	harness.RequireAbsent(t, tr, purgeAfter)
	if got := w.Spawned(tr.TraceIDs()[0]); len(got) == 0 {
		t.Fatal("the witness saw no process for an admin delete")
	}
}
