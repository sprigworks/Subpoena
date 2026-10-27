//subpoena:impl_derived
//subpoena:pure_logic

package harness

import (
	"errors"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

type unknownWitness struct{ events []witness.ProcessEvent }

func (w unknownWitness) Spawned(string) []witness.ProcessEvent { return w.events }

type healthWitness struct {
	unknownWitness
	err error
}

func (w healthWitness) Health() error { return w.err }

func TestNoSpawnNeedsHealthyCapture(t *testing.T) {
	gap := errors.New("observation lost")
	for _, tc := range []struct {
		name string
		w    witness.Witness
		want Verdict
	}{
		{"healthy empty", healthWitness{}, Pass},
		{"unhealthy empty", healthWitness{err: gap}, Inconclusive},
		{"unknown empty", unknownWitness{}, Inconclusive},
		{"healthy observed", healthWitness{unknownWitness: unknownWitness{[]witness.ProcessEvent{{PID: 42}}}}, Fail},
		{"unhealthy observed", healthWitness{unknownWitness{[]witness.ProcessEvent{{PID: 42}}}, gap}, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NoSpawn(tc.w, "trace")
			if got != tc.want || (err == nil) != (got == Pass) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			fatal, _ := runRequire(func(tb testing.TB) { RequireNoSpawn(tb, tc.w, "trace") })
			if (fatal == "") != (got == Pass) {
				t.Fatalf("RequireNoSpawn fatal = %q for %v", fatal, got)
			}
		})
	}
}
