//subpoena:impl_derived

package cross

import "testing"

// A kill that began on testimony is a self-report at once, whatever the repeat gives.
// confirmKill sets that outcome too, but only for a repeat with no witness evidence,
// so here, with witness evidence on the repeat alone, this reading is all there is.
func TestAKillThatBeganOnTestimonyIsNotRedeemedByTheRepeat(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "signed_test.go": signedHelper, "gate_test.go": `package mini

import "testing"

func TestRefused(t *testing.T) {
	if nth == 2 { t.Fatal("a plain assertion") }
	if nth == 3 { t.Fatal(signed("witness: a connection arrived")) }
}
func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true})
	if r.Outcome != KilledBySelfReport || r.Evidence != EvidenceOther || r.FirstFailure != "a plain assertion" {
		t.Fatalf("got %+v", r)
	}
}
