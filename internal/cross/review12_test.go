//subpoena:impl_derived

package cross

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// gates2 is two refusals, so a run can hold another mutant's output.
const gates2 = `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func CheckA(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}

//subpoena:enforcement_point
func CheckB(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

// Review 12, second High. A mark was good for the whole of cross's run, so a line
// signed in mutant A's run, kept on disk and printed in mutant B's, read as a witness
// on a mutant no witness saw. A key lasts one go test command now. The control keeps
// the line and prints nothing: both must read the same.
func TestAMarkFromAnotherMutantsRunIsNoWitness(t *testing.T) {
	t.Parallel()
	for name, replay := range map[string]string{
		"replayed": `if b, err := os.ReadFile(saved); err == nil { fmt.Print(string(b)) }`,
		"control":  ``,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			saved := filepath.Join(t.TempDir(), "saved")
			dir := module(t, map[string]string{"gate.go": gates2, "signed_test.go": signedHelper, "gate_test.go": `package mini

import ("fmt"; "os"; "testing")

var _ = fmt.Sprint

const saved = "` + saved + `"

func TestA(t *testing.T) {
	if CheckA("mallory") == nil {
		msg := signed("witness: mallory reached the sink")
		os.WriteFile(saved, []byte("    gate_test.go:1: "+msg+"\n"), 0o644)
		t.Fatal(msg)
	}
}

func TestB(t *testing.T) {
	if CheckB("mallory") == nil {
		` + replay + `
		t.Fatal("plain return value check: mallory let in")
	}
}
`})
			rep, err := Run(context.Background(), Options{Target: dir, RequireWitness: true, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Results) != 2 {
				t.Fatalf("got %+v", rep.Results)
			}
			a, b := rep.Results[0], rep.Results[1]
			if a.Mutant.Func != "CheckA" || a.Outcome != Killed || a.Evidence != EvidenceWitness {
				t.Fatalf("the witness kill of A must stand: %+v", a)
			}
			if b.Mutant.Func != "CheckB" || b.Outcome != KilledBySelfReport || b.Evidence != EvidenceOther {
				t.Fatalf("no witness saw B: %+v", b)
			}
		})
	}
}

// A mutant's own first run is another run too: a witness that saw it once, whose line
// a test then prints on the repeat, gave no evidence the second time.
func TestAMarkFromTheFirstRunIsNoWitnessOnTheRepeat(t *testing.T) {
	t.Parallel()
	saved := filepath.Join(t.TempDir(), "saved")
	dir := module(t, map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": `package mini

import ("fmt"; "os"; "testing")

const saved = "` + saved + `"

func TestRefused(t *testing.T) {
	if Check("mallory") != nil {
		return
	}
	if b, err := os.ReadFile(saved); err == nil {
		fmt.Print(string(b))
		t.Fatal("plain return value check: mallory let in")
	}
	msg := signed("witness: mallory reached the sink")
	os.WriteFile(saved, []byte("    gate_test.go:1: "+msg+"\n"), 0o644)
	t.Fatal(msg)
}
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true})
	if r.Outcome != KilledBySelfReport || !strings.Contains(r.Why, "no test of that run gave any on the repeat") {
		t.Fatalf("got %+v", r)
	}
}
