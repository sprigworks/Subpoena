//subpoena:impl_derived

package cross

import (
	"context"
	"strings"
	"testing"
)

// gateGo is the code under test of the verdict repros: Check refuses mallory.
const gateGo = `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

// bootGo exits from outside any test once the refusal is gone, after a line
// with the shape of a failure message.
const bootGo = `package mini

import (
	"errors"
	"fmt"
	"os"
)

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Open(key string) error {
	if key == "" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}

func Boot(key string) {
	if err := Open(key); err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "config errors:\n  config.go:12: %s\n", "MESSAGE")
	os.Exit(1)
}
`

const bootTest = `package mini

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	Boot("")
	os.Exit(m.Run())
}

func TestNothing(t *testing.T) {}
`

// A process that exits while TestMain or init runs failed no test: what it
// printed is package output, never a failure message, whatever its shape
// (repros e1-boot, e2-boot-witness, n1c-logshort).
func TestPackageOutputIsNeverAFailureMessage(t *testing.T) {
	cases := []struct {
		name, message string
		strict        bool
	}{
		{"plain", "empty key", false},
		{"tagged", "witness: no spawn seen", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := module(t, map[string]string{"gate.go": strings.Replace(bootGo, "MESSAGE", c.message, 1), "gate_test.go": bootTest})
			rep, err := Run(context.Background(), Options{Target: dir, RequireWitness: c.strict})
			if err != nil {
				t.Fatal(err)
			}
			if r := rep.Results[0]; r.Outcome != Crashed {
				t.Fatalf("want crashed, got %s, evidence %s %q", r.Outcome, r.Evidence, r.FirstFailure)
			}
		})
	}
	t.Run("log.Fatal with a short file prefix", func(t *testing.T) {
		const test = `package mini

import (
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile)
	log.SetPrefix("  ")
	if Check("mallory") == nil {
		log.Fatal("fixture not ready")
	}
	os.Exit(m.Run())
}

func TestNothing(t *testing.T) {}
`
		rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
		if err != nil {
			t.Fatal(err)
		}
		if r := rep.Results[0]; r.Outcome != Crashed {
			t.Fatalf("want crashed, got %s, evidence %q", r.Outcome, r.FirstFailure)
		}
	})
}
