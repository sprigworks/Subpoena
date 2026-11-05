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

// A panic can land beside an open line, where the text no longer starts a line
// (repro e21b-spinner, there by a goroutine printing dots). The panic value's
// Error method prints here instead: the runtime calls it just ahead of writing
// "panic: ", so the same line comes out on every run. The exit code still says.
func TestAPanicBesideAnOpenLineIsACrash(t *testing.T) {
	const src = `package mini

import (
	"errors"
	"fmt"
)

var ErrDenied = errors.New("denied")

type loud struct{}

func (loud) Error() string {
	fmt.Print("....")
	return "nil pointer dereference"
}

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	panic(loud{})
}
`
	const test = `package mini

import "testing"

func TestA(t *testing.T) {
	t.Log("about to call")
	Check("mallory")
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": src, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Crashed {
		t.Fatalf("want crashed, got %s, evidence %q", r.Outcome, r.FirstFailure)
	}
}

// Any exit but a test binary's own 1 is a death, whatever the output shows.
func TestExitCodeDecidesAPackageDied(t *testing.T) {
	const out = `{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:3: denied\n"}
{"Action":"fail","Package":"p","Test":"TestA"}
{"Action":"fail","Package":"p"}
`
	for code, crashed := range map[string]bool{"1": false, "2": true, "137": true, exitUnknown: true} {
		if _, _, got := firstFailure(out + exitEvent("p", code) + "\n"); got != crashed {
			t.Errorf("exit %s: crashed = %v, want %v", code, got, crashed)
		}
	}
}

// A recover middleware's log line in a test that passed says nothing about the
// test that failed: the binary lived, or it would not exit 1. Both orders give
// the same verdict (repros k1-passing-panicline, k1b-swapped).
func TestAPanicLineInAPassingTestIsNoCrashInEitherOrder(t *testing.T) {
	const logs = `
func TestMiddlewareRecovers(t *testing.T) {
	recoverMiddleware(func() { panic("handled") })
}
`
	const denied = `
func TestDenied(t *testing.T) {
	if Check("mallory") == nil {
		t.Fatal("mallory was let in")
	}
}
`
	const head = `package mini

import (
	"fmt"
	"os"
	"testing"
)

func recoverMiddleware(f func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n", r)
		}
	}()
	f()
}
`
	for name, test := range map[string]string{"log first": head + logs + denied, "log last": head + denied + logs} {
		t.Run(name, func(t *testing.T) {
			rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
			if err != nil {
				t.Fatal(err)
			}
			if r := rep.Results[0]; r.Outcome != Killed || r.FirstFailure != "mallory was let in" {
				t.Fatalf("want a kill, got %s %q\n%s", r.Outcome, r.FirstFailure, r.Output)
			}
		})
	}
}

// A panic line in a test that did not pass still gives no kill, though the
// binary exited 1: a framework recovered it, and the evidence is mixed.
func TestAPanicLineInAFailedTestIsACrash(t *testing.T) {
	const test = `package mini

import (
	"fmt"
	"os"
	"testing"
)

func TestDenied(t *testing.T) {
	fmt.Fprintln(os.Stderr, "panic: recovered by the middleware")
	if Check("mallory") == nil {
		t.Fatal("mallory was let in")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Crashed {
		t.Fatalf("want crashed, got %s %q", r.Outcome, r.FirstFailure)
	}
}
