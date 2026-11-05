//subpoena:impl_derived

package cross

import (
	"context"
	"os"
	"path/filepath"
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

// Tests here fail by state left from an earlier run: only that, and not the
// mutant, can turn them red. Each module has two mutants, so a run at -j 1
// shares a worker between them.
const twoGates = gateGo + `
//subpoena:enforcement_point
func Check2(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

// A test that leaves a file in the copy must not trip on it in the next case:
// each case gets a fresh copy, as the baseline does (repro e4-state).
func TestStateLeftInTheCopyIsNoKill(t *testing.T) {
	const test = `package mini

import (
	"os"
	"testing"
)

func TestWorkdirIsFresh(t *testing.T) {
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}
}
`
	for _, jobs := range []int{1, 2} {
		rep, err := Run(context.Background(), Options{Target: module(t, map[string]string{"gate.go": twoGates, "gate_test.go": test}), Jobs: jobs})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Results {
			if r.Outcome != Survived {
				t.Fatalf("-j %d: want survived, got %s %q", jobs, r.Outcome, r.FirstFailure)
			}
		}
	}
}

// State outside the copy survives a fresh copy, so a red test is run again
// without the mutant, and failing there too it proves nothing (repro
// e4b-outside-state).
func TestATestRedWithoutTheMutantIsNoKill(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "mark")
	test := `package mini

import (
	"os"
	"testing"
)

func TestFirstRunOnly(t *testing.T) {
	const mark = "` + mark + `"
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("already initialised")
	}
	os.WriteFile(mark, nil, 0o644)
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Outcome != Unconfirmed || !rep.Failed() || !strings.Contains(r.Output, "already initialised") {
		t.Fatalf("want unconfirmed, got %s %q\n%s", r.Outcome, r.FirstFailure, r.Output)
	}
}

// A flake can pass one rerun, so a kill takes killReruns of them (repro
// e5-flake, made certain: this test fails on its second and fourth runs, which
// are the mutant run and the second rerun). With one rerun it comes back a kill.
func TestAFlakeNeedsMoreThanOneRerun(t *testing.T) {
	count := filepath.Join(t.TempDir(), "count")
	test := `package mini

import (
	"os"
	"testing"
)

func TestFlaky(t *testing.T) {
	const count = "` + count + `"
	b, _ := os.ReadFile(count)
	b = append(b, 'x')
	os.WriteFile(count, b, 0o644)
	if len(b) == 2 || len(b) == 4 {
		t.Fatal("upstream was slow")
	}
}
`
	reruns := killReruns
	defer func() { killReruns = reruns }()
	for n, want := range map[int]Outcome{1: Killed, 3: Unconfirmed} {
		os.Remove(count)
		killReruns = n
		rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
		if err != nil {
			t.Fatal(err)
		}
		if r := rep.Results[0]; r.Outcome != want {
			t.Fatalf("%d reruns: want %s, got %s %q", n, want, r.Outcome, r.FirstFailure)
		}
	}
}

// A self-report kill is a kill too: the same check holds it.
func TestASelfReportKillIsConfirmedToo(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "mark")
	test := `package mini

import (
	"os"
	"testing"
)

func TestFirstRunOnly(t *testing.T) {
	const mark = "` + mark + `"
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("already initialised")
	}
	os.WriteFile(mark, nil, 0o644)
}
`
	rep, err := Run(context.Background(), Options{Target: module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}), RequireWitness: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed {
		t.Fatalf("want unconfirmed, got %s", r.Outcome)
	}
}

// A rerun's names come from the events, top-level names only, since -run reads
// a slash as a subtest level; a package with no failed test is not rerun.
func TestFailedTestsNamesWhatToRerun(t *testing.T) {
	names, pkgs := failedTests(strings.Join([]string{
		`{"Action":"fail","Package":"p","Test":"TestA/sub"}`,
		`{"Action":"fail","Package":"p","Test":"TestA"}`,
		`{"Action":"pass","Package":"p","Test":"TestB"}`,
		`{"Action":"fail","Package":"p"}`,
		`{"Action":"fail","Package":"q"}`,
		`{"Action":"fail","Package":"r","Test":"TestC"}`,
	}, "\n"))
	if strings.Join(names, " ") != "TestA TestC" || strings.Join(pkgs, " ") != "p r" {
		t.Fatalf("got %v %v", names, pkgs)
	}
}

func init() {
	// One rerun keeps this suite's many real kills cheap; a test that needs
	// more sets it.
	killReruns = 1
}
