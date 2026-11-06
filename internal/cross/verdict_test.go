//subpoena:impl_derived

package cross

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/internal/crossmark"
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
	// After m.Run the binary has finished testing, so its exit 1 reads as a
	// test's: only the rule on package output keeps the line from a kill.
	t.Run("after m.Run", func(t *testing.T) {
		src := strings.Replace(bootGo, "MESSAGE", "empty key", 1)
		test := strings.Replace(bootTest, "Boot(\"\")\n\tos.Exit(m.Run())", "code := m.Run()\n\tBoot(\"\")\n\tos.Exit(code)", 1)
		rep, err := run(t, module(t, map[string]string{"gate.go": src, "gate_test.go": test}))
		if err != nil {
			t.Fatal(err)
		}
		if r := rep.Results[0]; r.Outcome != Crashed {
			t.Fatalf("want crashed, got %s, evidence %s %q", r.Outcome, r.Evidence, r.FirstFailure)
		}
	})
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
		if _, _, got := firstFailure(out+exitEvent("p", code)+"\n", testKey); got != crashed {
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
// e5-flake, made certain: this test fails on its second, third and fifth runs,
// which are the mutant run, its repeat and the second rerun). With one rerun it
// comes back a kill.
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
	if len(b) == 2 || len(b) == 3 || len(b) == 5 {
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

// The rerun is the mutant run's whole command: a failure that needs a sibling
// test comes back without the mutant only if the sibling runs too (Review 4,
// finding 2, repro r1sibling).
func TestAFailureThatNeedsASiblingIsNoKill(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "mark")
	test := `package mini

import (
	"os"
	"testing"
)

var stale bool

func TestAReadsState(t *testing.T) {
	const mark = "` + mark + `"
	_, err := os.Stat(mark)
	stale = err == nil
	os.WriteFile(mark, nil, 0o644)
}

func TestBUnrelated(t *testing.T) {
	if stale {
		t.Fatal("stale state from a previous run")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed || !strings.Contains(r.Output, "stale state") {
		t.Fatalf("want unconfirmed, got %s %q\n%s", r.Outcome, r.FirstFailure, r.Output)
	}
}

// A rare flake passes every run without the mutant, so those cannot catch it.
// It fails only on the mutant run here, the shape of go-kratos/gateway's
// TestRetryBreaker: red once with the mutant, then green with it.
func TestAKillMustRepeatWithTheMutant(t *testing.T) {
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
	if len(b) == 2 {
		t.Fatal("upstream was slow")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed || !strings.Contains(r.Why, "again with the mutant") {
		t.Fatalf("want unconfirmed, got %s %q\n%s", r.Outcome, r.FirstFailure, r.Output)
	}
}

// testKey signs the synthetic output of tests that read failures directly.
const testKey = "test-key"

// signedHelper signs as the harness does, for a fixture module, which cannot
// import the harness: its env var and its mark, with stdlib only.
const signedHelper = `package mini

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

var key = os.Getenv("` + crossmark.Env + `")

func signed(msg string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(msg))
	return msg + " [subpoena-cross:" + hex.EncodeToString(h.Sum(nil))[:32] + "]"
}
`

func init() {
	// One rerun keeps this suite's many real kills cheap; a test that needs
	// more sets it.
	killReruns = 1
}

// A line the code under test prints has the shape of a t.Log, so a tag there
// must not pass the strict gate. Only the harness can sign the tag (repro
// e3-app-witness).
func TestAWitnessTagFromTheCodeUnderTestIsNoEvidence(t *testing.T) {
	const src = `package mini

import (
	"errors"
	"fmt"
)

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Check(u string) error {
	fmt.Println("    audit.go:40: witness: request seen for", u)
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`
	const test = `package mini

import "testing"

func TestDenied(t *testing.T) {
	if Check("mallory") == nil {
		t.Fatal("error return was nil")
	}
}
`
	rep, err := Run(context.Background(), Options{Target: module(t, map[string]string{"gate.go": src, "gate_test.go": test}), RequireWitness: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != KilledBySelfReport || r.Evidence != EvidenceOther {
		t.Fatalf("want a self-report kill, got %s, evidence %s %q", r.Outcome, r.Evidence, r.FirstFailure)
	}
}

// A hand-written tag with no mark is a claim, not the harness's word, whoever
// wrote it; so is a mark made with another run's key. A real mark is a witness.
func TestOnlyTheRunsMarkMakesAWitness(t *testing.T) {
	line := func(text string) string {
		b, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		return `{"Action":"output","Package":"p","Test":"TestA","Output":` + string(b) + `}` + "\n" + `{"Action":"fail","Package":"p","Test":"TestA"}`
	}
	for _, c := range []struct {
		name, head string
		want       Evidence
	}{
		{"signed", crossmark.Sign(testKey, "witness: saw a dial"), EvidenceWitness},
		{"bare tag", "witness: saw a dial", EvidenceOther},
		{"another key", crossmark.Sign("other", "witness: saw a dial"), EvidenceOther},
		{"mark on an untagged line", crossmark.Sign(testKey, "saw a dial"), EvidenceOther},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := line("    a_test.go:3: " + c.head + "\n")
			ev, msg, _ := firstFailure(raw, testKey)
			if ev != c.want || strings.Contains(msg, "subpoena-cross") {
				t.Fatalf("evidence %q, message %q", ev, msg)
			}
			if got := witnessFailure(raw, testKey); (got != "") != (c.want == EvidenceWitness) || strings.Contains(got, "subpoena-cross") {
				t.Fatalf("witnessFailure = %q", got)
			}
		})
	}
}

// A test's text is not the go command's: a real t.Fatal holding "[build failed]"
// is a kill, and a panic holding "[setup failed]" a crash (repros i2-buildtext,
// i3-buildpanic).
func TestBuildFailedIsReadOnlyFromGoTestsOwnLine(t *testing.T) {
	for text, want := range map[string]Outcome{
		`t.Fatal("deploy log said FAIL example.com/x [build failed] and mallory was let in")`: Killed,
		`panic("[setup failed]")`: Crashed,
	} {
		test := `package mini

import "testing"

func TestDenied(t *testing.T) {
	if Check("mallory") == nil {
		` + text + `
	}
}
`
		rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
		if err != nil {
			t.Fatal(err)
		}
		if r := rep.Results[0]; r.Outcome != want {
			t.Fatalf("%s: want %s, got %s\n%s", text, want, r.Outcome, r.Output)
		}
	}
}

// go test passes a package it has no tests for, so a fault in one shows first
// in go build, on every mutant, as if each had broken it. It is the module's
// fault, so it stops the run before any mutant (repros i5-nomain, i4-linkfail).
func TestABaselineThatDoesNotBuildIsAnError(t *testing.T) {
	dir := module(t, map[string]string{"gate.go": gateGo, "gate_test.go": strings.Replace(denyOnly, "denied", "Check", 1), "tool/tool.go": "package main\n"})
	_, err := run(t, dir)
	if err == nil || !strings.Contains(err.Error(), "baseline does not build") {
		t.Fatalf("want a baseline error, got %v", err)
	}
}

const denyOnly = `package mini

import "testing"

func TestDenied(t *testing.T) {
	if denied("mallory") == nil {
		t.Fatal("mallory was let in")
	}
}
`

// A marker can follow an upstream comment, so marking a line removes no
// upstream text (B04, T27), prose is not counted as one, and the lines
// marker-only comments added are taken back out (B25).
func TestMarkersAreCountedAndLinesMapBack(t *testing.T) {
	const src = `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied // upstream's reason //subpoena:enforcement
	}
	return nil
}

// Not an enforcement point, in prose: the //subpoena:enforcement marker.
func Other() {}
`
	test := `package mini

import "testing"

func TestRefused(t *testing.T) {
	if Check("mallory") == nil {
		t.Fatal("not refused")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": src, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Killed {
		t.Fatalf("results %+v", rep.Results)
	}
	if m := rep.Results[0].Mutant; m.Line != 10 || m.Upstream != 9 { // no doc text, so no gofmt line
		t.Fatalf("line %d upstream %d, want 10 and 9", m.Line, m.Upstream)
	}
	if rep.Markers != 1 || len(rep.Unplaced) != 0 {
		t.Fatalf("markers %d unplaced %v", rep.Markers, rep.Unplaced)
	}
}

// A test whose binary holds none of the mutated code cannot have seen the
// mutant, however often it fails (T34: go-kratos/gateway's circuitbreaker.go:68).
func TestAFailureInABinaryThatDoesNotLinkTheMutantIsNoKill(t *testing.T) {
	count := filepath.Join(t.TempDir(), "count")
	test := `package other

import (
	"os"
	"testing"
)

func TestFlaky(t *testing.T) {
	const count = "` + count + `"
	b, _ := os.ReadFile(count)
	b = append(b, 'x')
	os.WriteFile(count, b, 0o644)
	if len(b) == 2 || len(b) == 3 {
		t.Fatal("upstream was slow")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate/gate.go": strings.Replace(gateGo, "package mini", "package gate", 1), "other/other_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed || !strings.Contains(r.Why, "do not link") {
		t.Fatalf("want unconfirmed, got %s %q\n%s", r.Outcome, r.FirstFailure, r.Output)
	}
}

// A noexec TMPDIR with GOTMPDIR set is the case GOTMPDIR exists for, so the
// wrapper is built there (Review 4, finding 7).
func TestTheWrapperIsBuiltInGOTMPDIR(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOTMPDIR", dir)
	r, err := newRunner(context.Background(), module(t, map[string]string{"gate.go": gateGo}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.remove()
	if filepath.Dir(r.dir) != dir {
		t.Fatalf("runner dir %s, want under %s", r.dir, dir)
	}
}

// flakyByRun is a test that counts its runs outside the copy, with body after.
func flakyByRun(count, imports, body string) string {
	return `package mini

import (
	"os"
	"testing"` + imports + `
)

func TestFlaky(t *testing.T) {
	const count = "` + count + `"
	b, _ := os.ReadFile(count)
	b = append(b, 'x')
	os.WriteFile(count, b, 0o644)
	n := len(b)
	_ = n
` + body + `
}
`
}

// A flake that leaves a file in the copy would confirm itself on a reused copy,
// so the repeat gets a fresh one (Review 5, finding 2).
func TestAFlakeThatLeavesAFileDoesNotConfirmItself(t *testing.T) {
	test := flakyByRun(filepath.Join(t.TempDir(), "count"), "", `	if _, err := os.Stat("left"); err == nil {
		t.Fatal("left behind")
	}
	if n == 2 {
		os.WriteFile("left", nil, 0o644)
		t.Fatal("upstream was slow")
	}`)
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed {
		t.Fatalf("want unconfirmed, got %s %q", r.Outcome, r.FirstFailure)
	}
}

// Only a clean failure is red again: a panic on the repeat is no kill, nor is a
// different test failing (Review 5, finding 3).
func TestARepeatMustBeACleanKill(t *testing.T) {
	test := flakyByRun(filepath.Join(t.TempDir(), "count"), "", `	if n == 2 {
		t.Fatal("upstream was slow")
	}
	if n == 3 {
		panic("died")
	}`)
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed || !strings.Contains(r.Why, "crashed") {
		t.Fatalf("want unconfirmed on a crash, got %s %q", r.Outcome, r.Why)
	}
	count := filepath.Join(t.TempDir(), "count")
	other := flakyByRun(count, "", `	if n == 2 {
		t.Fatal("upstream was slow")
	}`) + `
func TestOther(t *testing.T) {
	b, _ := os.ReadFile("` + count + `")
	if len(b) == 3 {
		t.Fatal("something else")
	}
}
`
	rep, err = run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": other}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed || !strings.Contains(r.Why, "different test") {
		t.Fatalf("want unconfirmed on a different test, got %s %q", r.Outcome, r.Why)
	}
}

// A failure can need a test in another package: here package a, seeing what the
// baseline left outside the copy, writes a file package mini fails on. Neither
// looks at a refusal (Review 5, finding 4).
func TestAFailureThatNeedsAnotherPackageIsNoKill(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "mark")
	first := `package a

import (
	"os"
	"testing"
)

func TestWrites(t *testing.T) {
	const mark = "` + mark + `"
	if _, err := os.Stat(mark); err == nil {
		os.WriteFile("../trigger", nil, 0o644)
	}
	os.WriteFile(mark, nil, 0o644)
}
`
	second := `package mini

import (
	"os"
	"testing"
	"time"
)

func TestReads(t *testing.T) {
	time.Sleep(time.Second)
	if _, err := os.Stat("trigger"); err == nil {
		t.Fatal("state from the other package")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": gateGo, "gate_test.go": second, "a/a_test.go": first}))
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Unconfirmed {
		t.Fatalf("want unconfirmed, got %s %q", r.Outcome, r.FirstFailure)
	}
}

// A comment on a line of its own that names a marker is prose, on any line
// (Review 5, finding 1); on a line of code a bad argument is an error, not a
// marker dropped (finding 6).
func TestProseIsNoMarkerAndABadTrailingOneIsLoud(t *testing.T) {
	prose := strings.Replace(gateGo, "package mini\n", "package mini\n\n// shape: return nil // why //subpoena:enforcement\n", 1)
	test := `package mini

import "testing"

func TestRefused(t *testing.T) {
	if Check("mallory") == nil {
		t.Fatal("not refused")
	}
}
`
	rep, err := run(t, module(t, map[string]string{"gate.go": prose, "gate_test.go": test}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Markers != 1 || len(rep.Unplaced) != 0 {
		t.Fatalf("markers %d unplaced %v", rep.Markers, rep.Unplaced)
	}
	bad := strings.Replace(gateGo, "return ErrDenied //subpoena:enforcement", "return ErrDenied // why //subpoena:enforcement grp=a", 1)
	if _, err := run(t, module(t, map[string]string{"gate.go": bad, "gate_test.go": test})); err == nil {
		t.Fatal("a bad trailing marker passed")
	}
}
