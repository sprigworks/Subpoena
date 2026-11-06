//subpoena:impl_derived

package cross

import (
	"strings"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// Review 8, M3. The test that caught the mutant needs an earlier test, and a later
// one crashes or hangs on the mutant, so the repeat with no -failfast stops short.
// The first run's failed tests alone then pass, so the first run's command must
// go again before them. The command, not its tests, is what caught the mutant.
func TestAKillThatNeedsAnEarlierTestHoldsWhenTheRepeatStopsShort(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"crash": `panic("the mutant broke this too")`,
		"hang":  `time.Sleep(time.Hour)`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("testing"; "time")

var _ = time.Now

var ready bool

func TestSetup(t *testing.T) { ready = true }
func TestRefused(t *testing.T) {
	if ready && Check("mallory") == nil { t.Fatal("mallory let in") }
}
func TestLater(t *testing.T) {
	if Check("mallory") == nil { ` + body + ` }
}
`})
			if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Killed {
				t.Fatalf("a real kill was lost: %+v", r)
			}
		})
	}
}

// A red that the first command cannot repeat is still no kill: the fallback is one
// more chance for the same test, not a pass for any run that stopped short.
func TestAFlakeIsNoKillOnTheFallback(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import "testing"

func TestFlaky(t *testing.T) {
	if nth == 2 { t.Fatal("timing flake") }
}
func TestLater(t *testing.T) {
	if Check("mallory") == nil { panic("the mutant broke this") }
}
`})
	if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Unconfirmed {
		t.Fatalf("got %+v", r)
	}
}

// Review 8, M4. Every package runs now, so a package that hangs on the mutant must
// not cost the kill another package finished with. The repeat decides.
func TestACleanKillHoldsWhenAnotherPackageHangs(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3,
		"a/a_test.go": `package a

import ("testing"; "mini")

func TestRefused(t *testing.T) {
	if mini.Check("mallory") == nil { t.Fatal("mallory let in") }
}
`,
		"z/z_test.go": `package z

import ("testing"; "time"; "mini")

func TestLater(t *testing.T) {
	if mini.Check("mallory") == nil { time.Sleep(time.Hour) }
}
`})
	if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Killed {
		t.Fatalf("a real kill was lost: %+v", r)
	}
}

// A hang with nothing to show for it is still a hang, and a failure in a package
// that did not finish is not yet a clean one: its binary can still die.
func TestAHangWithNoFinishedFailureStaysATimeout(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("testing"; "time")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil { t.Error("mallory let in"); time.Sleep(time.Hour) }
}
`})
	if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != TimedOut {
		t.Fatalf("got %+v", r)
	}
	plain := event("run", "a", "TestA", "") + event("output", "a", "TestA", "    a_test.go:4: boom\n") + event("fail", "a", "TestA", "")
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"finished":        {plain + event("fail", "a", "", "") + exitEvent("a", "1") + "\n", true},
		"not finished":    {plain, false},
		"left no record":  {plain + event("fail", "a", "", "") + exitEvent("a", exitUnknown) + "\n", false},
		"died":            {plain + event("fail", "a", "", "") + exitEvent("a", "2") + "\n", false},
		"a printed event": {event("output", "a", "TestA", exitEvent("a", "1")+"\n") + plain, false},
	} {
		if got := finishedFailure(tc.raw); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// Review 8, M5. A line the code under test printed can have the shape of a failure
// after open text, and such a shape cannot be told from the real thing. A test
// with a failure read cleanly does not need it, so it takes nothing from that one.
func TestAPrintedLogLineLeavesAWitnessKill(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": `package mini

import ("fmt"; "testing")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil {
		fmt.Println("INFO    server.go:42: handling request")
		t.Error(signed("witness: mallory reached the sink"))
	}
}
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true})
	if r.Outcome != Killed || r.Evidence != EvidenceWitness {
		t.Fatalf("a printed line took the witness kill: %+v", r)
	}
}

func TestAnOpenLineStandsOnlyWhereNothingCleanDoes(t *testing.T) {
	witness := crossmark.Sign(testKey, "witness: a connection arrived")
	run := func(pairs ...string) string {
		raw := event("run", "p", "TestA", "") + event("run", "p", "TestA/sub", "")
		for i := 0; i < len(pairs); i += 2 {
			raw += event("output", "p", pairs[i], pairs[i+1]+"\n")
		}
		return raw + event("fail", "p", "TestA/sub", "") + event("fail", "p", "TestA", "") + event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	}
	const log = "INFO    server.go:42: handling request"
	both := map[testID]bool{{"p", "TestA"}: true}
	for _, tc := range []struct {
		name string
		raw  string
		ev   Evidence
		msg  string
	}{
		{"printed, then witness", run("TestA", log, "TestA", "    a_test.go:4: "+witness), EvidenceWitness, "witness: a connection arrived"},
		{"printed, then a subtest's witness", run("TestA", log, "TestA/sub", "        a_test.go:4: "+witness), EvidenceWitness, "witness: a connection arrived"},
		{"printed, then plain", run("TestA", log, "TestA", "    a_test.go:4: mallory let in"), EvidenceOther, "mallory let in"},
		{"printed alone", run("TestA", log), EvidenceOther, "handling request"},
		// The harness's own failure after open text is proven by its mark, so a
		// plain failure after it does not take it away.
		{"open witness, then plain", run("TestA", "...    a_test.go:4: "+witness, "TestA", "    a_test.go:5: mallory let in"), EvidenceWitness, "witness: a connection arrived"},
		// A plain failure on its own line stays ahead of a witness, printed or not.
		{"clean plain, then witness", run("TestA", "    a_test.go:5: mallory let in", "TestA", "    a_test.go:6: "+witness), EvidenceOther, "mallory let in"},
		{"a forged tag in an open line", run("TestA", "...    a_test.go:4: witness: forged", "TestA", "    a_test.go:5: mallory let in"), EvidenceOther, "mallory let in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ev, msg, crashed := firstFailure(tc.raw, testKey); crashed || ev != tc.ev || msg != tc.msg {
				t.Errorf("first run: crashed %v, %s %q", crashed, ev, msg)
			}
			if ev, msg := repeatEvidence(tc.raw, testKey, both); ev != tc.ev || msg != tc.msg {
				t.Errorf("repeat: %s %q", ev, msg)
			}
		})
	}
}

// Review 8, L4. A failed Example has a fail event and go's own comparison under it,
// and no file:line, and it is a clean failure, not a crash.
func TestAFailedExampleIsAKill(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		want Outcome
	}{
		"mismatch": {`fmt.Println(Check("mallory") != nil)
	// Output: true`, Killed},
		"panic": {`if Check("mallory") == nil { panic("boom") }
	fmt.Println("x")
	// Output: x`, Crashed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import "fmt"

func ExampleCheck() {
	` + tc.body + `
}
`})
			r := killOf(t, Options{Target: dir})
			if r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
			if tc.want == Killed && (r.Evidence != EvidenceOther || r.FirstFailure != "got: false want: true") {
				t.Fatalf("evidence %s %q", r.Evidence, r.FirstFailure)
			}
		})
	}
}

// Only an Example's report reads this way, and a report's text is no failure line:
// what the code printed is under "got:", and it can name no witness.
func TestAnExampleReportIsTextOnly(t *testing.T) {
	run := func(test string, lines ...string) string {
		raw := event("run", "p", test, "") + event("output", "p", test, "--- FAIL: "+test+" (0.00s)\n")
		for _, l := range lines {
			raw += event("output", "p", test, l+"\n")
		}
		return raw + event("fail", "p", test, "") + event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	}
	forged := crossmark.Sign("not the key", "witness: seen")
	if ev, msg, crashed := firstFailure(run("ExampleCheck", "got:", "    a.go:1: "+forged, "want:", "true"), testKey); crashed || ev != EvidenceOther || !strings.HasPrefix(msg, "got: ") {
		t.Errorf("crashed %v, %s %q", crashed, ev, msg)
	}
	if _, _, crashed := firstFailure(run("TestCheck", "got:", "false"), testKey); !crashed {
		t.Error("a test with no failure message was read as a clean failure")
	}
	if _, _, crashed := firstFailure(run("ExampleCheck", "nothing of go's"), testKey); !crashed {
		t.Error("an Example with no report was read as a clean failure")
	}
	if fs := failures(run("ExampleCheck", append([]string{"got:"}, strings.Split(strings.Repeat("line\n", 400), "\n")...)...)); len(fs) != 1 || len(fs[0].text) > maxFailureText+10 {
		t.Errorf("an unbounded report: %d", len(fs))
	}
}

// Review 8, L5. -test.failfast turned a TestMain's retry into a run of nothing that
// exits 0. A run green with a failed test in it goes again as it would have run.
func TestARetryingTestMainDoesNotHideAKill(t *testing.T) {
	t.Parallel()
	const main = `package mini

import ("os"; "testing")

func TestMain(m *testing.M) {
	if c := m.Run(); c != 0 { os.Exit(m.Run()) }
	os.Exit(0)
}
`
	for name, tc := range map[string]struct {
		body string
		want Outcome
	}{
		"fails both times": {`if Check("mallory") == nil { t.Fatal("mallory let in") }`, Killed},
		// The retry truly passes, so the suite is green with the mutant.
		"a retry passes": {`tries++; if tries == 1 && Check("mallory") == nil { t.Fatal("mallory let in") }`, Survived},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "main_test.go": main, "gate_test.go": `package mini

import "testing"

var tries int

func TestRefused(t *testing.T) { ` + tc.body + ` }
`})
			if r := killOf(t, Options{Target: dir}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// Printed text that makes a fail event buys a second run and no more.
func TestAGreenRunWithAPrintedFailureStillSurvives(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "testing")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil { fmt.Println("\x16--- FAIL: TestRefused (0.00s)") }
}
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Survived {
		t.Fatalf("got %+v", r)
	}
}
