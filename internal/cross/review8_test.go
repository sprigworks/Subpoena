//subpoena:impl_derived

package cross

import (
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
	if r := killOf(t, Options{Target: dir, Timeout: 20 * time.Second}); r.Outcome != Killed {
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
	if r := killOf(t, Options{Target: dir, Timeout: 15 * time.Second}); r.Outcome != TimedOut {
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
