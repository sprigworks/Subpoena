//subpoena:impl_derived

package cross

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// event is one line of go test -json.
func event(action, pkg, test, output string) string {
	b, err := json.Marshal(struct{ Action, Package, Test, Output string }{action, pkg, test, output})
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// failedRun is a package's events for a test that failed on msg.
func failedRun(pkg, test, msg string) string {
	return event("run", pkg, test, "") +
		event("output", pkg, test, "    a_test.go:4: "+msg+"\n") +
		event("fail", pkg, test, "") +
		event("fail", pkg, "", "") +
		exitEvent(pkg, "1") + "\n"
}

func witnessIn(pkg string) string {
	return strings.Replace(signedHelper, "package mini", "package "+pkg, 1)
}

// Finding 2. Packages finish in any order, and a verdict must not turn on it.
func TestEvidenceIsNotReadInFinishOrder(t *testing.T) {
	a := failedRun("a", "TestRefused", crossmark.Sign(testKey, "witness: a connection arrived"))
	b := failedRun("b", "TestPlain", "mallory let in")
	both := map[testID]bool{{"a", "TestRefused"}: true, {"b", "TestPlain"}: true}
	for name, raw := range map[string]string{"witness first": a + b, "plain first": b + a} {
		t.Run(name, func(t *testing.T) {
			if ev, msg, _ := firstFailure(raw, testKey); ev != EvidenceWitness || msg != "witness: a connection arrived" {
				t.Errorf("first run: %s %q", ev, msg)
			}
			if ev, _ := repeatEvidence(raw, testKey, both); ev != EvidenceWitness {
				t.Errorf("repeat: %s", ev)
			}
		})
	}
	// With no witness the message is stable too.
	c := failedRun("c", "TestOther", "another plain one")
	for _, raw := range []string{b + c, c + b} {
		if _, msg, _ := firstFailure(raw, testKey); msg != "mallory let in" {
			t.Errorf("message %q", msg)
		}
	}
}

// Within a package order is what happened: a plain failure first stays first, in
// a test and in a run, and a witness in a test the first run did not have is none.
func TestAWitnessTakesNothingFromThePackageOrTestAheadOfIt(t *testing.T) {
	const p = "a"
	witness := crossmark.Sign(testKey, "witness: a connection arrived")
	two := event("run", p, "TestA", "") + event("run", p, "TestB", "") +
		event("output", p, "TestA", "    a_test.go:4: plain\n") + event("fail", p, "TestA", "") +
		event("output", p, "TestB", "    a_test.go:9: "+witness+"\n") + event("fail", p, "TestB", "") +
		event("fail", p, "", "") + exitEvent(p, "1") + "\n"
	if ev, _, _ := firstFailure(two, testKey); ev != EvidenceOther {
		t.Errorf("first run: %s", ev)
	}
	if ev, _ := repeatEvidence(two, testKey, map[testID]bool{{p, "TestA"}: true}); ev != EvidenceOther {
		t.Errorf("a test not of the first run gave the evidence: %s", ev)
	}
	if ev, _ := repeatEvidence(two, testKey, map[testID]bool{{p, "TestA"}: true, {p, "TestB"}: true}); ev != EvidenceWitness {
		t.Errorf("a test of the first run gave witness evidence, read as %s", ev)
	}
	one := event("run", p, "TestA", "") +
		event("output", p, "TestA", "    a_test.go:4: plain\n") +
		event("output", p, "TestA", "    a_test.go:5: "+witness+"\n") +
		event("fail", p, "TestA", "") + event("fail", p, "", "") + exitEvent(p, "1") + "\n"
	if ev, _ := repeatEvidence(one, testKey, map[testID]bool{{p, "TestA"}: true}); ev != EvidenceOther {
		t.Errorf("a later witness in the test redeemed it: %s", ev)
	}
}

// x3 and x2. b's plain failure takes nothing from a's witness on either run, and a
// later test that panics in a, which -failfast hid from the first run, costs nothing.
func TestAWitnessKillHoldsWhenAnotherPackageCatchesTheMutantToo(t *testing.T) {
	t.Parallel()
	refused := `func TestRefused(t *testing.T) {
	if mini.Check("mallory") == nil { t.Fatal(signed("witness: a connection arrived")) }
}
`
	for name, later := range map[string]string{
		"both red":    "",
		"later panic": `func TestLater(t *testing.T) { if mini.Check("eve") == nil { panic("eve let in") } }` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			evidence := t.TempDir()
			dir := module(t, map[string]string{"gate.go": strings.Replace(gate3, `u == "mallory"`, `u != "admin"`, 1),
				"a/signed_test.go": witnessIn("a"),
				"a/a_test.go":      "package a\n\nimport (\n\t\"testing\"\n\n\t\"mini\"\n)\n\n" + refused + later,
				"b/b_test.go": `package b

import (
	"testing"

	"mini"
)

func TestPlain(t *testing.T) {
	if mini.Check("mallory") == nil { t.Fatal("mallory let in") }
}
`})
			r := killOf(t, Options{Target: dir, RequireWitness: true, EvidenceDir: evidence})
			if r.Outcome != Killed || r.Evidence != EvidenceWitness {
				t.Fatalf("a witness kill was lost: %+v", r)
			}
			// The repeat's output is kept, so the verdict can be shown.
			if len(r.RepeatEvidence) == 0 {
				t.Fatalf("no repeat kept: %+v", r)
			}
			b, err := os.ReadFile(r.RepeatEvidence[len(r.RepeatEvidence)-1])
			if err != nil || !strings.Contains(string(b), "witness: a connection arrived") {
				t.Fatalf("the repeat's output is not what decided: %v\n%s", err, b)
			}
		})
	}
}

// go test's -failfast skips each package not yet started once one has failed, so
// the witness's package would not run at all, by chance, if a plain one went first.
func TestAPackageThatFailsFirstSkipsNoOtherPackage(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3,
		"a/a_test.go": `package a

import (
	"testing"

	"mini"
)

func TestPlain(t *testing.T) {
	if mini.Check("mallory") == nil { t.Fatal("mallory let in") }
}
`,
		"z/signed_test.go": witnessIn("z"),
		"z/z_test.go": `package z

import (
	"net/http"
	"testing"

	"mini"
)

var _ = http.StatusOK

func TestRefused(t *testing.T) {
	if mini.Check("mallory") == nil { t.Fatal(signed("witness: a connection arrived")) }
}
`})
	if r := killOf(t, Options{Target: dir, RequireWitness: true}); r.Outcome != Killed || r.Evidence != EvidenceWitness {
		t.Fatalf("a witness kill was lost: %+v", r)
	}
}

// A self-report from the repeat says what the repeat printed.
func TestASelfReportFromTheRepeatShowsTheRepeat(t *testing.T) {
	t.Parallel()
	evidence := t.TempDir()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "signed_test.go": signedHelper, "gate_test.go": `package mini

import "testing"

func TestRefused(t *testing.T) {
	if nth == 2 { t.Fatal(signed("witness: a connection arrived")) }
	if nth == 3 { t.Fatal("a plain assertion") }
}
func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true, EvidenceDir: evidence})
	if r.Outcome != KilledBySelfReport || !strings.Contains(r.Output, "a plain assertion") || len(r.RepeatEvidence) != 1 {
		t.Fatalf("got %+v", r)
	}
}

// That second look is for a package that died, not for a witness that was not
// there: the dead package's test has to fail, cleanly, with witness evidence.
func TestAPackageThatDiesOnTheRepeatIsNoWitness(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "signed_test.go": signedHelper, "gate_test.go": `package mini

import "testing"

func TestRefused(t *testing.T) {
	if nth == 2 { t.Fatal(signed("witness: a connection arrived")) }
	if nth == 3 { t.Fatal("a plain assertion") }
	if nth == 4 { t.Fatal("plain again") }
}
func TestLater(t *testing.T) { if nth == 3 { panic("died") } }
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true})
	if r.Outcome == Killed {
		t.Fatalf("got %+v", r)
	}
}

func TestStoppedShortSeesOneDeadPackage(t *testing.T) {
	dead := event("run", "a", "TestRefused", "") + event("output", "a", "TestRefused", "panic: boom\n") +
		event("fail", "a", "TestRefused", "") + event("fail", "a", "", "") + exitEvent("a", "2") + "\n"
	raw := failedRun("b", "TestPlain", "mallory let in") + dead
	if !stoppedShort(raw, errors.New("exit 1"), testKey) {
		t.Fatal("one dead package beside a clean failure is a run stopped short")
	}
	if stoppedShort(failedRun("b", "TestPlain", "mallory let in"), errors.New("exit 1"), testKey) {
		t.Fatal("a run with no death stopped short")
	}
}

// Finding 3. go test gives a printed open line and the failure after it as one line.
func TestAnOpenLineBeforeAFailureIsNoCrash(t *testing.T) {
	witness := crossmark.Sign(testKey, "witness: a connection arrived")
	for _, tc := range []struct {
		name, line string
		crashed    bool
		ev         Evidence
		msg        string
	}{
		{"partial", "partial    app_test.go:12: mallory let in", false, EvidenceOther, "mallory let in"},
		{"a dot", ".    app_test.go:12: mallory let in", false, EvidenceOther, "mallory let in"},
		{"prompt with a space", "login:     app_test.go:12: mallory let in", false, EvidenceOther, "mallory let in"},
		{"a subtest's indent", "partial        app_test.go:12: mallory let in", false, EvidenceOther, "mallory let in"},
		{"witness", "...    app_test.go:12: " + witness, false, EvidenceWitness, "witness: a connection arrived"},
		{"not go test's indent", "2026/11/06 10:00:00 app.go:12: a log line", true, "", ""},
		{"no file", "partial    mallory let in", true, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := event("run", "p", "TestA", "") + event("output", "p", "TestA", tc.line+"\n") +
				event("fail", "p", "TestA", "") + event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
			ev, msg, crashed := firstFailure(raw, testKey)
			if crashed != tc.crashed || ev != tc.ev || msg != tc.msg {
				t.Fatalf("crashed %v, %s %q", crashed, ev, msg)
			}
		})
	}
	// It is the fail event that makes it a failure, and a death stays a death.
	line := event("output", "p", "TestA", "partial    app_test.go:12: boom\n")
	if _, _, crashed := firstFailure(line+event("pass", "p", "TestA", "")+event("fail", "p", "", "")+exitEvent("p", "1")+"\n", testKey); !crashed {
		t.Error("a passing test's line was read")
	}
	if _, _, crashed := firstFailure(line+event("fail", "p", "TestA", "")+event("fail", "p", "", "")+exitEvent("p", "2")+"\n", testKey); !crashed {
		t.Error("a dead binary's line was read")
	}
	// A line of a message's own text is indented, and is no second failure.
	multi := event("output", "p", "TestA", "    a_test.go:1: \n") +
		event("output", "p", "TestA", "        said    x.go:9: inner\n") +
		event("fail", "p", "TestA", "") + event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	if fs := failures(multi); len(fs) != 1 {
		t.Errorf("failures %+v", fs)
	}
}

func TestAPrintedOpenLineKeepsTheKill(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		want Outcome
	}{
		"failure":        {`fmt.Print("partial"); if Check("mallory") == nil { t.Fatal("mallory let in") }`, Killed},
		"silent failure": {`fmt.Print("partial"); if Check("mallory") == nil { t.FailNow() }`, Crashed},
		"panic":          {`fmt.Print("partial"); if Check("mallory") == nil { panic("boom") }`, Crashed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "testing")

func TestRefused(t *testing.T) { ` + tc.body + ` }
`})
			if r := killOf(t, Options{Target: dir}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// Finding 5. A test can print the byte go test's own lines carry, and go test then
// makes a fail event of its text. A test has one ending, and it ran.
func TestAFramedLineFailsNoTest(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import ("fmt"; "testing")

func TestFlaky(t *testing.T) { if nth == 2 { t.Fatal("timing flake") } }
func TestOther(t *testing.T) {
	if nth == 3 {
		fmt.Print("\x16--- FAIL: TestFlaky (0.00s)\n")
		t.Fatal("a second, different flake")
	}
}
func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
`})
	r := killOf(t, Options{Target: dir})
	if r.Outcome != Unconfirmed || !strings.Contains(r.Why, "different test") {
		t.Fatalf("got %+v", r)
	}
}

func TestAFailEventNeedsATestThatRanAndDidNotPass(t *testing.T) {
	raw := event("run", "p", "TestPassed", "") + event("pass", "p", "TestPassed", "") +
		event("run", "p", "TestSkipped", "") + event("skip", "p", "TestSkipped", "") +
		event("run", "p", "TestReal", "") + event("output", "p", "TestReal", "    a_test.go:1: boom\n") +
		event("fail", "p", "TestPassed", "") + event("fail", "p", "TestSkipped", "") +
		event("fail", "p", "TestNeverRan", "") + event("fail", "p", "TestReal", "") +
		event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	got := failedTests(raw, testKey)
	if len(got) != 1 || !got[testID{"p", "TestReal"}] {
		t.Fatalf("tests %v", got)
	}
	// Its own output is read as go test gave it, so a framed line can move a message
	// to another test. A test framed that way is no test of the first run.
	moved := event("run", "p", "TestPassed", "") + event("pass", "p", "TestPassed", "") +
		event("run", "p", "TestReal", "") +
		event("output", "p", "TestPassed", "    a_test.go:1: "+crossmark.Sign(testKey, "witness: moved")+"\n") +
		event("fail", "p", "TestPassed", "") + event("fail", "p", "TestReal", "") +
		event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	if ev, _ := repeatEvidence(moved, testKey, map[testID]bool{{"p", "TestPassed"}: true}); ev != EvidenceOther {
		t.Fatalf("evidence %s", ev)
	}
}

// Finding 6. -failfast in GOFLAGS must not narrow the repeat. Both tests catch the
// mutant, and only the repeat's whole run reaches the one the first run stopped at.
func TestFailfastInGoflagsDoesNotStopTheRepeat(t *testing.T) {
	t.Setenv("GOFLAGS", strings.TrimSpace(os.Getenv("GOFLAGS")+" -failfast"))
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import "testing"

func TestAFirstOnTheRepeat(t *testing.T) {
	if nth == 3 && Check("mallory") == nil { t.Fatal("mallory let in") }
}
func TestBFirstOnTheMutantRun(t *testing.T) {
	if Check("mallory") == nil { t.Fatal("mallory let in") }
}
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Killed {
		t.Fatalf("a real kill was lost: %+v", r)
	}
}

// Under -shuffle a test that crashes or hangs can run ahead of the one that caught
// the mutant on the fallback too, so the fallback runs that test alone. Here the
// other test comes first in the file, as shuffle can put it, and spares only the
// first run.
func TestALaterCrashAheadOfTheFailedTestCannotLoseAKill(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"crash": `panic("the mutant broke this too")`,
		"hang":  `time.Sleep(time.Hour)`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import ("testing"; "time")

var _ = time.Now

func TestAhead(t *testing.T) {
	if nth >= 3 && Check("mallory") == nil { ` + body + ` }
}
func TestRefused(t *testing.T) {
	if Check("mallory") == nil { t.Fatal("mallory let in") }
}
`})
			if r := killOf(t, Options{Target: dir, Timeout: 20 * time.Second}); r.Outcome != Killed {
				t.Fatalf("a real kill was lost: %+v", r)
			}
		})
	}
}

func TestOnlyTestsNarrowsTheCommand(t *testing.T) {
	whole := []string{"-json", "-run", "^TestSelected$", "./..."}
	got := onlyTests(whole, map[testID]bool{{"a", "TestB"}: true, {"b", "TestA"}: true, {"c", "TestA"}: true})
	want := []string{"-json", "-run", "^TestSelected$", "-run", "^(TestA|TestB)$", "./..."}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if got := onlyTests(whole, nil); !slices.Equal(got, whole) {
		t.Fatalf("no tests: %q", got)
	}
}

const spellGate = `package mini

var audited int

//subpoena:enforcement_point
func Check(u string) bool {
	if u != "admin" { //subpoena:enforcement_guard false
		return false
	}
	audited++ MARK
	return true
}

OWN
var Note = 1
`

// Findings 7 and 8. A marker with its words in the wrong case or two letters swapped
// is an error, and a sentence that opens with those words is not.
func TestAMisspeltMarkerIsAnErrorAndProseIsNot(t *testing.T) {
	for _, tc := range []struct {
		mark, own string
		mutants   int // 0 for an error
	}{
		{"//Subpoena:enforcement", "//", 0},
		{"//SUBPOENA:ENFORCEMENT", "//", 0},
		{"//subpoena:Enforcement", "//", 0},
		{"//subpoena:enfrocement", "//", 0},
		{"//subpeona:enforcement", "//", 0},
		{"//usbpoena:enforcement group=a", "//", 0},
		{"//subpoena:enforcement_gaurd true", "//", 0},
		{"// keep count //Subpoena:enforcement", "//", 0},
		{"// keep count //subpoena:enfrocement", "//", 0},
		{"//", "//Subpoena:enforcement", 0},
		{"//", "// Subpoena: enforcement", 0},
		{"//", "//subpoena:enfrocement_guard true", 0},
		{"//", "// subpoena : enforcement", 0},
		{"//", "//subpoena:enforcement_guard true and more", 0},
		{"// see //subpoena:enforcement_point //subpoena:enforcement bad words", "//", 0},
		{"//", "// subpoena: enforcement points are listed in docs.", 1},
		{"//", "// Subpoena: enforcement points are listed in docs.", 1},
		{"//", "// Subpoena: Enforcement is where the refusal happens.", 1},
		{"//", "// Subpoena's enforcement markers are in the docs.", 1},
		{"//", "// See subpoena:enforcement in the docs.", 1},
		{"//", "// Note: enforcement is checked here.", 1},
		{"// a Subpoena: enforcement note on this line", "//", 1},
		{"// functions marked //subpoena:enforcement_point", "//", 1},
		{"//subpoena enforcement", "//", 1},
		{"// see //subpoena:enforcement_point //subpoena:enforcement", "//", 2},
		{"//subpoena:enforcement", "// subpoena: enforcement points are listed in docs.", 2},
	} {
		t.Run(tc.mark+" "+tc.own, func(t *testing.T) {
			src := strings.NewReplacer("MARK", tc.mark, "OWN", tc.own).Replace(spellGate)
			dir := module(t, map[string]string{"gate.go": src})
			ms, err := FindMutants(dir, dir)
			if tc.mutants == 0 {
				if err == nil {
					t.Fatalf("no error, %d mutants", len(ms))
				}
				if !strings.Contains(err.Error(), proseHint) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || len(ms) != tc.mutants {
				t.Fatalf("err %v, %d mutants", err, len(ms))
			}
		})
	}
}

// The hint is true of a comment on its own line too.
func TestTheMarkerHintFitsAnOwnLine(t *testing.T) {
	dir := module(t, map[string]string{"gate.go": gate3 + "\n//subpoena:enforcement_x\nvar Note = 1\n"})
	_, err := FindMutants(dir, dir)
	if err == nil || strings.Contains(err.Error(), "on a line of code, a comment") {
		t.Fatalf("err = %v", err)
	}
}

func TestSwappedIsOneSwapOfNeighbours(t *testing.T) {
	is := func(s string) bool { return s == "subpoena" }
	for s, want := range map[string]bool{"subpoena": true, "subpeona": true, "usbpoena": true, "subpoean": true, "subpoen": false, "supboean": false, "sbupoean": false} {
		if got := swapped(s, is); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
}
