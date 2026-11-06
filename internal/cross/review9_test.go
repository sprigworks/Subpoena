//subpoena:impl_derived

package cross

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// Review 9, H1. The test that caught the mutant has its name in a package that
// hangs, or that package hangs before any test, so every try that runs all the
// packages hangs, the failed test's name alone included.
func TestAHangATestNameOrTestMainReachesCostsNoKill(t *testing.T) {
	t.Parallel()
	const refused = `package a

import ("testing"; "mini")

func TestCheck(t *testing.T) {
	if mini.Check("mallory") == nil { t.Fatal("mallory let in") }
}
`
	for name, hang := range map[string]string{
		"same name": `package z

import ("testing"; "time"; "mini")

func TestCheck(t *testing.T) {
	if mini.Check("mallory") == nil { time.Sleep(time.Hour) }
}
`,
		"TestMain": `package z

import ("os"; "testing"; "time"; "mini")

func TestMain(m *testing.M) {
	if mini.Check("mallory") == nil { time.Sleep(time.Hour) }
	os.Exit(m.Run())
}

func TestOther(t *testing.T) {}
`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "a/a_test.go": refused, "z/z_test.go": hang})
			if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Killed {
				t.Fatalf("a real kill was lost: %+v", r)
			}
		})
	}
}

// The same hang, and the test that caught the mutant needs an earlier test in its
// package: the first run's command has to go in that package alone.
func TestAKillThatNeedsAnEarlierTestHoldsWhenAnotherPackageHangs(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3,
		"a/a_test.go": `package a

import ("testing"; "mini")

var ready bool

func TestSetup(t *testing.T) { ready = true }
func TestCheck(t *testing.T) {
	if ready && mini.Check("mallory") == nil { t.Fatal("mallory let in") }
}
`,
		"z/z_test.go": `package z

import ("testing"; "time"; "mini")

func TestCheck(t *testing.T) {
	if mini.Check("mallory") == nil { time.Sleep(time.Hour) }
}
`})
	if r := killOf(t, Options{Target: dir, Timeout: 30 * time.Second}); r.Outcome != Killed {
		t.Fatalf("a real kill was lost: %+v", r)
	}
}

func TestLastTriesGoAPackageAtATime(t *testing.T) {
	args := []string{"-json", "-run", "^TestSelected$", "./...", "-args", "-test.failfast"}
	first := map[testID]bool{{"a", "TestA"}: true, {"b", "TestB"}: true}
	raw := event("run", "a", "TestA", "") + event("run", "b", "TestB", "") + event("pass", "c", "", "")
	got := lastTries(args, raw, first)
	want := [][]string{
		args,
		{"-json", "-run", "^TestSelected$", "a", "-args", "-test.failfast"},
		{"-json", "-run", "^TestSelected$", "-run", "^(TestA)$", "a"},
		{"-json", "-run", "^TestSelected$", "b", "-args", "-test.failfast"},
		{"-json", "-run", "^TestSelected$", "-run", "^(TestB)$", "b"},
	}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Fatalf("got %q", got)
	}
	// One package: the command in it is the command, so it does not go twice.
	one := map[testID]bool{{"a", "TestA"}: true}
	if got := lastTries(args, event("run", "a", "TestA", ""), one); len(got) != 2 {
		t.Fatalf("one package: %q", got)
	}
}

// A hang in the failed package itself is the part this cannot reach. It stays
// unconfirmed, and must not send the reader after a flake.
func TestAHangInTheFailedPackageSaysSoAndNotFlake(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import ("testing"; "time")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil {
		if nth > 2 { time.Sleep(time.Hour) }
		t.Fatal("mallory let in")
	}
}
`})
	r := killOf(t, Options{Target: dir, Timeout: 15 * time.Second})
	if r.Outcome != Unconfirmed || r.Why != noFinish || !r.Hung {
		t.Fatalf("got %+v", r)
	}
}

// A crash on the repeat keeps its reason, and if every last try then hangs, that is
// still no flake.
func TestACrashThenHangsIsCalledHung(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import ("testing"; "time")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil {
		if nth == 3 { panic("died") }
		if nth > 3 { time.Sleep(time.Hour) }
		t.Fatal("mallory let in")
	}
}
`})
	r := killOf(t, Options{Target: dir, Timeout: 15 * time.Second})
	if r.Outcome != Unconfirmed || !strings.Contains(r.Why, "crashed") || !r.Hung {
		t.Fatalf("got %+v", r)
	}
}

// A try that finished says more than one that hung: here the test passes alone, so
// that is the reason, and the flake advice is right.
func TestAFlakeBehindAHangIsCalledWhatItIs(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import ("testing"; "time")

func TestFlaky(t *testing.T) {
	if nth == 2 { t.Fatal("timing flake") }
}
func TestLater(t *testing.T) {
	if Check("mallory") == nil { time.Sleep(time.Hour) }
}
`})
	r := killOf(t, Options{Target: dir, Timeout: 15 * time.Second})
	if r.Outcome != Unconfirmed || r.Why == noFinish || r.Hung {
		t.Fatalf("got %+v", r)
	}
}

// Review 9, M1. A witness failure outlives a printed pass, so that real kill stands.
func TestAPrintedPassDoesNotUndoARealWitnessKill(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"plain":   `fmt.Print("\x16--- PASS: TestRefused (0.00s)\n"); t.Error(signed("witness: mallory reached the sink"))`,
		"subtest": `fmt.Print("\x16--- PASS: TestRefused (0.00s)\n"); t.Run("s", func(t *testing.T) {}); t.Error(signed("witness: mallory reached the sink"))`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": `package mini

import ("fmt"; "testing")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil { ` + body + ` }
}
`})
			r := killOf(t, Options{Target: dir, RequireWitness: true})
			if r.Outcome != Killed || r.Evidence != EvidenceWitness {
				t.Fatalf("a real kill was lost: %+v", r)
			}
		})
	}
}

// Review 10, H3 undid the rest of review 9's M1: a pass ends a test, whichever way
// round its events came, and only a mark outlives one.
func TestAPassEndsATestUnlessAWitnessFailureOutlivesIt(t *testing.T) {
	const a, b = "TestA", "TestB"
	end := event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	boom := event("output", "p", a, "    a_test.go:1: boom\n")
	mark := event("output", "p", a, "    a_test.go:1: "+crossmark.Sign(testKey, "witness: boom")+"\n")
	forged := event("output", "p", a, "    a_test.go:1: "+crossmark.Sign("not the key", "witness: boom")+"\n")
	bare := event("output", "p", a, "    a_test.go:1: witness: boom\n")
	real := event("run", "p", b, "") + event("output", "p", b, "    b_test.go:1: boom\n") + event("fail", "p", b, "")
	run, pass, fail := event("run", "p", a, ""), event("pass", "p", a, ""), event("fail", "p", a, "")
	for name, tc := range map[string]struct {
		raw  string
		want []string
	}{
		"pass then fail, either printed": {run + pass + boom + fail + end, nil},
		"printed fail, real pass":        {run + fail + pass + real + end, []string{b}},
		"printed fail, real skip":        {run + fail + event("skip", "p", a, "") + real + end, []string{b}},
		"real pass, a later test prints": {run + pass + real + fail + end, []string{b}},
		"a subtest starts in between":    {run + pass + event("run", "p", a+"/s", "") + event("pass", "p", a+"/s", "") + boom + fail + end, nil},
		"another package's test starts":  {run + pass + event("run", "q", b, "") + boom + fail + end, nil},
		"witness, printed pass first":    {run + pass + mark + fail + end, []string{a}},
		"witness, printed pass after":    {run + mark + fail + pass + end, []string{a}},
		"witness, printed skip first":    {run + event("skip", "p", a, "") + mark + fail + end, []string{a}},
		"witness, another test between":  {run + pass + event("run", "p", b, "") + mark + fail + end, nil},
		"witness, own subtest between":   {run + pass + event("run", "p", a+"/s", "") + mark + fail + end, []string{a}},
		"witness, a test after the fail": {run + mark + fail + event("run", "p", b, "") + pass + end, []string{a}},
		"another key's mark":             {run + pass + forged + fail + end, nil},
		"a tag with no mark":             {run + pass + bare + fail + end, nil},
		"a witness that never ran":       {pass + mark + fail + end, nil},
	} {
		var got []string
		for k := range failedTests(tc.raw, testKey) {
			got = append(got, k.test)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q", name, got)
		}
	}
}
