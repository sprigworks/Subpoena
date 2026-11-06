//subpoena:impl_derived

package cross

import (
	"slices"
	"strings"
	"testing"
	"time"
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

// Review 9, M1. A printed pass comes before the real fail, so the test's last ending
// decides, and the real kill stands, witness evidence included.
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

func TestATestsLastEndingDecides(t *testing.T) {
	const a, b = "TestA", "TestB"
	end := event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	boom := event("output", "p", a, "    a_test.go:1: boom\n")
	real := event("run", "p", b, "") + event("output", "p", b, "    b_test.go:1: boom\n") + event("fail", "p", b, "")
	for name, tc := range map[string]struct {
		raw  string
		want []string
	}{
		"printed pass, real fail":        {event("run", "p", a, "") + event("pass", "p", a, "") + boom + event("fail", "p", a, "") + end, []string{a}},
		"printed fail, real pass":        {event("run", "p", a, "") + event("fail", "p", a, "") + event("pass", "p", a, "") + real + end, []string{b}},
		"printed fail, real skip":        {event("run", "p", a, "") + event("fail", "p", a, "") + event("skip", "p", a, "") + real + end, []string{b}},
		"real pass, a later test prints": {event("run", "p", a, "") + event("pass", "p", a, "") + real + event("fail", "p", a, "") + end, []string{b}},
		"a subtest starts in between":    {event("run", "p", a, "") + event("pass", "p", a, "") + event("run", "p", a+"/s", "") + event("pass", "p", a+"/s", "") + boom + event("fail", "p", a, "") + end, []string{a}},
		"another package's test starts":  {event("run", "p", a, "") + event("pass", "p", a, "") + event("run", "q", b, "") + boom + event("fail", "p", a, "") + end, []string{a}},
	} {
		var got []string
		for k := range failedTests(tc.raw) {
			got = append(got, k.test)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q", name, got)
		}
	}
}
