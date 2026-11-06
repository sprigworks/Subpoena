//subpoena:impl_derived

package cross

import (
	"context"
	"path/filepath"
	"slices"
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

// staleSuite gives a test that fails on any binary run after the first, for a reason
// that has nothing to do with the code, through a TestMain that calls m.Run as main
// says. Under -test.failfast a second m.Run is a run of nothing and exits 0, so a
// rerun with that flag cannot see this.
func staleSuite(t *testing.T, fails, main string) map[string]string {
	state := filepath.Join(t.TempDir(), "state")
	return map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": `package mini

import ("os"; "testing")

const state = "` + state + `"

var stale = func() bool { _, err := os.Stat(state); return err == nil }()

func TestCache(t *testing.T) { if stale { ` + fails + ` } }

func TestAdmin(t *testing.T) { if Check("admin") != nil { t.Fatal("admin refused") } }

func TestMain(m *testing.M) {
	` + main + `
	os.WriteFile(state, nil, 0o644)
	os.Exit(code)
}
`}
}

// Review 12, first High. The reruns without the mutant kept -test.failfast, so a
// suite that fails with no mutant at all read green there and its red stood as a kill.
func TestARerunIsNotBlindToATestMainThatCallsMRunAgain(t *testing.T) {
	t.Parallel()
	const plain = `t.Fatal("stale cache from a previous run")`
	for name, tc := range map[string]struct {
		fails, main string
		witness     bool
	}{
		"the last m.Run decides": {plain, "m.Run(); code := m.Run()", false},
		"a retry":                {plain, "code := 0; for i := 0; i < 3; i++ { if code = m.Run(); code == 0 { break } }", false},
		"a retry, under witness": {`t.Error(signed("witness: a file from an earlier run is on disk"))`, "code := 0; for i := 0; i < 3; i++ { if code = m.Run(); code == 0 { break } }", true},
		"control, one m.Run":     {plain, "code := m.Run()", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := killOf(t, Options{Target: module(t, staleSuite(t, tc.fails, tc.main)), RequireWitness: tc.witness})
			if r.Outcome != Unconfirmed || r.Why != "the suite failed without the mutant" {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// The reruns without the flag take nothing from a real kill: green is green.
func TestAKillThroughASecondMRunStillHoldsItsReruns(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("os"; "testing")

func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }

func TestMain(m *testing.M) { first := m.Run(); second := m.Run(); os.Exit(first | second) }
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Killed {
		t.Fatalf("got %+v", r)
	}
}

// killReruns is 1 in this package's tests, so the narrowed reruns are pinned here.
func TestRerunsGoWithoutFailfastWholeThenNarrow(t *testing.T) {
	t.Parallel()
	whole := []string{"-json", "-count=1", "-failfast=false", "./...", "-args", "-test.failfast"}
	for n, want := range [][]string{
		{"-json", "-count=1", "-failfast=false", "./..."},
		{"-json", "-count=1", "-failfast=false", "mini/a"},
	} {
		if got := rerunArgs(whole, []string{"mini/a"}, n); !slices.Equal(got, want) {
			t.Fatalf("rerun %d: got %q", n, got)
		}
	}
	if got := rerunArgs(whole, nil, 1); !slices.Equal(got, whole[:4]) {
		t.Fatalf("no failed package: got %q", got)
	}
}

// Review 12, H4. TestMain throws away a first m.Run's output, so under -test.failfast
// the second m.Run leaves a green run with nothing in it to say a test failed, though
// the suite catches the mutant. A green first run goes again without the flag, always.
func TestAQuietFirstMRunDoesNotHideAKill(t *testing.T) {
	t.Parallel()
	const quiet = `out := os.Stdout
	os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	code := m.Run()
	os.Stdout = out
`
	const plain = `t.Fatal("mallory let in")`
	for name, tc := range map[string]struct {
		main, fails string
		witness     bool
		want        Outcome
	}{
		"warm-up":            {quiet + "code = m.Run()\n", plain, false, Killed},
		"retry":              {quiet + "if code != 0 { code = m.Run() }\n", plain, false, Killed},
		"retry, witness":     {quiet + "if code != 0 { code = m.Run() }\n", `t.Fatal(signed("witness: mallory reached the sink"))`, true, Killed},
		"retry, self-report": {quiet + "if code != 0 { code = m.Run() }\n", plain, true, KilledBySelfReport},
		// A real survivor: no test looks at mallory, with or without the flag.
		"nothing catches it": {quiet + "code = m.Run()\n", "", false, Survived},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := `if Check("mallory") == nil { ` + tc.fails + ` }`
			if tc.want == Survived {
				body = ""
			}
			dir := module(t, map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": `package mini

import ("os"; "testing")

func TestRefused(t *testing.T) { ` + body + ` }

func TestMain(m *testing.M) {
	` + tc.main + `	os.Exit(code)
}
`})
			r := killOf(t, Options{Target: dir, RequireWitness: tc.witness})
			if r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
			if tc.witness && tc.want == Killed && r.Evidence != EvidenceWitness {
				t.Fatalf("evidence: %+v", r)
			}
		})
	}
}

// Review 12, H3. Package testing's own frames carry a line printed with no frame to
// whichever test printed last, so two parallel tests can put one's panic line on the
// other. Beside a test that did not pass, a crash line on a passing test is a crash.
// Where nothing ran beside anything the line stays a log line.
func TestACrashLineOnATestBesideAFailureIsACrash(t *testing.T) {
	t.Parallel()
	const refused = `func TestRefused(t *testing.T) {
	PAR
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %v\n", r)
			t.Fatal("handler died")
		}
	}()
	time.Sleep(200 * time.Millisecond)
	if Check("mallory") == nil { var m map[string]int; m["x"] = 1 }
}

func TestAdmin(t *testing.T) {
	PAR
	if Check("admin") != nil { t.Fatal("admin refused") }
	time.Sleep(600 * time.Millisecond)
}
`
	const logs = `func TestLogs(t *testing.T) { fmt.Println("panic: recovered and logged") }

func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`
	const table = `func TestCheck(t *testing.T) {
	for _, user := range []string{"mallory", "admin"} {
		t.Run(user, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("panic: %v\n", r)
					t.Fatal("handler died")
				}
			}()
			if user == "admin" { time.Sleep(600 * time.Millisecond); return }
			time.Sleep(200 * time.Millisecond)
			if Check("mallory") == nil { var m map[string]int; m["x"] = 1 }
		})
	}
}
`
	// Two subtests in turn inside a parallel test ran one after the other.
	const inTurn = `func TestOuter(t *testing.T) {
	t.Parallel()
	t.Run("logs", func(t *testing.T) { fmt.Println("panic: recovered and logged") })
	t.Run("refused", func(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } })
}

func TestOther(t *testing.T) { t.Parallel() }
`
	// Each pair of parallel subtests waits for its parent, so these two groups never meet.
	const apart = `func TestFirst(t *testing.T) {
	t.Run("logs", func(t *testing.T) { t.Parallel(); fmt.Println("panic: recovered and logged") })
}

func TestSecond(t *testing.T) {
	t.Run("refused", func(t *testing.T) { t.Parallel(); if Check("mallory") == nil { t.Fatal("mallory let in") } })
}
`
	for name, tc := range map[string]struct {
		tests string
		want  Outcome
	}{
		"parallel":               {strings.ReplaceAll(refused, "PAR", "t.Parallel()"), Crashed},
		"parallel subtests":      {table, Crashed},
		"not parallel":           {strings.ReplaceAll(refused, "PAR", ""), Crashed},
		"sequential log line":    {logs, Killed},
		"subtests in turn":       {inTurn, Killed},
		"groups that never meet": {apart, Killed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "testing"; "time")

var _ = time.Now

` + tc.tests})
			if r := killOf(t, Options{Target: dir}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// -parallel 1: both tests pause and continue, one after the other. Nothing ran beside.
func TestParallelTestsThatTookTurnsWereNotBeside(t *testing.T) {
	t.Parallel()
	turn := func(k eventKey, end string, more ...string) string {
		return event("cont", k[0], k[1], "") + strings.Join(more, "") + event(end, k[0], k[1], "")
	}
	a, b := eventKey{"p", "TestA"}, eventKey{"p", "TestB"}
	apart := endings(turn(a, "pass") + turn(b, "fail"))
	if besideFailure(apart, a) {
		t.Fatal("in turn: beside")
	}
	together := endings(event("cont", "p", "TestA", "") + turn(b, "fail") + event("pass", "p", "TestA", ""))
	if !besideFailure(together, a) {
		t.Fatal("overlapping: not beside")
	}
}

// Review 12, H5. testify's suite recovers a panic and reports it with t.Errorf, so the
// line has no column 0 to read as a crash. This is its shape; a fixture module cannot
// import testify. A crash is not a kill, whatever the test did with it.
func TestAPanicAFrameworkRecoveredIsACrash(t *testing.T) {
	t.Parallel()
	const recovers = `defer func() {
		if r := recover(); r != nil {
			t.Errorf("test panicked: %v\n%s", r, "goroutine 7 [running]:")
			t.FailNow()
		}
	}()
	if Check("mallory") == nil { var m map[string]int; m["x"] = 1 }`
	for name, tc := range map[string]struct {
		body    string
		witness bool
		want    Outcome
	}{
		"recovered":       {recovers, false, Crashed},
		"under witness":   {recovers, true, Crashed},
		"after open text": {`fmt.Print("no newline"); ` + recovers, false, Crashed},
		"a plain failure": {`if Check("mallory") == nil { t.Fatal("mallory let in") }`, false, Killed},
		// The cost: the same words logged by a test that fails read crashed.
		"logged, and failed": {`t.Log("test panicked: a story"); if Check("mallory") == nil { t.Fatal("mallory let in") }`, false, Crashed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "testing")

var _ = fmt.Sprint

func TestRefused(t *testing.T) {
	` + tc.body + `
}
`})
			if r := killOf(t, Options{Target: dir, RequireWitness: tc.witness}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// The same line in a test that passed is a log line, as any crash line is.
func TestAPanicLineInAPassingTestIsALogLine(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import "testing"

func TestLogs(t *testing.T) { t.Log("test panicked: a story") }

func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Killed {
		t.Fatalf("got %+v", r)
	}
}
