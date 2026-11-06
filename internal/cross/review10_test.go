//subpoena:impl_derived

package cross

import (
	"slices"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// Review 10, H1. A printed fail in a package that went green is no failure, however
// real its events look, so a crash elsewhere stays the crash it is.
const framedGhost = `fmt.Print("\x16=== RUN   TestGhost\n\x16--- FAIL: TestGhost (0.00s)\n    a_test.go:1: mallory let in\n")`

func TestAFailPrintedInAGreenPackageCarriesNoKill(t *testing.T) {
	t.Parallel()
	for name, print := range map[string]string{
		"from a test":         "func TestFine(t *testing.T) { " + framedGhost + " }\n",
		"from init, unmarked": `func init() { fmt.Print("=== RUN   TestGhost\n--- FAIL: TestGhost (0.00s)\n    a_test.go:1: mallory let in\n") }` + "\nfunc TestFine(t *testing.T) {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3,
				"a/a_test.go": "package a\n\nimport (\"fmt\"; \"testing\")\n\n" + print,
				"b/b_test.go": `package b

import ("testing"; "mini")

func TestCrash(t *testing.T) {
	if mini.Check("mallory") == nil { panic("somewhere unrelated") }
}
`})
			if r := killOf(t, Options{Target: dir}); r.Outcome != Crashed {
				t.Fatalf("a crash read as a kill: %+v", r)
			}
		})
	}
}

func TestOnlyAPackageThatExitedOneFails(t *testing.T) {
	ghost := event("run", "green", "TestGhost", "") + event("output", "green", "TestGhost", "    a_test.go:1: mallory let in\n") + event("fail", "green", "TestGhost", "")
	if fs := failures(ghost); len(fs) != 0 {
		t.Errorf("a package with no exit event gave %+v", fs)
	}
	if finishedFailure(ghost) {
		t.Error("a package with no exit event finished failing")
	}
	// A real failed package beside it keeps its own, and only its own.
	red := failedRun("red", "TestRefused", "mallory let in")
	if got := failedPackages(ghost + red); !slices.Equal(got, []string{"red"}) {
		t.Errorf("failed packages: %q", got)
	}
	fs := failures(ghost + red)
	if len(fs) != 1 || fs[0].pkg != "red" {
		t.Errorf("failures: %+v", fs)
	}
	// A binary that died is still named: stoppedShort goes by it.
	raw := event("run", "d", "TestA", "") + event("fail", "d", "", "") + exitEvent("d", "2") + "\n"
	if _, dead := readFailures(raw + red); !dead["d"] || dead["red"] {
		t.Errorf("dead: %v", dead)
	}
}

// Review 10, H3. Every test passed, TestMain exited 1 on the mutant, and a fail was
// printed after the real pass. That is no kill, from whichever code printed it.
func TestAFailPrintedAfterARealPassIsNoKill(t *testing.T) {
	t.Parallel()
	const print = `fmt.Print("\x16--- FAIL: TestLast (0.00s)\n    a_test.go:4: mallory let in\n")`
	for name, printer := range map[string]string{
		"TestMain": "if mini.Check(\"mallory\") == nil { " + print + "; code = 1 }",
		"teardown": print + "; if mini.Check(\"mallory\") == nil { code = 1 }",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "a/a_test.go": `package a

import ("fmt"; "os"; "testing"; "mini")

func TestLast(t *testing.T) { if mini.Check("admin") != nil { t.Fatal("admin refused") } }
func TestMain(m *testing.M) {
	code := m.Run()
	` + printer + `
	os.Exit(code)
}
`})
			if r := killOf(t, Options{Target: dir}); r.Outcome != Unconfirmed {
				t.Fatalf("no test failed: %+v", r)
			}
		})
	}
}

// The same with the run line printed too, so the test has no pass. Its binary said
// PASS, which only m.Run with every test passed says.
func TestAGhostFromABinaryThatSaidPassIsNoKill(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "a/a_test.go": `package a

import ("fmt"; "os"; "testing"; "mini")

func TestLast(t *testing.T) {}
func TestMain(m *testing.M) {
	code := m.Run()
	if mini.Check("mallory") == nil {
		` + framedGhost + `
		code = 1
	}
	os.Exit(code)
}
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Unconfirmed {
		t.Fatalf("no test failed: %+v", r)
	}
}

func TestPassSaidByTheBinaryLeavesOnlyAMark(t *testing.T) {
	end := event("output", "p", "", "PASS\n") + event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	run, fail := event("run", "p", "TestA", ""), event("fail", "p", "TestA", "")
	plain := event("output", "p", "TestA", "    a_test.go:1: boom\n")
	witness := event("output", "p", "TestA", "    a_test.go:1: "+crossmark.Sign(testKey, "witness: boom")+"\n")
	if got := failedTests(run+plain+fail+end, testKey); len(got) != 0 {
		t.Errorf("plain: %v", got)
	}
	if got := failedTests(run+witness+fail+end, testKey); !got[testID{"p", "TestA"}] {
		t.Errorf("witness: %v", got)
	}
	// A test's own output saying PASS is no word from the binary.
	said := event("output", "p", "TestA", "PASS\n") + event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	if got := failedTests(run+plain+fail+said, testKey); !got[testID{"p", "TestA"}] {
		t.Errorf("a test's line: %v", got)
	}
}

// A printed pass costs a plain kill, and says so: red, and no kill. This is the side
// to lose on, and the test holds it there. A witness failure keeps its kill.
func TestAPrintedPassCostsAPlainKillLoudly(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "testing")

func TestRefused(t *testing.T) {
	if Check("mallory") == nil {
		fmt.Print("\x16--- PASS: TestRefused (0.00s)\n")
		t.Error("mallory let in")
	}
}
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Unconfirmed {
		t.Fatalf("got %+v", r)
	}
}

// Review 10, H2. A crash line in a test that failed is a crash, and a printed pass
// must not turn that off, ahead of the real fail or after it, witness failure or not.
func TestAPrintedPassDoesNotHideACrashLine(t *testing.T) {
	t.Parallel()
	const pass = `fmt.Print("\x16--- PASS: TestRefused (0.00s)\n\x16=== NAME  TestRefused\n")`
	test := func(failure, late string) string {
		return `package mini

import ("fmt"; "os"; "testing")

func TestRefused(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %v\n", r)
			t.Error(` + failure + `)
		}
	}()
	if Check("mallory") == nil {
		` + pass + `
		var m map[string]int
		m["x"] = 1
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	` + late + `
	os.Exit(code)
}
`
	}
	for name, src := range map[string]string{
		"plain":         test(`"mallory let in"`, ""),
		"witness":       test(`signed("witness: mallory reached the sink")`, ""),
		"pass after it": test(`signed("witness: mallory reached the sink")`, `fmt.Print("\x16--- PASS: TestRefused (0.00s)\n")`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": src})
			r := killOf(t, Options{Target: dir, RequireWitness: true})
			if r.Outcome != Crashed || !strings.Contains(r.Output, "panic: ") {
				t.Fatalf("a crash was read as something else: %+v", r)
			}
		})
	}
}

func TestACrashLineIsCrashUnlessTheTestCleanlyPassed(t *testing.T) {
	end := event("fail", "p", "", "") + exitEvent("p", "1") + "\n"
	run, boom := event("run", "p", "TestA", ""), event("output", "p", "TestA", "panic: boom\n")
	line := event("output", "p", "TestA", "    a_test.go:1: boom\n")
	pass, fail := event("pass", "p", "TestA", ""), event("fail", "p", "TestA", "")
	for name, tc := range map[string]struct {
		raw  string
		dead bool
	}{
		"failed":                  {run + boom + line + fail + end, true},
		"printed pass, real fail": {run + pass + boom + line + fail + end, true},
		"real fail, printed pass": {run + boom + line + fail + pass + end, true},
		"a passing test's log":    {run + boom + pass + failedRun("p", "TestB", "real"), false},
	} {
		if _, dead := readFailures(tc.raw); dead["p"] != tc.dead {
			t.Errorf("%s: dead %v", name, dead)
		}
		if got := crashOutput(tc.raw, 5); tc.dead && !strings.Contains(got, "panic: boom") {
			t.Errorf("%s: shown %q", name, got)
		}
	}
}
