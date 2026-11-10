//subpoena:impl_derived

package cross

import (
	"strings"
	"testing"
)

// Review 11, H3. A TestMain that calls m.Run twice gets a run of nothing the second
// time under -test.failfast, and that run's PASS is package testing's own. The failed
// test is real, so the kill stands. A PASS the run without -test.failfast says too
// still gives no failed test, so this buys no ghost a kill.
func TestASecondMRunDoesNotCostARealKill(t *testing.T) {
	t.Parallel()
	const refused = `func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`
	const ghost = `func TestFine(t *testing.T) {}
`
	const ghostMain = `func TestMain(m *testing.M) {
	first, second := m.Run(), m.Run()
	fmt.Print("\x16=== RUN   TestGhost\n\x16--- FAIL: TestGhost (0.00s)\n    a_test.go:1: mallory let in\n")
	if Check("mallory") == nil { os.Exit(1) }
	os.Exit(first | second)
}
`
	for name, tc := range map[string]struct {
		main, tests string
		want        Outcome
	}{
		"either run fails":  {"func TestMain(m *testing.M) { first := m.Run(); second := m.Run(); os.Exit(first | second) }\n", refused, Killed},
		"first run decides": {"func TestMain(m *testing.M) { first := m.Run(); second := m.Run(); if first != 0 { os.Exit(first) }; os.Exit(second) }\n", refused, Killed},
		// The binary says PASS with every test passed, so a printed fail is nothing.
		"a ghost, every test passed": {ghostMain, ghost, Unconfirmed},
		// The cost: a suite that truly passes its second m.Run says PASS beside the
		// failure in any run. It stays red and loud.
		"the second run truly passes": {"func TestMain(m *testing.M) { first := m.Run(); disk = true; second := m.Run(); os.Exit(first | second) }\n",
			`func TestRefused(t *testing.T) { if !disk && Check("mallory") == nil { t.Fatal("mallory let in") } }
`, Unconfirmed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("fmt"; "os"; "testing")

var _ = fmt.Sprint
var disk bool

` + tc.main + tc.tests})
			if r := killOf(t, Options{Target: dir}); r.Outcome != tc.want {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

// Review 11, H2. A framed NAME line can put a real crash line on a test that passed,
// or will. Under RequireWitness that is a crash wherever it landed: a witness kill is
// the verdict that has to hold against printed text.
func TestACrashLineMovedByAFramedLineIsNoWitnessKill(t *testing.T) {
	t.Parallel()
	test := func(print string) string {
		return `package mini

import ("fmt"; "testing")

func TestAdmin(t *testing.T) {}

func TestRefused(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Print(` + print + `)
			t.Error(signed("witness: mallory reached the sink"))
		}
	}()
	if Check("mallory") == nil { panic("nil map") }
}

func TestLater(t *testing.T) {}
`
	}
	for name, print := range map[string]string{
		"onto a test that passed":    `"\x16=== NAME  TestAdmin\npanic: nil map\n\x16=== NAME  TestRefused\n"`,
		"onto a test yet to run":     `"\x16=== NAME  TestLater\npanic: nil map\n\x16=== NAME  TestRefused\n"`,
		"onto a test that never ran": `"\x16=== RUN   TestGhost\npanic: nil map\n\x16--- PASS: TestGhost (0.00s)\n\x16=== NAME  TestRefused\n"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := module(t, map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": test(print)})
			if r := killOf(t, Options{Target: dir, RequireWitness: true}); r.Outcome != Crashed {
				t.Fatalf("a crash read as something else: %+v", r)
			}
		})
	}
}

// A witness failure with no crash line anywhere still kills, and a passing test's
// log line in a plain run is still a log line.
func TestACrashLineRuleLeavesOrdinaryRunsAlone(t *testing.T) {
	t.Parallel()
	const log = `package mini

import ("fmt"; "testing")

func TestLogs(t *testing.T) { fmt.Println("panic: recovered and logged") }

func TestRefused(t *testing.T) {
	if Check("mallory") == nil { t.Error(signed("witness: mallory reached the sink")) }
}
`
	files := func(src string) map[string]string {
		return map[string]string{"gate.go": gate3, "signed_test.go": signedHelper, "gate_test.go": src}
	}
	if r := killOf(t, Options{Target: module(t, files(log))}); r.Outcome != Killed {
		t.Errorf("a plain run lost a kill to a passing test's log line: %+v", r)
	}
	clean := strings.Replace(log, "panic: recovered", "recovered", 1)
	if r := killOf(t, Options{Target: module(t, files(clean)), RequireWitness: true}); r.Outcome != Killed || r.Evidence != EvidenceWitness {
		t.Errorf("a witness kill was lost: %+v", r)
	}
}

func TestCrashEventsNameFailedPackagesWithACrashLine(t *testing.T) {
	boom := func(pkg string) string { return event("output", pkg, "TestA", "panic: boom\n") }
	failed := func(pkg string) string { return event("fail", pkg, "", "") }
	raw := boom("crashed") + failed("crashed") + boom("green") + event("output", "quiet", "TestA", "fine\n") + failed("quiet")
	if got, want := crashEvents(raw), exitEvent("crashed", exitCrashLine)+"\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	coloured := event("output", "p", "TestA", "\x1b[38;5;9m• [PANICKED] [0.001 seconds]\x1b[0m\n") + failed("p")
	if crashEvents(coloured) == "" {
		t.Error("a coloured Ginkgo panic gave no event")
	}
	// The code is a death, whatever the binary's own exit said.
	if _, dead := readFailures(raw + exitEvent("crashed", "1") + "\n" + crashEvents(raw)); !dead["crashed"] {
		t.Errorf("dead: %v", dead)
	}
}
