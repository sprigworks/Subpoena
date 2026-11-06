//subpoena:impl_derived

package cross

import "testing"

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
