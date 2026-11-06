//subpoena:impl_derived

package cross

import (
	"slices"
	"testing"
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
}
