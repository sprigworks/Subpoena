//subpoena:impl_derived

package cross

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// counted is a test file's helper: run() is the number of this test binary's
// run, counted in a file outside the copy, the baseline being 1 and the mutant
// run 2. It makes a flake happen on a chosen run.
func counted(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "count")
	return fmt.Sprintf(`package mini

import (
	"os"
	"strconv"
	"strings"
)

func run() int {
	b, _ := os.ReadFile(%q)
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	n++
	os.WriteFile(%q, []byte(strconv.Itoa(n)), 0o644)
	return n
}

var nth = run()
`, path, path)
}

func killOf(t *testing.T, o Options) Result {
	t.Helper()
	_, r := outcome(t, o)
	return r
}

// Finding 2. -failfast on the repeat stops at the first test that catches the
// mutant, and that need not be the one the first run stopped at: -shuffle makes it
// so at random, this makes it so on the repeat. Both tests catch the mutant.
func TestARepeatRunsPastAnotherTestThatCaughtTheMutant(t *testing.T) {
	t.Parallel()
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

// With no -failfast the repeat reaches tests the mutant run never did. One that
// the mutant crashes or hangs says nothing of the test that caught it.
func TestATestOnlyTheRepeatReachesCannotLoseAKill(t *testing.T) {
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

func TestARefused(t *testing.T) {
	if Check("mallory") == nil { t.Fatal("mallory let in") }
}
func TestBLater(t *testing.T) {
	if Check("mallory") == nil { ` + body + ` }
}
`})
			if r := killOf(t, Options{Target: dir, Timeout: 20 * time.Second}); r.Outcome != Killed {
				t.Fatalf("a real kill was lost: %+v", r)
			}
		})
	}
}

// That second look is no second chance: the first command must then be a clean
// kill of the same test, and here it passes.
func TestACrashOnTheRepeatStaysUnconfirmedIfTheFirstCommandPasses(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import "testing"

func TestFlake(t *testing.T) {
	if nth == 2 { t.Fatal("timing") }
	if nth == 3 { panic("died") }
}
func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
`})
	r := killOf(t, Options{Target: dir})
	if r.Outcome != Unconfirmed || !strings.Contains(r.Why, "crashed") {
		t.Fatalf("got %+v", r)
	}
}

// Finding 9, with R5's finding 4 as its mirror (TestAFailureThatNeedsAnother...):
// the test that noticed needs a test in another package to run first.
func TestARepeatKeepsAKillThatShowsInAnotherPackage(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3,
		"a/a_test.go": `package a

import (
	"os"
	"testing"

	"mini"
)

func TestDrive(t *testing.T) {
	if mini.Check("mallory") == nil { os.WriteFile("../b/admitted", nil, 0o644) }
}
`, "b/b_test.go": `package b

import (
	"os"
	"testing"
	"time"

	_ "mini"
)

func TestNobodyAdmitted(t *testing.T) {
	time.Sleep(2 * time.Second)
	if _, err := os.Stat("admitted"); err == nil { t.Fatal("the audit log holds an admission") }
}
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Killed {
		t.Fatalf("a real kill was lost: %+v", r)
	}
}

// Finding 3. A test's log can hold the line go test prints for a failure.
func TestPrintedTextNamesNoFailedTest(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import "testing"

func TestFlaky(t *testing.T) { if nth == 2 { t.Fatal("timing flake") } }
func TestOther(t *testing.T) {
	if nth == 3 {
		t.Logf("nested run said:\n%s", "--- FAIL: TestFlaky (0.00s)")
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

func TestFailedTestsComeFromFailEvents(t *testing.T) {
	raw := strings.Join([]string{
		`{"Action":"run","Package":"p","Test":"TestB"}`,
		`{"Action":"run","Package":"p","Test":"TestB/sub"}`,
		`{"Action":"output","Package":"p","Test":"TestB","Output":"    x_test.go:1: boom\n"}`,
		`{"Action":"output","Package":"p","Test":"TestB","Output":"--- FAIL: TestForged (0.00s)\n"}`,
		`{"Action":"fail","Package":"p","Test":"TestB/sub"}`,
		`{"Action":"fail","Package":"p","Test":"TestB"}`,
		`{"Action":"fail","Package":"p"}`,
		exitEvent("p", "1"),
	}, "\n")
	if got := failingTests(raw); strings.Join(got, " ") != "TestB/sub TestB" {
		t.Fatalf("names %v", got)
	}
	got := failedTests(raw, testKey)
	if len(got) != 1 || !got[testID{"p", "TestB"}] {
		t.Fatalf("tests %v", got)
	}
}

// One test name in two packages is two tests.
func TestAFailedTestIsNamedWithItsPackage(t *testing.T) {
	line := func(pkg string) string {
		return strings.Join([]string{
			`{"Action":"run","Package":"` + pkg + `","Test":"TestX"}`,
			`{"Action":"output","Package":"` + pkg + `","Test":"TestX","Output":"    x_test.go:1: boom\n"}`,
			`{"Action":"fail","Package":"` + pkg + `","Test":"TestX"}`,
			exitEvent(pkg, "1"),
		}, "\n")
	}
	if why := notAKill(line("b"), fmt.Errorf("exit 1"), "k", failedTests(line("a"), testKey)); !strings.Contains(why, "different test") {
		t.Fatalf("why = %q", why)
	}
}

// Finding 4. The gate promises independent evidence, and here only one of the two
// runs with the mutant had any.
func TestRequireWitnessAsksTheRepeatToo(t *testing.T) {
	t.Parallel()
	test := func(repeat string) string {
		return `package mini

import "testing"

func TestRefused(t *testing.T) {
	if nth == 2 { t.Fatal(signed("witness: a connection arrived")) }
	if nth == 3 { t.Fatal(` + repeat + `) }
}
func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
`
	}
	files := func(body string) map[string]string {
		return map[string]string{"gate.go": gate3, "run_test.go": counted(t), "signed_test.go": signedHelper, "gate_test.go": body}
	}
	r := killOf(t, Options{Target: module(t, files(test(`"a plain assertion"`))), RequireWitness: true})
	if r.Outcome != KilledBySelfReport || r.Evidence != EvidenceOther || r.FirstFailure != "a plain assertion" || r.Why == "" {
		t.Fatalf("got %+v", r)
	}
	// Plain mode asks nothing of the evidence.
	if r := killOf(t, Options{Target: module(t, files(test(`"a plain assertion"`)))}); r.Outcome != Killed {
		t.Fatalf("got %+v", r)
	}
	r = killOf(t, Options{Target: module(t, files(test(`signed("witness: a connection arrived")`))), RequireWitness: true})
	if r.Outcome != Killed || r.Evidence != EvidenceWitness {
		t.Fatalf("a witness kill was lost: %+v", r)
	}
}

// Under -shuffle another test can fail ahead of the one that gave the witness
// evidence, and that test's plain failure takes nothing from it.
func TestRepeatEvidenceIsReadFromTheSameTest(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "signed_test.go": signedHelper, "gate_test.go": `package mini

import "testing"

func TestAAheadOnTheRepeat(t *testing.T) {
	if nth == 3 && Check("mallory") == nil { t.Fatal("a plain assertion") }
}
func TestBWitness(t *testing.T) {
	if Check("mallory") == nil { t.Fatal(signed("witness: a connection arrived")) }
}
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true})
	if r.Outcome != Killed || r.Evidence != EvidenceWitness {
		t.Fatalf("a witness kill was lost: %+v", r)
	}
}

const trailingGate = `package mini

var audited int

//subpoena:enforcement_point
func Check(u string) bool {
	if u != "admin" { //subpoena:enforcement_guard false
		return false
	}
	audited++ MARK
	return true
}
`

// Finding 6. A misspelt marker after upstream's comment is an error, as a misspelt
// marker that is the whole comment is, and one with no space before it is a marker.
func TestATrailingMarkerIsReadAsLooselyAsAWholeComment(t *testing.T) {
	for _, tc := range []struct {
		mark    string
		mutants int // 0 for an error
	}{
		{"//subpoena:enforcement_gaurd", 0},
		{"// keep count //subpoena:enforcement_gaurd", 0},
		{"// keep count //subpoena:enforcement: true", 0},
		{"// keep count //subpoena:enforcment", 0},
		{"// keep count // subpoena : enforcement", 0},
		{"// keep count//subpoena:enforcement", 2},
		{"// keep count //subpoena:enforcement", 2},
		{"// keep count //subpoena:enforcement_point of this function", 1},
		{"// keep count", 1},
	} {
		t.Run(tc.mark, func(t *testing.T) {
			dir := module(t, map[string]string{"gate.go": strings.Replace(trailingGate, "MARK", tc.mark, 1)})
			ms, err := FindMutants(dir, dir)
			if tc.mutants == 0 {
				if err == nil {
					t.Fatalf("no error, %d mutants", len(ms))
				}
				return
			}
			if err != nil || len(ms) != tc.mutants {
				t.Fatalf("err %v, %d mutants", err, len(ms))
			}
			if n, unplaced := markerCount(ms); n != tc.mutants || len(unplaced) != 0 {
				t.Fatalf("%d markers, unplaced %v", n, unplaced)
			}
		})
	}
}

// Finding 16. Trailing prose that names a marker stops the run, by design, and
// the error says what it read.
func TestAMarkerErrorSaysProseReadsAsAMarker(t *testing.T) {
	for name, src := range map[string]string{
		"outside a point": gate3 + "\nvar strict bool // on where the code carries //subpoena:enforcement markers\n",
		"inside a point":  strings.Replace(trailingGate, "MARK", "// the //subpoena:enforcement markers", 1),
	} {
		t.Run(name, func(t *testing.T) {
			dir := module(t, map[string]string{"gate.go": src})
			if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), "reads as one") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// Finding 8. The link check's advice belongs to the link check alone.
func TestOnlyTheLinkCheckGivesItsHint(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "gate_test.go": `package mini

import ("os"; "testing"; "time")

func TestMain(m *testing.M) {
	if nth >= 3 && nth <= 5 { time.Sleep(time.Hour) }
	os.Exit(m.Run())
}
func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`})
	r := killOf(t, Options{Target: dir, Timeout: 20 * time.Second})
	if r.Outcome != Unconfirmed || !strings.Contains(r.Why, "did not finish") || r.Hint != "" {
		t.Fatalf("hang: %+v", r)
	}
	dir = module(t, map[string]string{"gate.go": gate3, "other/other.go": "package other\n", "other/other_test.go": `package other

import "testing"

func TestRed(t *testing.T) { t.Fatal("red, with no link to the mutant") }
`})
	mutants, err := FindMutants(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	res := Result{Outcome: Killed}
	o := Options{Log: os.Stderr, Timeout: time.Minute}
	raw := `{"Action":"fail","Package":"mini/other","Test":"TestRed"}`
	if err := confirmKill(context.Background(), o, sandbox{dir: dir}, nil, raw, mutants, nil, &res); err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Unconfirmed || res.Hint != separateProgramHint {
		t.Fatalf("link: %+v", res)
	}
}

// Finding 10, R5 16. A block comment and a string that show a marker hold none.
func TestAMarkerShownInABlockCommentOrStringIsNotCounted(t *testing.T) {
	dir := module(t, map[string]string{"gate.go": gate3 + "\n/*\nMarking a line:\n   return nil // why //subpoena:enforcement\n*/\n\nvar usage = `\n   return nil // why //subpoena:enforcement\n`\n"})
	ms, err := FindMutants(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if n, unplaced := markerCount(ms); n != 1 || len(unplaced) != 0 {
		t.Fatalf("%d markers, unplaced %v", n, unplaced)
	}
}

// Finding 12. A tree a detached child held is moved aside, and holds mutated
// source: it goes when the run does.
func TestNoCopyOutlivesTheRun(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dir := module(t, map[string]string{"gate.go": `package mini

import (
	"errors"
	"os/exec"
	"syscall"
)

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	c := exec.Command("sh", "-c", "i=0; end=$(($(date +%s)+4)); while [ $(date +%s) -lt $end ]; do mkdir -p job/$i && : > job/$i/f; i=$((i+1)); done")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	c.Start()
	return nil
}
`, "gate_test.go": `package mini

import "testing"

func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`})
	if r := killOf(t, Options{Target: dir}); r.Outcome != Killed {
		t.Fatalf("got %+v", r)
	}
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range left {
		t.Errorf("left in TMPDIR: %s", e.Name())
	}
}

// Finding 15. gofmt puts a // before a directive whether or not a marker is there,
// so that // is upstream's. Before a marker alone it is not.
func TestUpstreamLineKeepsTheEmptyCommentBeforeADirective(t *testing.T) {
	src := func(directive string) []byte {
		return []byte("package p\n\n// Check.\n//\n//subpoena:enforcement_point\n" + directive + "func Check() {\n\tx() //subpoena:enforcement\n}\n")
	}
	if got := upstreamLine(src("//go:noinline\n"), 9); got != 8 {
		t.Fatalf("with a directive: %d", got)
	}
	if got := upstreamLine(src(""), 8); got != 6 {
		t.Fatalf("without one: %d", got)
	}
}
