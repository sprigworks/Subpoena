//subpoena:impl_derived

package cross

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// A kill that began on testimony is a self-report at once, whatever the repeat gives.
// confirmKill sets that outcome too, but only for a repeat with no witness evidence,
// so here, with witness evidence on the repeat alone, this reading is all there is.
func TestAKillThatBeganOnTestimonyIsNotRedeemedByTheRepeat(t *testing.T) {
	t.Parallel()
	dir := module(t, map[string]string{"gate.go": gate3, "run_test.go": counted(t), "signed_test.go": signedHelper, "gate_test.go": `package mini

import "testing"

func TestRefused(t *testing.T) {
	if nth == 2 { t.Fatal("a plain assertion") }
	if nth == 3 { t.Fatal(signed("witness: a connection arrived")) }
}
func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
`})
	r := killOf(t, Options{Target: dir, RequireWitness: true})
	if r.Outcome != KilledBySelfReport || r.Evidence != EvidenceOther || r.FirstFailure != "a plain assertion" {
		t.Fatalf("got %+v", r)
	}
}

// holds is what stands between a parallel table and a crash line read as a log line.
// Each clause has a case that only it decides.
func TestHoldsReadsWhatRan(t *testing.T) {
	t.Parallel()
	parent := ending{ran: true, start: 10, to: 100}
	paused := ending{ran: true, start: 10, paused: 15, from: 50, to: 100}
	for name, tc := range map[string]struct {
		parent, child ending
		want          bool
	}{
		"inside":                     {parent, ending{start: 20, to: 30}, true},
		"never ran":                  {ending{start: 10, to: 100}, ending{start: 20, to: 30}, false},
		"started first":              {parent, ending{start: 5, to: 30}, false},
		"ended after":                {parent, ending{start: 20, to: 200}, false},
		"never ended":                {parent, ending{start: 20}, false},
		"failed, and the parent not": {parent, ending{start: 20, to: 30, failed: true}, false},
		"failed, and the parent too": {ending{ran: true, start: 10, to: 100, failed: true}, ending{start: 20, to: 30, failed: true}, true},
		"before the parent paused":   {paused, ending{start: 12, to: 30}, true},
		"while the parent paused":    {paused, ending{start: 30, to: 60}, false},
		"after the parent continued": {paused, ending{start: 60, to: 70}, true},
		"the parent never continued": {ending{ran: true, start: 10, paused: 15, to: 100}, ending{start: 30, to: 60}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tc.parent.holds(tc.child); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

// Review 14, L5. read and read/all are parallel siblings, and read/all ends inside
// read. Only the pause says it is no subtest, so the crash line on it stands.
func TestAParallelSiblingThatEndsInsideTheFailureIsBesideIt(t *testing.T) {
	t.Parallel()
	const p, read, all = "mini", "TestCheck/read", "TestCheck/read/all"
	raw := event("run", p, "TestCheck", "") + event("run", p, read, "") + event("pause", p, read, "") +
		event("run", p, all, "") + event("pause", p, all, "") + event("cont", p, read, "") + event("cont", p, all, "") +
		event("pass", p, all, "") + event("fail", p, read, "") + event("fail", p, "TestCheck", "")
	if !besideFailure(endings(raw), eventKey{p, all}) {
		t.Fatal("read/all read as read's subtest")
	}
}

// Review 14, H1 and L4. What the baseline says of a package with no test, and of one
// whose m.Run hid everything.
func TestNoTestPackagesReadsCoverageAndBenchmarks(t *testing.T) {
	t.Parallel()
	const p = "mini/other"
	pass := event("pass", p, "", "")
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"no test files under -cover": {event("output", p, "", "\tmini/other\t\tcoverage: 0.0% of statements\n") + pass, true},
		"no statements":              {event("output", p, "", "coverage: [no statements]\n") + pass, true},
		"-coverpkg":                  {event("output", p, "", "coverage: 12.5% of statements in ./...\n") + pass, true},
		"a benchmark":                {event("run", p, "BenchmarkRead", "") + pass, true},
		"a sub-benchmark":            {event("run", p, "BenchmarkRead/small", "") + pass, true},
		"nothing shown":              {pass, false},
		"other package output":       {event("output", p, "", "coverage: unknown\n") + pass, false},
		"a test's own line":          {event("output", p, "TestA", "coverage: 0.0% of statements\n") + pass, false},
		"a test beside the line":     {event("run", p, "TestA", "") + event("output", p, "", "coverage: 50.0% of statements\n") + pass, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := noTestPackages(tc.raw)[p]; got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

// A benchmark shows no test, whatever m.Run then did: that is the quiet signature.
func TestABenchmarkDoesNotHideAQuietPackage(t *testing.T) {
	t.Parallel()
	raw := event("run", "mini", "BenchmarkRead", "") + event("pass", "mini", "BenchmarkRead", "") + event("pass", "mini", "", "")
	if got := quietPackages(raw, nil); !slices.Equal(got, []string{"mini"}) {
		t.Fatalf("got %q", got)
	}
}

// quietRetry hides m.Run's output and calls it again only on failure, so a green run
// shows nothing at all, a coverage line included.
const quietRetry = `func TestMain(m *testing.M) {
	out := os.Stdout
	os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	code := m.Run()
	os.Stdout = out
	if code != 0 { code = m.Run() }
	os.Exit(code)
}
`

// Review 14, H1 and L4, through the whole run. Under -cover a package with no test
// files passes, and it costs a survivor nothing. A quiet kill still reads killed under
// -cover, and with a benchmark, which runs whatever -test.failfast says.
func TestGoFlagsLeaveTheQuietSignatureAlone(t *testing.T) {
	refused := `func TestRefused(t *testing.T) { if Check("mallory") == nil { t.Fatal("mallory let in") } }
`
	quiet := "package mini\n\nimport (\"os\"; \"testing\")\n\n" + refused + quietRetry
	flags := os.Getenv("GOFLAGS")
	t.Run("-cover, a survivor", func(t *testing.T) {
		t.Setenv("GOFLAGS", strings.TrimSpace(flags+" -cover"))
		var log strings.Builder
		dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": "package mini\n\nimport \"testing\"\n\n" + lookOnly, "other/other.go": "package other\n\nvar Note = 1\n"})
		if r := killOf(t, Options{Target: dir, Log: &log}); r.Outcome != Survived {
			t.Fatalf("got %+v", r)
		}
		if strings.Contains(log.String(), goesAgain) {
			t.Fatalf("a survivor went again:\n%s", log.String())
		}
	})
	t.Run("-cover, a quiet kill", func(t *testing.T) {
		t.Setenv("GOFLAGS", strings.TrimSpace(flags+" -cover"))
		if r := killOf(t, Options{Target: module(t, map[string]string{"gate.go": gate3, "gate_test.go": quiet})}); r.Outcome != Killed {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("-bench, a quiet kill", func(t *testing.T) {
		t.Setenv("GOFLAGS", strings.TrimSpace(flags+" -bench=. -benchtime=1x"))
		dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": quiet + "func BenchmarkRead(b *testing.B) { for b.Loop() {} }\n"})
		if r := killOf(t, Options{Target: dir}); r.Outcome != Killed {
			t.Fatalf("got %+v", r)
		}
	})
}
