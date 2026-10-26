//subpoena:spec_derived
//subpoena:pure_logic

// The port check from docs/ports.md (Q2, Q3): RunEvaluator runs any command
// that speaks the subpoena-traceql protocol over the whole corpus. It runs
// processes over files; no telemetry.
package conformance

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

func TestRejectedCorpusIsRejectedBySubset(t *testing.T) {
	c, err := LoadCorpus("..")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rejected) < 20 {
		t.Fatalf("want the rejected corpus, got %d queries", len(c.Rejected))
	}
	for _, q := range c.Rejected {
		if _, err := traceql.Parse(q); err == nil {
			t.Errorf("pkg/traceql accepts %s, which conformance/rejected.traceql says is outside the subset", q)
		}
	}
}

func buildReference(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "subpoena-traceql")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/subpoena-traceql").CombinedOutput(); err != nil {
		t.Fatalf("build subpoena-traceql: %v\n%s", err, out)
	}
	return bin
}

// The Go evaluator, through the protocol, agrees with the whole corpus.
func TestReferenceEvaluatorPasses(t *testing.T) {
	c, err := LoadCorpus("..")
	if err != nil {
		t.Fatal(err)
	}
	r, err := RunEvaluator(context.Background(), c, []string{buildReference(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.Mismatches {
		t.Error(m)
	}
	if want := len(c.Queries)*len(c.Fixtures) + len(c.Rejected); r.Runs != want {
		t.Fatalf("ran %d cases, want %d", r.Runs, want)
	}
}

// An evaluator that answers nothing and accepts everything must fail on both
// counts: missed matches and accepted rejections.
func TestAnEvaluatorThatMatchesNothingFails(t *testing.T) {
	c, err := LoadCorpus("..")
	if err != nil {
		t.Fatal(err)
	}
	r, err := RunEvaluator(context.Background(), c, []string{"sh", "-c", "exit 0", "sh"})
	if err != nil {
		t.Fatal(err)
	}
	var missed, accepted int
	for _, m := range r.Mismatches {
		if m.Fixture == "" {
			accepted++
		} else {
			missed++
		}
	}
	if accepted != len(c.Rejected) || missed == 0 {
		t.Fatalf("want every rejection accepted and some matches missed: %d accepted, %d missed", accepted, missed)
	}
}

// A crash is a mismatch with the evaluator's stderr, not a silent "no match".
func TestAnEvaluatorThatFailsIsAMismatch(t *testing.T) {
	c, err := LoadCorpus("..")
	if err != nil {
		t.Fatal(err)
	}
	r, err := RunEvaluator(context.Background(), c, []string{"sh", "-c", "echo boom >&2; exit 1", "sh"})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(c.Queries) * len(c.Fixtures); len(r.Mismatches) < n {
		t.Fatalf("every evaluation should be a mismatch: %d of %d", len(r.Mismatches), n)
	}
	if !strings.Contains(r.Mismatches[0].String(), "boom") {
		t.Fatalf("the mismatch should carry stderr: %s", r.Mismatches[0])
	}
}

// Output is compared as a set of normalised IDs, so unsorted or upper-case
// output, and blank lines, are accepted; an ID the fixture does not hold is not.
func TestOutputIsComparedAsASet(t *testing.T) {
	c, err := LoadCorpus("..")
	if err != nil {
		t.Fatal(err)
	}
	ref := buildReference(t)
	r, err := RunEvaluator(context.Background(), c, []string{"sh", "-c", `out=$("$0" "$1" "$2") || exit $?; printf '%s\n' "$out" | sort -r | tr a-f A-F`, ref})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.Mismatches {
		t.Error(m)
	}
	r, err = RunEvaluator(context.Background(), c, []string{"sh", "-c", `"$0" "$1" "$2" || exit $?; echo c0de00000000000000000000deadbeef`, ref})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Mismatches) < len(c.Queries)*len(c.Fixtures) {
		t.Fatalf("an extra ID in every answer should fail every pair, got %d mismatches", len(r.Mismatches))
	}
}
