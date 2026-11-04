//subpoena:spec_derived
//subpoena:pure_logic

// Behaviour is taken from docs/evidence-reports.md: the capture rule for an
// absence, inconclusive counted as a failure, sources kept apart, and the
// adapter's source mapping. Plain data in, no telemetry.
package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolp(b bool) *bool { return &b }

func doc(runs ...Run) Document { return Document{Schema: SchemaResults, Runs: runs} }

func TestAggregatesPerAssertion(t *testing.T) {
	r := Build(doc(
		Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "a", Source: SourceTestimony, Kind: KindExists, Verdict: VerdictPass},
			{ID: "b", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
		}},
		Run{RunID: "r2", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "a", Source: SourceTestimony, Kind: KindExists, Verdict: VerdictFail, Detail: "no span"},
			{ID: "b", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
		}},
	))

	if r.Inputs.Runs != 2 || r.Inputs.Assertions != 4 {
		t.Fatalf("inputs = %d runs, %d assertions; want 2, 4", r.Inputs.Runs, r.Inputs.Assertions)
	}
	byID := map[string]Invariant{}
	for _, inv := range r.Invariants {
		byID[inv.ID] = inv
	}
	a := byID["a"]
	if a.RunsChecked != 2 || a.Passed != 1 || a.Failed != 1 {
		t.Errorf("a = %+v; want 2 runs, 1 passed, 1 failed", a)
	}
	if len(a.Failures) != 1 || a.Failures[0].RunID != "r2" {
		t.Errorf("a failures = %+v; want r2", a.Failures)
	}
	b := byID["b"]
	if b.Passed != 2 || b.Failed != 0 {
		t.Errorf("b = %+v; want 2 passed", b)
	}
}

func TestInconclusiveIsAFailureAndNeverPassed(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "a", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictInconclusive, Detail: "capture incomplete"},
	}}))
	if r.Totals.Passed != 0 || r.Totals.Inconclusive != 1 {
		t.Fatalf("totals = %+v; want 0 passed, 1 inconclusive", r.Totals)
	}
	if r.Proven() {
		t.Error("Proven() = true with an inconclusive result; want false")
	}
}

// An absence cannot be proven from a capture that is not complete: a pass of
// kind absent becomes inconclusive, matching pkg/harness. A positive match
// stands.
func TestIncompleteCaptureDowngradesAbsenceOnly(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(false), Assertions: []Assertion{
		{ID: "absent", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
		{ID: "exists", Source: SourceTestimony, Kind: KindExists, Verdict: VerdictPass},
	}}))
	byID := map[string]Invariant{}
	for _, inv := range r.Invariants {
		byID[inv.ID] = inv
	}
	if got := byID["absent"]; got.Passed != 0 || got.Inconclusive != 1 {
		t.Errorf("absent = %+v; want 0 passed, 1 inconclusive", got)
	}
	if len(byID["absent"].Unproven) != 1 || !strings.Contains(byID["absent"].Unproven[0].Detail, "capture incomplete") {
		t.Errorf("absent unproven = %+v; want a capture-incomplete reason", byID["absent"].Unproven)
	}
	if got := byID["exists"]; got.Passed != 1 || got.Inconclusive != 0 {
		t.Errorf("exists = %+v; want 1 passed", got)
	}
	if r.Capture.Incomplete != 1 {
		t.Errorf("capture = %+v; want 1 incomplete", r.Capture)
	}
}

// Capture completeness that the input does not state cannot support an
// absence either.
func TestUnstatedCaptureCannotProveAnAbsence(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", Assertions: []Assertion{
		{ID: "a", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
	}}))
	if r.Capture.Unstated != 1 {
		t.Errorf("capture = %+v; want 1 unstated", r.Capture)
	}
	if r.Invariants[0].Inconclusive != 1 {
		t.Errorf("invariant = %+v; want 1 inconclusive", r.Invariants[0])
	}
}

// Two sources are never presented as one strength.
func TestSourcesStayApart(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "a", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
		{ID: "a", Source: SourceWitness, Kind: KindAbsent, Verdict: VerdictPass},
		{ID: "b", Source: "", Kind: KindExists, Verdict: VerdictPass},
	}}))
	byID := map[string]Invariant{}
	for _, inv := range r.Invariants {
		byID[inv.ID] = inv
	}
	if got := strings.Join(byID["a"].Sources, ","); got != "testimony,witness" {
		t.Errorf("a sources = %q; want testimony,witness", got)
	}
	if got := strings.Join(byID["b"].Sources, ","); got != "other" {
		t.Errorf("b sources = %q; want other (empty source is other)", got)
	}
	if r.Sources.Witness != 1 || r.Sources.Testimony != 1 || r.Sources.Other != 1 {
		t.Errorf("source totals = %+v; want one each", r.Sources)
	}
}

func TestClaimFallsBackToTheID(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "no_denied_chunk_in_context", Verdict: VerdictPass},
		{ID: "x", Claim: "A sentence a reader can use.", Verdict: VerdictPass},
	}}))
	byID := map[string]Invariant{}
	for _, inv := range r.Invariants {
		byID[inv.ID] = inv
	}
	if got := byID["no_denied_chunk_in_context"].Claim; got != "No denied chunk in context" {
		t.Errorf("claim = %q; want the derived title", got)
	}
	if got := byID["x"].Claim; got != "A sentence a reader can use." {
		t.Errorf("claim = %q; want the supplied sentence", got)
	}
}

func TestUnrecognizedVerdictIsInconclusive(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "a", Kind: KindExists, Verdict: "green"},
	}}))
	if r.Totals.Inconclusive != 1 || r.Totals.Passed != 0 {
		t.Errorf("totals = %+v; want the odd verdict counted inconclusive", r.Totals)
	}
	if !strings.Contains(r.Invariants[0].Unproven[0].Detail, "unrecognized verdict") {
		t.Errorf("unproven = %+v; want an unrecognized-verdict reason", r.Invariants[0].Unproven)
	}
}

func TestMarkdownStatesFailuresAndInconclusive(t *testing.T) {
	r := Build(doc(
		Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "no_denied_chunk_in_context", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
			{ID: "cites_the_source", Source: SourceTestimony, Kind: KindExists, Verdict: VerdictFail, Detail: "no cite span"},
			{ID: "no_disallowed_egress", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictInconclusive, Detail: "capture incomplete"},
		}},
	))
	page := Markdown(r, 0)
	for _, want := range []string{
		"No denied chunk in context",
		"# Test evidence report",
		"**Cites the source** (`cites_the_source`)",
		"`r1` (testimony): no cite span",
		"Inconclusive is a failure",
		"2 of 3 assertion results were not proven",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// A failing result is listed, not only counted.
func TestFailuresAreListed(t *testing.T) {
	r := Build(doc(
		Run{RunID: "r2", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "a", Kind: KindExists, Verdict: VerdictFail, Detail: "second"},
		}},
		Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "a", Kind: KindExists, Verdict: VerdictFail, Detail: "first"},
		}},
	))
	refs := r.Invariants[0].Failures
	if len(refs) != 2 || refs[0].RunID != "r1" || refs[1].RunID != "r2" {
		t.Fatalf("failures = %+v; want r1 then r2", refs)
	}
	page := Markdown(r, 1)
	if !strings.Contains(page, "and 1 result more") {
		t.Errorf("cap not reported:\n%s", page)
	}
}

func TestLimitCapsListedFailures(t *testing.T) {
	var refs []ResultRef
	for _, id := range []string{"a", "b", "c"} {
		refs = append(refs, ResultRef{RunID: id, Source: SourceTestimony, Detail: "x"})
	}
	var b strings.Builder
	listResults(&b, refs, 2)
	if got := strings.Count(b.String(), "- `"); got != 2 {
		t.Errorf("listed %d results, want 2", got)
	}
	if !strings.Contains(b.String(), "1 result more") {
		t.Errorf("missing remainder line:\n%s", b.String())
	}
}

func TestLoadRunResultsMapsSourcesAndLabel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	body := `{
	  "run_id": "20261103T233153Z-530c4709",
	  "task_id": "board-allowed-audit-fee",
	  "model": "m1",
	  "harness_fingerprint": "sha256:abc",
	  "capture_complete": true,
	  "assertions": {"results": [
	    {"id": "a", "evaluator": "subpoena", "kind": "absent", "verdict": "pass"},
	    {"id": "b", "evaluator": "grader", "kind": "output_contains", "verdict": "fail", "detail": "no match"},
	    {"id": "c", "evaluator": "grader", "source": "witness", "kind": "absent", "verdict": "pass"}
	  ]}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, _, err := Load(FormatRunResults, []string{path}, map[string]string{"a": "A sentence."})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d; want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Label != "board-allowed-audit-fee" {
		t.Errorf("label = %q; want the task id", run.Label)
	}
	if run.CapturedAt != "20261103T233153Z" {
		t.Errorf("captured_at = %q; want the stamp from the run id", run.CapturedAt)
	}
	want := map[string]string{"a": SourceTestimony, "b": SourceOther, "c": SourceWitness}
	for _, a := range run.Assertions {
		if got := a.Source; got != want[a.ID] {
			t.Errorf("%s source = %q; want %q", a.ID, got, want[a.ID])
		}
	}
	if run.Assertions[0].Claim != "A sentence." {
		t.Errorf("claim = %q; want the claims file to fill it", run.Assertions[0].Claim)
	}
	r := Build(doc)
	if r.Window.From != "2026-11-03T23:31:53Z" {
		t.Errorf("window from = %q", r.Window.From)
	}
}

// A directory walk skips files that are not run results, so a run directory
// holding traces beside its result file is fine.
func TestLoadDirectorySkipsOtherJSON(t *testing.T) {
	dir := t.TempDir()
	run := `{"run_id":"20261103T233153Z-1","capture_complete":true,
	  "assertions":{"results":[{"id":"a","verdict":"pass"}]}}`
	if err := os.WriteFile(filepath.Join(dir, "results.json"), []byte(run), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trace.otlp.json"), []byte(`{"resourceSpans":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, skipped, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d; want 1", len(doc.Runs))
	}
	if len(skipped) != 1 {
		t.Errorf("skipped = %v; want the trace file", skipped)
	}
}

func TestLoadErrorsWhenNothingParses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(FormatSubpoena, []string{dir}, nil); err == nil {
		t.Error("Load = nil error with no runs; want an error")
	}
}

func TestLoadSubpoenaDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	body := `{"schema":"https://subpoena.dev/schemas/results/v1","runs":[
	  {"run_id":"r1","capture_complete":false,"assertions":[
	    {"id":"a","source":"testimony","kind":"absent","verdict":"pass"}]}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, _, err := Load(FormatSubpoena, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Build(doc)
	if r.Invariants[0].Inconclusive != 1 {
		t.Errorf("invariant = %+v; want the incomplete capture to downgrade the absence", r.Invariants[0])
	}
}

func TestLoadRejectsUnknownFormat(t *testing.T) {
	if _, _, err := Load("csv", []string{"x"}, nil); err == nil {
		t.Error("Load = nil error for an unknown format; want an error")
	}
}

func TestTitleize(t *testing.T) {
	for in, want := range map[string]string{
		"no_denied_chunk_in_context": "No denied chunk in context",
		"gateway_in":                 "Gateway in",
		"already Title":              "Already Title",
	} {
		if got := titleize(in); got != want {
			t.Errorf("titleize(%q) = %q; want %q", in, got, want)
		}
	}
}
