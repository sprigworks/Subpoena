//subpoena:spec_derived
//subpoena:pure_logic

// Behaviour is taken from docs/evidence-reports.md: the capture rule for an
// absence, inconclusive counted as a failure, sources kept apart, an
// unreadable input counted as a failure, batches split on a gap in time, and
// the adapter's source mapping. Plain data in, no telemetry.
package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

func doc(runs ...Run) Document { return Document{Schema: SchemaResults, Runs: runs} }

func byID(r *Report) map[string]Invariant {
	out := map[string]Invariant{}
	for _, inv := range r.Invariants {
		out[inv.ID] = inv
	}
	return out
}

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
	inv := byID(r)
	a := inv["a"]
	if a.RunsChecked != 2 || a.Passed != 1 || a.Failed != 1 {
		t.Errorf("a = %+v; want 2 runs, 1 passed, 1 failed", a)
	}
	if len(a.Failures) != 1 || a.Failures[0].RunID != "r2" {
		t.Errorf("a failures = %+v; want r2", a.Failures)
	}
	b := inv["b"]
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
	inv := byID(r)
	if got := inv["absent"]; got.Passed != 0 || got.Inconclusive != 1 {
		t.Errorf("absent = %+v; want 0 passed, 1 inconclusive", got)
	}
	if len(inv["absent"].Unproven) != 1 || !strings.Contains(inv["absent"].Unproven[0].Detail, "capture incomplete") {
		t.Errorf("absent unproven = %+v; want a capture-incomplete reason", inv["absent"].Unproven)
	}
	if got := inv["exists"]; got.Passed != 1 || got.Inconclusive != 0 {
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
	inv := byID(r)
	if got := strings.Join(inv["a"].Sources, ","); got != "testimony,witness" {
		t.Errorf("a sources = %q; want testimony,witness", got)
	}
	if got := strings.Join(inv["b"].Sources, ","); got != "other" {
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
	inv := byID(r)
	if got := inv["no_denied_chunk_in_context"].Claim; got != "No denied chunk in context" {
		t.Errorf("claim = %q; want the derived title", got)
	}
	if got := inv["x"].Claim; got != "A sentence a reader can use." {
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

// An input file that cannot be read is on the page and counts as a failure: a
// result that could not be read is not a pass.
func TestUnreadableInputIsReportedAndCounts(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "a", Source: SourceTestimony, Kind: KindExists, Verdict: VerdictPass},
	}}))
	r.AddLoadNotes(LoadNotes{Unreadable: []Unreadable{{Path: "cut-off.json", Reason: "unexpected end of JSON input"}}})
	if r.Totals.Unreadable != 1 {
		t.Fatalf("unreadable = %d; want 1", r.Totals.Unreadable)
	}
	if r.Proven() {
		t.Error("Proven() = true with an unreadable input; want false")
	}
	page := Markdown(r)
	for _, want := range []string{"Unreadable input", "cut-off.json", "unexpected end of JSON input"} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// The headline leads with how many runs were touched, not how few results.
func TestResultLeadsWithRunsTouched(t *testing.T) {
	r := Build(doc(
		Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "a", Kind: KindExists, Verdict: VerdictFail},
			{ID: "b", Kind: KindExists, Verdict: VerdictPass},
		}},
		Run{RunID: "r2", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "a", Kind: KindExists, Verdict: VerdictPass},
			{ID: "b", Kind: KindExists, Verdict: VerdictPass},
		}},
	))
	if r.Totals.RunsWithFailed != 1 {
		t.Fatalf("runs with a failed check = %d; want 1", r.Totals.RunsWithFailed)
	}
	page := Markdown(r)
	if !strings.Contains(page, "1 of 2 runs (50%) recorded at least one failed or inconclusive check") {
		t.Errorf("headline does not lead with runs touched:\n%s", firstLines(page, 10))
	}
}

// Runs far apart in time are separate sittings: a check that exists in one is
// not counted against the others.
func TestBatchesSplitOnAGap(t *testing.T) {
	base := time.Date(2026, 11, 3, 23, 0, 0, 0, time.UTC)
	mk := func(id string, at time.Time, check string) Run {
		return Run{RunID: id, CapturedAt: at.Format(time.RFC3339), CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: check, Kind: KindExists, Verdict: VerdictPass}}}
	}
	r := Build(doc(
		mk("b1", base, "early_check"),
		mk("b2", base.Add(2*time.Minute), "early_check"),
		mk("b3", base.Add(5*time.Hour), "late_check"),
	))
	if len(r.Batches) != 2 {
		t.Fatalf("batches = %d; want 2", len(r.Batches))
	}
	if r.Batches[0].Runs != 2 || r.Batches[1].Runs != 1 {
		t.Errorf("batches = %+v; want 2 runs then 1", r.Batches)
	}
	if r.Batches[0].Checks != 1 || r.Batches[1].Checks != 1 {
		t.Errorf("checks per batch = %d, %d; want 1 and 1", r.Batches[0].Checks, r.Batches[1].Checks)
	}
	// A check that exists in one sitting only must not look like it ran in both.
	inv := byID(r)
	if got := inv["early_check"].RunsPerBatch; len(got) != 2 || got[0] != 2 || got[1] != 0 {
		t.Errorf("early_check runs per batch = %v; want [2 0]", got)
	}
	if got := inv["late_check"].RunsPerBatch; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("late_check runs per batch = %v; want [0 1]", got)
	}
	page := Markdown(r)
	for _, want := range []string{"## Batches", "| Runs by batch |", "2 · 0", "0 · 1"} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q:\n%s", want, page)
		}
	}
}

// A failure line says which sitting it came from when there is more than one.
func TestFailureLineNamesTheBatch(t *testing.T) {
	base := time.Date(2026, 11, 3, 23, 0, 0, 0, time.UTC)
	mk := func(id string, at time.Time, verdict string) Run {
		return Run{RunID: id, CapturedAt: at.Format(time.RFC3339), CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: "a", Source: SourceTestimony, Kind: KindExists, Verdict: verdict}}}
	}
	r := Build(doc(
		mk("b1", base, VerdictFail),
		mk("b2", base.Add(5*time.Hour), VerdictPass),
	))
	page := Markdown(r)
	if !strings.Contains(page, "`b1` failed (batch 1, testimony, `a`)") {
		t.Errorf("failure line does not name the batch:\n%s", page)
	}
}

// A single sitting says nothing about batches, so the section stays out.
func TestSingleBatchHasNoBatchSection(t *testing.T) {
	base := time.Date(2026, 11, 3, 23, 0, 0, 0, time.UTC)
	r := Build(doc(
		Run{RunID: "r1", CapturedAt: base.Format(time.RFC3339), CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: "a", Kind: KindExists, Verdict: VerdictPass}}},
		Run{RunID: "r2", CapturedAt: base.Add(time.Minute).Format(time.RFC3339), CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: "a", Kind: KindExists, Verdict: VerdictPass}}},
	))
	if len(r.Batches) != 1 {
		t.Fatalf("batches = %d; want 1", len(r.Batches))
	}
	if strings.Contains(Markdown(r), "## Batches") {
		t.Error("page has a batch section for a single batch")
	}
}

// The exercised column appears only when the input recorded it.
func TestExercisedColumnOnlyWhenRecorded(t *testing.T) {
	plain := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "a", Kind: KindAbsent, Verdict: VerdictPass},
	}}))
	if anyExercised(plain.Invariants) {
		t.Error("exercised reported for input that never recorded it")
	}
	page := Markdown(plain)
	if strings.Contains(page, "| Exercised |") {
		t.Error("exercised column present with nothing recorded")
	}
	if !strings.Contains(page, "does not record how often") {
		t.Error("page does not say it cannot state how often a check was exercised")
	}

	yes, no := true, false
	recorded := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "a", Kind: KindAbsent, Verdict: VerdictPass, Exercised: &yes},
		{ID: "b", Kind: KindAbsent, Verdict: VerdictPass, Exercised: &no},
	}}))
	inv := byID(recorded)
	if !inv["a"].ExercisedRecorded || inv["a"].Exercised != 1 {
		t.Errorf("a = %+v; want exercised recorded as 1", inv["a"])
	}
	if !inv["b"].ExercisedRecorded || inv["b"].Exercised != 0 {
		t.Errorf("b = %+v; want exercised recorded as 0", inv["b"])
	}
	if !strings.Contains(Markdown(recorded), "| Exercised |") {
		t.Error("exercised column missing when the input records it")
	}
}

func TestMarkdownStatesFailuresAndInconclusive(t *testing.T) {
	r := Build(doc(
		Run{RunID: "r1", Label: "audit-fee", CaptureComplete: boolp(true), Assertions: []Assertion{
			{ID: "no_denied_chunk_in_context", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictPass},
			{ID: "cites_the_source", Source: SourceTestimony, Kind: KindExists, Verdict: VerdictFail, Detail: "no cite span"},
			{ID: "no_disallowed_egress", Source: SourceTestimony, Kind: KindAbsent, Verdict: VerdictInconclusive, Detail: "capture incomplete"},
		}},
	))
	page := Markdown(r)
	for _, want := range []string{
		"No denied chunk in context",
		"# Test evidence report",
		"**Not verified.**",
		"**Cites the source** — 1 of 1 run failed",
		"- audit-fee: 1 of 1 run",
		"`r1` failed audit-fee (testimony, `cites_the_source`): `no cite span`",
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
	doc, notes, err := Load(FormatRunResults, []string{path}, map[string]string{"a": "A sentence."})
	if err != nil {
		t.Fatal(err)
	}
	if len(notes.Unreadable) != 0 {
		t.Fatalf("unreadable = %+v; want none", notes.Unreadable)
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
	doc, notes, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d; want 1", len(doc.Runs))
	}
	if len(notes.Skipped) != 1 {
		t.Errorf("skipped = %v; want the trace file", notes.Skipped)
	}
	if len(notes.Unreadable) != 0 {
		t.Errorf("unreadable = %v; a trace is not an unreadable result", notes.Unreadable)
	}
}

// A cut-off file that holds a failure must not disappear. This is the case
// that let a damaged input hide a failing run behind a clean page.
func TestTruncatedRunFileIsUnreadableNotSkipped(t *testing.T) {
	dir := t.TempDir()
	pass := `{"run_id":"20261103T233153Z-1","capture_complete":true,
	  "assertions":{"results":[{"id":"a","verdict":"pass"}]}}`
	cut := `{"run_id":"20261103T233200Z-2","task_id":"audit-fee","capture_complete":true,
	  "assertions":{"results":[{"id":"a","verdict":"fail","detail":"no span"`
	if err := os.WriteFile(filepath.Join(dir, "pass.json"), []byte(pass), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cut.json"), []byte(cut), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, notes, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes.Unreadable) != 1 {
		t.Fatalf("unreadable = %+v; want the cut-off file", notes.Unreadable)
	}
	r := Build(doc)
	r.AddLoadNotes(notes)
	if r.Proven() {
		t.Error("Proven() = true with a cut-off input; want false")
	}
	page := Markdown(r)
	if !strings.Contains(page, "cut.json") || !strings.Contains(page, "Unreadable input") {
		t.Errorf("page does not report the cut-off input:\n%s", page)
	}
}

func TestNoRunsFoundIsAnError(t *testing.T) {
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

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
