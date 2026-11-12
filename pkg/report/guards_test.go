//subpoena:impl_derived
//subpoena:pure_logic

// The report's fail-closed guards, each driven through Load or Build as a
// caller would, written after reading the implementation. Plain data in, no
// telemetry. A guard here that stops working lets a damaged input read as
// "all passed", so make cross-self cross-examines them.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const passingRun = `{"run_id":"20261104T010000Z-aaaaaaaa","task_id":"q1","capture_complete":true,
  "assertions":{"results":[{"id":"c1","evaluator":"subpoena","kind":"exists","verdict":"pass","detail":"q"}]}}`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// wantUnreadable loads dir and requires the named file on the unreadable list
// with the given reason, and a report that does not read as proven.
func wantUnreadable(t *testing.T, format, dir, name, reason string) {
	t.Helper()
	doc, notes, err := Load(format, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range notes.Unreadable {
		if filepath.Base(u.Path) == name && strings.Contains(u.Reason, reason) {
			found = true
		}
	}
	if !found {
		t.Fatalf("unreadable = %+v; want %s: %s", notes.Unreadable, name, reason)
	}
	r := Build(doc)
	r.AddLoadNotes(notes)
	if r.Proven() {
		t.Error("Proven() = true; want false")
	}
}

func TestRunFileWithItsResultsWipedIsUnreadable(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"1.json": passingRun,
		"2.json": `{"run_id":"20261104T010100Z-bbbbbbbb","capture_complete":true,
		  "assertions":{"passed":[],"failed":[],"inconclusive":[],"results":[]}}`,
	})
	wantUnreadable(t, FormatRunResults, dir, "2.json", "no assertion results")
	doc, _, _ := Load(FormatRunResults, []string{dir}, nil)
	if len(doc.Runs) != 1 {
		t.Errorf("runs = %d; the wiped run must not count as a run", len(doc.Runs))
	}
}

func TestSubpoenaRunWithNoResultsIsUnreadable(t *testing.T) {
	dir := writeFiles(t, map[string]string{"r.json": `{"runs":[
	  {"run_id":"r1","capture_complete":true,"assertions":[{"id":"a","kind":"exists","verdict":"pass"}]},
	  {"run_id":"r2","capture_complete":true,"assertions":[]}]}`})
	wantUnreadable(t, FormatSubpoena, dir, "r.json", "run r2: no assertion results")
}

func TestSubpoenaDocumentWithNoRunsIsUnreadable(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.json": `{"schema":"https://subpoena.dev/schemas/results/v1","runs":[]}`,
		"b.json": `{"runs":[{"run_id":"r1","assertions":[{"id":"a","kind":"exists","verdict":"pass"}]}]}`,
	})
	wantUnreadable(t, FormatSubpoena, dir, "a.json", "no assertion results")
}

func TestBlankFileIsUnreadableNotSkipped(t *testing.T) {
	for name, body := range map[string]string{"empty-object": `{}`, "null": `null`} {
		t.Run(name, func(t *testing.T) {
			dir := writeFiles(t, map[string]string{"1.json": passingRun, "2.json": body})
			wantUnreadable(t, FormatRunResults, dir, "2.json", "blank")
		})
	}
}

// A file that lost its results but kept any field of the format is damage, not
// a stranger.
func TestDamagedResultFileIsNotSetAside(t *testing.T) {
	for name, c := range map[string]struct{ format, body string }{
		"null runs":             {FormatSubpoena, `{"runs":null}`},
		"run file, no id":       {FormatRunResults, `{"task_id":"t","capture_complete":true,"assertions":{"results":[]}}`},
		"only capture complete": {FormatRunResults, `{"capture_complete":true}`},
	} {
		t.Run(name, func(t *testing.T) {
			good := passingRun
			if c.format == FormatSubpoena {
				good = `{"runs":[{"run_id":"r1","assertions":[{"id":"a","kind":"exists","verdict":"pass"}]}]}`
			}
			dir := writeFiles(t, map[string]string{"1.json": good, "2.json": c.body})
			wantUnreadable(t, c.format, dir, "2.json", "no assertion results")
		})
	}
}

// The wrong -from must not read a file of the other format as a stranger.
func TestOtherFormatIsNotSetAside(t *testing.T) {
	subpoena := `{"runs":[{"run_id":"r1","assertions":[{"id":"a","kind":"exists","verdict":"fail"}]}]}`
	wantUnreadable(t, FormatRunResults, writeFiles(t, map[string]string{"1.json": passingRun, "2.json": subpoena}), "2.json", "no")
	wantUnreadable(t, FormatSubpoena, writeFiles(t, map[string]string{"1.json": subpoena, "2.json": passingRun}), "2.json", "no assertion results")
}

func TestPageSaysWhenARunHasNoTime(t *testing.T) {
	r := Build(doc(
		Run{RunID: "r1", CapturedAt: "2026-11-03T10:00:00Z", CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: "a", Kind: KindExists, Verdict: VerdictPass}}},
		Run{RunID: "r2", CapturedAt: "yesterday", CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: "a", Kind: KindExists, Verdict: VerdictPass}}},
	))
	if page := Markdown(r); !strings.Contains(page, "1 run has no usable time") {
		t.Errorf("page does not say a run has no time:\n%s", firstLines(page, 4))
	}
}

func TestRunWithNoIDIsUnreadable(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"1.json": passingRun,
		"2.json": `{"task_id":"q","assertions":{"results":[{"id":"a","kind":"exists","verdict":"pass"}]}}`,
	})
	wantUnreadable(t, FormatRunResults, dir, "2.json", "no run_id")
}

func TestSameRunIDInTwoFilesIsUnreadable(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": passingRun, "2.json": passingRun})
	wantUnreadable(t, FormatRunResults, dir, "2.json", "already read from")
}

func TestOneFileSpelledTwoWaysCountsOnce(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": passingRun})
	path := filepath.Join(dir, "1.json")
	doc, notes, err := Load(FormatRunResults, []string{path, dir + "/./1.json"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(notes.Unreadable) != 0 {
		t.Errorf("runs = %d, unreadable = %+v; want the file read once", len(doc.Runs), notes.Unreadable)
	}
}

// The case that hid a failure: the id lists and the results are two records of
// the same verdicts, and a failure in only one of them must not be lost.
func TestFailureNamedOnlyInTheListIsNotLost(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": `{"run_id":"20261104T010000Z-cccccccc","capture_complete":true,
	  "assertions":{"failed":["leak"],"results":[{"id":"c1","kind":"exists","verdict":"pass"}]}}`})
	if _, notes, err := Load(FormatRunResults, []string{dir}, nil); err != nil || len(notes.Unreadable) != 1 {
		t.Fatalf("err = %v, unreadable = %+v; want the file refused", err, notes.Unreadable)
	}
}

func TestListsAndResultsMustAgreeForEveryVerdict(t *testing.T) {
	for _, list := range []string{"passed", "failed", "inconclusive"} {
		t.Run(list, func(t *testing.T) {
			body := fmt.Sprintf(`{"run_id":"20261104T010000Z-dddddddd","capture_complete":true,
			  "assertions":{"%s":["other"],"results":[{"id":"c1","kind":"exists","verdict":"pass"}]}}`, list)
			wantUnreadable(t, FormatRunResults, writeFiles(t, map[string]string{"1.json": body}), "1.json", "disagree")
		})
	}
}

func TestAgreeingListsAndResultsLoad(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": `{"run_id":"20261104T010000Z-eeeeeeee","capture_complete":true,
	  "assertions":{"passed":["a"],"failed":["b"],"results":[
	    {"id":"a","kind":"exists","verdict":"pass"},{"id":"b","kind":"exists","verdict":"fail"}]}}`})
	doc, notes, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil || len(notes.Unreadable) != 0 || len(doc.Runs) != 1 {
		t.Fatalf("err = %v, unreadable = %+v, runs = %d", err, notes.Unreadable, len(doc.Runs))
	}
}

// Only a kind that says it does not rest on absence survives an incomplete
// capture. A missing or unknown kind has not said so.
func TestIncompleteCaptureOnlyKeepsKnownPositiveKinds(t *testing.T) {
	for kind, want := range map[string]string{
		KindExists: VerdictPass, KindOther: VerdictPass,
		KindAbsent: VerdictInconclusive, "": VerdictInconclusive, "output_contains": VerdictInconclusive,
	} {
		got, _ := effectiveVerdict(Assertion{Kind: kind, Verdict: VerdictPass}, false)
		if got != want {
			t.Errorf("kind %q on an incomplete capture = %s; want %s", kind, got, want)
		}
		if got, _ := effectiveVerdict(Assertion{Kind: kind, Verdict: VerdictPass}, true); got != VerdictPass {
			t.Errorf("kind %q on a complete capture = %s; want pass", kind, got)
		}
	}
}

// The id lists carry no kind, so a pass from them cannot stand on an incomplete
// capture.
func TestListOnlyPassOnIncompleteCaptureIsInconclusive(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": `{"run_id":"20261104T010000Z-ffffffff","capture_complete":false,
	  "assertions":{"passed":["no_leak"]}}`})
	doc, _, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := Build(doc); r.Totals.Passed != 0 || r.Totals.Inconclusive != 1 {
		t.Errorf("totals = %+v; want 1 inconclusive", r.Totals)
	}
}

func TestRunResultsCarriesExercised(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": `{"run_id":"20261104T010000Z-11111111","capture_complete":true,
	  "assertions":{"results":[{"id":"a","kind":"absent","verdict":"pass","exercised":true}]}}`})
	doc, _, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inv := Build(doc).Invariants[0]; !inv.ExercisedRecorded || inv.Exercised != 1 {
		t.Errorf("invariant = %+v; want exercised recorded as 1", inv)
	}
}

// The page is complete by itself: every result that did not pass is on it, with
// no cap and no pointer to a file that may not exist.
func TestEveryFailureIsOnThePage(t *testing.T) {
	var runs []Run
	for i := 0; i < 25; i++ {
		runs = append(runs, Run{RunID: fmt.Sprintf("r%02d", i), Label: "q", CaptureComplete: boolp(true),
			Assertions: []Assertion{{ID: "a", Kind: KindExists, Verdict: VerdictFail, Detail: "looked for x"}}})
	}
	page := Markdown(Build(doc(runs...)))
	for i := 0; i < 25; i++ {
		if id := fmt.Sprintf("`r%02d` failed", i); !strings.Contains(page, id) {
			t.Errorf("page is missing %s", id)
		}
	}
	if strings.Contains(page, "data file") {
		t.Error("page sends the reader to a data file that may not exist")
	}
	if !strings.Contains(page, "- q: 25 of 25 runs") {
		t.Errorf("page does not state the failure per question:\n%s", page)
	}
}

// A check that always passed still shows what it looks for, in the data file
// and on the page.
func TestPassingCheckShowsWhatItLooksFor(t *testing.T) {
	r := Build(doc(Run{RunID: "r1", CaptureComplete: boolp(true), Assertions: []Assertion{
		{ID: "seen", Kind: KindExists, Verdict: VerdictPass, Detail: `{ name = "a" }`},
		{ID: "unseen", Kind: KindAbsent, Verdict: VerdictPass, Detail: `{ name = "b" }`},
		{ID: "output", Kind: "output_contains", Verdict: VerdictPass, Detail: "output matches /x/"},
	}}))
	if got := byID(r)["seen"].Queries; len(got) != 1 || got[0] != `{ name = "a" }` {
		t.Errorf("queries = %v; want the query kept for a passing check", got)
	}
	page := Markdown(r)
	if strings.Contains(page, "passes if see") {
		t.Error("Appendix A refers the reader to itself")
	}
	for _, want := range []string{
		"(`seen`), passes if found: `{ name = \"a\" }`",
		"(`unseen`), passes if not found: `{ name = \"b\" }`",
		"| Unseen | not found |",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q:\n%s", want, page)
		}
	}
}

// A report with nothing readable must not say anything passed.
func TestNothingReadableDoesNotSayPassed(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": `{"run_id":"r","assertions":{"results":[{"id":"a","verd`})
	doc, notes, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Build(doc)
	r.AddLoadNotes(notes)
	page := Markdown(r)
	if strings.Contains(page, "passed.") || !strings.Contains(page, "no assertion results were read") {
		t.Errorf("result line:\n%s", firstLines(page, 14))
	}
}

func TestPageCountsFilesSetAside(t *testing.T) {
	dir := writeFiles(t, map[string]string{"1.json": passingRun, "trace.json": `{"resourceSpans":[]}`})
	doc, notes, err := Load(FormatRunResults, []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Build(doc)
	r.AddLoadNotes(notes)
	if page := Markdown(r); !strings.Contains(page, "1 file read as results; 1 other file set aside") {
		t.Errorf("page does not count the files:\n%s", firstLines(page, 14))
	}
}
