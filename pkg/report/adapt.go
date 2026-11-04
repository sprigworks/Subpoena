package report

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Formats Load understands.
const (
	// FormatSubpoena reads the stable results document described in
	// docs/evidence-reports.md.
	FormatSubpoena = "subpoena"
	// FormatRunResults reads one flat run-result file per run, the shape a
	// harness commonly writes first.
	FormatRunResults = "run-results"
)

// LoadNotes is what Load could not use.
type LoadNotes struct {
	// Read counts the files that yielded runs.
	Read int
	// Skipped lists files found by walking a directory that are not this
	// format at all: traces, a collector config, anything else in a run
	// directory. They are not results and are not failures.
	Skipped []string
	// Unreadable lists files that could not be used: truncated, corrupt,
	// blank, contradicting themselves, or holding a run with no results, no id
	// or an id already read. They are reported on the page and count as
	// failures.
	Unreadable []Unreadable
}

// Load reads every path in the given format and returns one document. A path
// is a file, a glob, or a directory (walked for *.json files). claims, when
// non-nil, supplies a title for an assertion id that carries none.
//
// A file that cannot be read is never silently dropped: it comes back in
// LoadNotes.Unreadable, for the caller to put on the page and count as a
// failure. A file that is simply not this format is a benign skip.
func Load(format string, paths []string, claims map[string]string) (Document, LoadNotes, error) {
	var notes LoadNotes
	if format != FormatSubpoena && format != FormatRunResults {
		return Document{}, notes, fmt.Errorf("unknown format %q (want %s or %s)", format, FormatSubpoena, FormatRunResults)
	}
	files, err := expand(paths)
	if err != nil {
		return Document{}, notes, err
	}
	doc := Document{Schema: SchemaResults}
	seen := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			notes.Unreadable = append(notes.Unreadable, Unreadable{Path: f.path, Reason: err.Error()})
			continue
		}
		var runs []Run
		switch format {
		case FormatSubpoena:
			runs, err = parseSubpoena(raw)
		case FormatRunResults:
			runs, err = parseRunResults(raw, claims)
		}
		if err != nil {
			notes.Unreadable = append(notes.Unreadable, Unreadable{Path: f.path, Reason: err.Error()})
			continue
		}
		if reason := unusableFile(raw, len(runs)); reason != "" {
			notes.Unreadable = append(notes.Unreadable, Unreadable{Path: f.path, Reason: reason})
			continue
		}
		if len(runs) == 0 {
			notes.Skipped = append(notes.Skipped, f.path)
			continue
		}
		usable := false
		for _, run := range runs {
			if reason := unusableRun(run, seen); reason != "" {
				notes.Unreadable = append(notes.Unreadable, Unreadable{Path: f.path, Reason: reason})
				continue
			}
			seen[run.RunID] = f.path
			doc.Runs = append(doc.Runs, run)
			usable = true
		}
		if usable {
			notes.Read++
		}
	}
	if len(doc.Runs) == 0 && len(notes.Unreadable) == 0 {
		return Document{}, notes, fmt.Errorf("no runs found in %d file(s)", len(files))
	}
	if claims != nil {
		applyClaims(&doc, claims)
	}
	return doc, notes, nil
}

type candidate struct {
	path string
}

// unusableFile says why a file that yielded no run still cannot count as "not
// this format": it carries a results field of either format, which also catches
// the wrong -from, or it is blank. A result file wiped to {} is damage, and no
// trace or config looks like that.
//
//subpoena:enforcement_point
func unusableFile(raw []byte, runs int) string {
	if runs > 0 {
		return ""
	}
	if carriesResults(raw) { //subpoena:enforcement_guard false
		return "no assertion results in the file for this -from format"
	}
	if isBlank(raw) { //subpoena:enforcement_guard false
		return "the file is blank"
	}
	return ""
}

// resultFields are the top-level fields of the two input formats. A file with
// any of them set out to be a result, however little of it survived.
var resultFields = []string{"schema", "runs", "run_id", "task_id", "assertions", "capture_complete", "harness_fingerprint"}

func carriesResults(raw []byte) bool {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return false
	}
	for _, field := range resultFields {
		if _, ok := top[field]; ok {
			return true
		}
	}
	return false
}

// unusableRun says why a run cannot be counted: a run with no results would
// read as a clean run, and a run with no id or one already read cannot be told
// apart from another.
//
//subpoena:enforcement_point
func unusableRun(run Run, seen map[string]string) string {
	if run.RunID == "" { //subpoena:enforcement_guard false
		return "a run has no run_id"
	}
	if len(run.Assertions) == 0 { //subpoena:enforcement_guard false
		return fmt.Sprintf("run %s: no assertion results", run.RunID)
	}
	if first, dup := seen[run.RunID]; dup { //subpoena:enforcement_guard false
		return fmt.Sprintf("run %s was already read from %s", run.RunID, first)
	}
	return ""
}

func isBlank(raw []byte) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func expand(paths []string) ([]candidate, error) {
	seen := map[string]bool{}
	var out []candidate
	add := func(path string) {
		key, err := filepath.Abs(path)
		if err != nil {
			key = filepath.Clean(path)
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, candidate{path: path})
	}
	for _, p := range paths {
		if strings.ContainsAny(p, "*?[") {
			matches, err := filepath.Glob(p)
			if err != nil {
				return nil, err
			}
			for _, m := range matches {
				add(m)
			}
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".json") {
				add(path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// parseSubpoena returns the runs, and an error only when the bytes are not
// readable as JSON.
func parseSubpoena(raw []byte) ([]Run, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	runs := make([]Run, 0, len(doc.Runs))
	for _, r := range doc.Runs {
		if r.CapturedAt == "" {
			r.CapturedAt = timestampFromRunID(r.RunID)
		}
		runs = append(runs, r)
	}
	return runs, nil
}

// runResultsFile is the flat shape a harness writes before any Subpoena output
// exists. See docs/evidence-reports.md.
type runResultsFile struct {
	RunID              string `json:"run_id"`
	TaskID             string `json:"task_id"`
	Model              string `json:"model"`
	HarnessFingerprint string `json:"harness_fingerprint"`
	CapturedAt         string `json:"captured_at"`
	CaptureComplete    *bool  `json:"capture_complete"`
	Assertions         struct {
		Passed       []string `json:"passed"`
		Failed       []string `json:"failed"`
		Inconclusive []string `json:"inconclusive"`
		Results      []struct {
			ID        string `json:"id"`
			Evaluator string `json:"evaluator"`
			Source    string `json:"source"`
			Kind      string `json:"kind"`
			Verdict   string `json:"verdict"`
			Detail    string `json:"detail"`
			Exercised *bool  `json:"exercised"`
		} `json:"results"`
	} `json:"assertions"`
}

// listsAgree checks the passed, failed and inconclusive id lists against
// results. The two record the same verdicts, so a disagreement means the file
// is damaged, and a failure named in only one of them must not be lost. A
// harness that writes results alone has no lists to compare.
//
//subpoena:enforcement_point
func (f *runResultsFile) listsAgree() error {
	a := &f.Assertions
	if len(a.Results) == 0 || len(a.Passed)+len(a.Failed)+len(a.Inconclusive) == 0 {
		return nil
	}
	for verdict, ids := range map[string][]string{
		VerdictPass: a.Passed, VerdictFail: a.Failed, VerdictInconclusive: a.Inconclusive,
	} {
		listed := map[string]bool{}
		for _, id := range ids {
			listed[id] = true
		}
		recorded := map[string]bool{}
		for _, res := range a.Results {
			if normalize(res.Verdict) == verdict {
				recorded[res.ID] = true
			}
		}
		if !sameKeys(listed, recorded) { //subpoena:enforcement_guard false
			return fmt.Errorf("the %s list and the results disagree", verdict)
		}
	}
	return nil
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// parseRunResults returns the run, and an error when the bytes are not readable
// as JSON or the file contradicts itself. A file with a run id or results but
// nothing usable comes back as a run Load reports as unreadable; a file with
// neither comes back empty for Load to judge.
func parseRunResults(raw []byte, claims map[string]string) ([]Run, error) {
	var f runResultsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	shaped := f.RunID != "" || len(f.Assertions.Results) > 0 ||
		len(f.Assertions.Passed) > 0 || len(f.Assertions.Failed) > 0 || len(f.Assertions.Inconclusive) > 0
	if !shaped {
		return nil, nil
	}
	if err := f.listsAgree(); err != nil {
		return nil, err
	}
	run := Run{
		RunID:              f.RunID,
		Label:              f.TaskID,
		Model:              f.Model,
		HarnessFingerprint: f.HarnessFingerprint,
		CapturedAt:         f.CapturedAt,
		CaptureComplete:    f.CaptureComplete,
	}
	if run.CapturedAt == "" {
		run.CapturedAt = timestampFromRunID(f.RunID)
	}
	if len(f.Assertions.Results) > 0 {
		for _, res := range f.Assertions.Results {
			run.Assertions = append(run.Assertions, Assertion{
				ID:        res.ID,
				Claim:     claim(claims, res.ID),
				Source:    sourceFromEvaluator(res.Source, res.Evaluator),
				Kind:      res.Kind,
				Verdict:   res.Verdict,
				Detail:    res.Detail,
				Exercised: res.Exercised,
			})
		}
		return []Run{run}, nil
	}
	// The lists carry no kind, so none is claimed: on an incomplete capture a
	// pass from a list cannot be told from an absence.
	add := func(ids []string, verdict string) {
		for _, id := range ids {
			run.Assertions = append(run.Assertions, Assertion{
				ID: id, Claim: claim(claims, id), Source: SourceTestimony, Verdict: verdict,
			})
		}
	}
	add(f.Assertions.Passed, VerdictPass)
	add(f.Assertions.Failed, VerdictFail)
	add(f.Assertions.Inconclusive, VerdictInconclusive)
	return []Run{run}, nil
}

// sourceFromEvaluator maps a result to a source. An explicit source wins; a
// Subpoena evaluator is the application's own telemetry (testimony); anything
// else is other. The adapter never claims a witness.
func sourceFromEvaluator(explicit, evaluator string) string {
	if strings.TrimSpace(explicit) != "" {
		return source(explicit)
	}
	if strings.EqualFold(strings.TrimSpace(evaluator), "subpoena") {
		return SourceTestimony
	}
	return SourceOther
}

// timestampFromRunID reads the leading 20060102T150405Z stamp a run id usually
// carries, so the report can state a window without another field.
func timestampFromRunID(id string) string {
	stamp, _, found := strings.Cut(id, "-")
	if !found || len(stamp) != 16 || stamp[8] != 'T' || stamp[15] != 'Z' {
		return ""
	}
	if t, ok := parseTime(stamp); ok {
		return t.Format("20060102T150405Z")
	}
	return ""
}

func claim(claims map[string]string, id string) string {
	if claims == nil {
		return ""
	}
	return claims[id]
}

func applyClaims(doc *Document, claims map[string]string) {
	for i := range doc.Runs {
		for j := range doc.Runs[i].Assertions {
			a := &doc.Runs[i].Assertions[j]
			if a.Claim == "" {
				a.Claim = claims[a.ID]
			}
		}
	}
}

// LoadClaims reads an id-to-sentence JSON object.
func LoadClaims(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}
