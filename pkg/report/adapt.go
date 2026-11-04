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
	// Skipped lists files found by walking a directory that are not this
	// format at all: traces, a collector config, anything else in a run
	// directory. They are not results and are not failures.
	Skipped []string
	// Unreadable lists files that carry the format but could not be read:
	// truncated, corrupt, or holding no result at all. They are reported on
	// the page and count as failures.
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
	for _, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			notes.Unreadable = append(notes.Unreadable, Unreadable{Path: f.path, Reason: err.Error()})
			continue
		}
		var runs []Run
		var shaped bool
		switch format {
		case FormatSubpoena:
			runs, shaped, err = parseSubpoena(raw)
		case FormatRunResults:
			runs, shaped, err = parseRunResults(raw, claims)
		}
		if err != nil {
			notes.Unreadable = append(notes.Unreadable, Unreadable{Path: f.path, Reason: err.Error()})
			continue
		}
		if len(runs) == 0 {
			if shaped {
				notes.Unreadable = append(notes.Unreadable, Unreadable{
					Path: f.path, Reason: "no assertion results in the file"})
			} else {
				notes.Skipped = append(notes.Skipped, f.path)
			}
			continue
		}
		doc.Runs = append(doc.Runs, runs...)
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

func expand(paths []string) ([]candidate, error) {
	seen := map[string]bool{}
	var out []candidate
	add := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
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

// parseSubpoena returns the runs, whether the file carries the document shape
// at all, and an error only when the bytes are not readable as JSON.
func parseSubpoena(raw []byte) ([]Run, bool, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, err
	}
	var runs []Run
	for _, r := range doc.Runs {
		if r.CapturedAt == "" {
			r.CapturedAt = timestampFromRunID(r.RunID)
		}
		if r.RunID != "" || len(r.Assertions) > 0 {
			runs = append(runs, r)
		}
	}
	return runs, doc.Schema != "" || len(doc.Runs) > 0, nil
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
		} `json:"results"`
	} `json:"assertions"`
}

// parseRunResults returns the run, whether the file carries the run shape at
// all, and an error when the bytes are not readable as JSON. A file with the
// shape but no results comes back as one run with no assertions, which the
// caller reports as unreadable: a run file that yields nothing is not a pass.
func parseRunResults(raw []byte, claims map[string]string) ([]Run, bool, error) {
	var f runResultsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, false, err
	}
	shaped := f.RunID != "" || len(f.Assertions.Results) > 0 ||
		len(f.Assertions.Passed) > 0 || len(f.Assertions.Failed) > 0 || len(f.Assertions.Inconclusive) > 0
	if !shaped {
		return nil, false, nil
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
				ID:      res.ID,
				Claim:   claim(claims, res.ID),
				Source:  sourceFromEvaluator(res.Source, res.Evaluator),
				Kind:    res.Kind,
				Verdict: res.Verdict,
				Detail:  res.Detail,
			})
		}
		return []Run{run}, true, nil
	}
	add := func(ids []string, verdict string) {
		for _, id := range ids {
			run.Assertions = append(run.Assertions, Assertion{
				ID: id, Claim: claim(claims, id), Source: SourceTestimony,
				Kind: KindOther, Verdict: verdict,
			})
		}
	}
	add(f.Assertions.Passed, VerdictPass)
	add(f.Assertions.Failed, VerdictFail)
	add(f.Assertions.Inconclusive, VerdictInconclusive)
	return []Run{run}, true, nil
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
