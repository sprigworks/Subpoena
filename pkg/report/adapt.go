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

// Load reads every path in the given format and returns one document. A path
// is a file, a glob, or a directory (walked for *.json files). A directory
// walk skips a file that does not parse in the format, so a run directory
// holding traces beside its results is fine; a file named outright must parse.
// claims, when non-nil, supplies a title for an assertion id that carries none.
func Load(format string, paths []string, claims map[string]string) (Document, []string, error) {
	if format != FormatSubpoena && format != FormatRunResults {
		return Document{}, nil, fmt.Errorf("unknown format %q (want %s or %s)", format, FormatSubpoena, FormatRunResults)
	}
	files, err := expand(paths)
	if err != nil {
		return Document{}, nil, err
	}
	doc := Document{Schema: SchemaResults}
	var skipped []string
	for _, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			if f.explicit {
				return Document{}, skipped, err
			}
			skipped = append(skipped, f.path)
			continue
		}
		var runs []Run
		var err2 error
		switch format {
		case FormatSubpoena:
			runs, err2 = parseSubpoena(raw)
		case FormatRunResults:
			runs, err2 = parseRunResults(raw, claims)
		}
		if err2 != nil || len(runs) == 0 {
			if f.explicit {
				if err2 == nil {
					err2 = fmt.Errorf("no runs in %s", f.path)
				}
				return Document{}, skipped, err2
			}
			skipped = append(skipped, f.path)
			continue
		}
		doc.Runs = append(doc.Runs, runs...)
	}
	if len(doc.Runs) == 0 {
		return Document{}, skipped, fmt.Errorf("no runs found in %d file(s)", len(files))
	}
	if claims != nil {
		applyClaims(&doc, claims)
	}
	return doc, skipped, nil
}

type candidate struct {
	path     string
	explicit bool // named outright or produced by a glob, not found by walking
}

func expand(paths []string) ([]candidate, error) {
	seen := map[string]bool{}
	var out []candidate
	add := func(path string, explicit bool) {
		if seen[path] {
			return
		}
		seen[path] = true
		out = append(out, candidate{path: path, explicit: explicit})
	}
	for _, p := range paths {
		if strings.ContainsAny(p, "*?[") {
			matches, err := filepath.Glob(p)
			if err != nil {
				return nil, err
			}
			for _, m := range matches {
				add(m, true)
			}
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(p, true)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".json") {
				add(path, false)
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

func parseSubpoena(raw []byte) ([]Run, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
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
		} `json:"results"`
	} `json:"assertions"`
}

func parseRunResults(raw []byte, claims map[string]string) ([]Run, error) {
	var f runResultsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.RunID == "" && len(f.Assertions.Results) == 0 {
		return nil, fmt.Errorf("not a run-results file")
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
		return []Run{run}, nil
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
