// Package report turns the results of many assertion runs into one readable
// page and one machine-readable data file. It is a generic aggregator: it
// knows about runs, assertions, sources and verdicts, and nothing about the
// application that produced them. See docs/evidence-reports.md.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Schema identifies the two JSON shapes: the results document this package
// reads, and the report data file it writes.
const (
	SchemaResults = "https://subpoena.dev/schemas/results/v1"
	SchemaReport  = "https://subpoena.dev/schemas/report/v1"
)

// Sources name the origin of a result. The names are the ones
// internal/cross uses when it classifies what killed a mutant.
const (
	// SourceWitness is an independent observer: evidence.
	SourceWitness = "witness"
	// SourceTestimony is the application's own account: a span, a return
	// value, a log line.
	SourceTestimony = "testimony"
	// SourceOther is neither: an exit code, an output check, a target record.
	SourceOther = "other"
)

// Verdicts are the three-valued outcomes, spelled as pkg/harness spells them.
const (
	VerdictPass         = "pass"
	VerdictFail         = "fail"
	VerdictInconclusive = "inconclusive"
)

// Kinds are the assertion shapes. Only KindAbsent interacts with capture
// completeness: an absence can be proven only from a complete capture.
const (
	KindAbsent = "absent"
	KindExists = "exists"
	KindOther  = "other"
)

// Document is a Subpoena results document: the stable input format.
type Document struct {
	Schema string `json:"schema,omitempty"`
	Runs   []Run  `json:"runs"`
}

// Run is one assertion run.
type Run struct {
	RunID              string `json:"run_id"`
	Label              string `json:"label,omitempty"`
	Model              string `json:"model,omitempty"`
	HarnessFingerprint string `json:"harness_fingerprint,omitempty"`
	CapturedAt         string `json:"captured_at,omitempty"`
	// CaptureComplete is required for assertion results of kind absent: an
	// absence cannot be proven from a capture that is not stated to be
	// complete. Absent or false is reported as inconclusive.
	CaptureComplete *bool       `json:"capture_complete,omitempty"`
	Assertions      []Assertion `json:"assertions"`
}

// Assertion is one result inside a run.
type Assertion struct {
	ID      string `json:"id"`
	Claim   string `json:"claim,omitempty"`
	Source  string `json:"source,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Verdict string `json:"verdict"`
	Detail  string `json:"detail,omitempty"`
}

// Report is the aggregate, and the data file written beside the page. Nothing
// here is app-specific: a label is opaque, printed and counted.
type Report struct {
	Schema      string      `json:"schema"`
	GeneratedAt string      `json:"generated_at"`
	Window      Window      `json:"window"`
	Inputs      Inputs      `json:"inputs"`
	Capture     Capture     `json:"capture"`
	Sources     SourceTotal `json:"sources"`
	Invariants  []Invariant `json:"invariants"`
	Totals      Totals      `json:"totals"`
}

// Window is the span of capture times present in the input.
type Window struct {
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Seconds int64  `json:"seconds,omitempty"`
}

// Inputs describes what was tested.
type Inputs struct {
	Runs               int      `json:"runs"`
	Assertions         int      `json:"assertions"`
	DistinctClaims     int      `json:"distinct_claims"`
	HarnessFingerprint []string `json:"harness_fingerprints,omitempty"`
	Models             []string `json:"models,omitempty"`
	Labels             int      `json:"labels"`
}

// Capture counts runs by whether the capture was complete. Unstated counts a
// run whose input did not say; it cannot prove an absence either.
type Capture struct {
	Complete   int `json:"complete"`
	Incomplete int `json:"incomplete"`
	Unstated   int `json:"unstated,omitempty"`
}

// SourceTotal counts results per source.
type SourceTotal struct {
	Witness   int `json:"witness"`
	Testimony int `json:"testimony"`
	Other     int `json:"other"`
}

// Totals counts results by effective verdict.
type Totals struct {
	Passed       int `json:"passed"`
	Failed       int `json:"failed"`
	Inconclusive int `json:"inconclusive"`
}

// Invariant aggregates every result recorded for one assertion id.
type Invariant struct {
	ID           string      `json:"id"`
	Claim        string      `json:"claim"`
	RunsChecked  int         `json:"runs_checked"`
	Passed       int         `json:"passed"`
	Failed       int         `json:"failed"`
	Inconclusive int         `json:"inconclusive"`
	Sources      []string    `json:"sources"`
	Failures     []ResultRef `json:"failures,omitempty"`
	Unproven     []ResultRef `json:"inconclusive_results,omitempty"`
}

// ResultRef points a failure back at the run that recorded it.
type ResultRef struct {
	RunID  string `json:"run_id"`
	Label  string `json:"label,omitempty"`
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
}

// Build aggregates the runs of every document into one report. A pass with
// kind absent in a run whose capture was incomplete is reported as
// inconclusive, the same rule the harness applies to an absence on an
// incomplete snapshot.
func Build(docs ...Document) *Report {
	r := &Report{
		Schema:      SchemaReport,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	byID := map[string]*invariantBuilder{}
	fingerprints := map[string]bool{}
	models := map[string]bool{}
	labels := map[string]bool{}
	var minT, maxT time.Time

	for _, doc := range docs {
		for _, run := range doc.Runs {
			r.Inputs.Runs++
			complete := run.CaptureComplete != nil && *run.CaptureComplete
			switch {
			case run.CaptureComplete == nil:
				r.Capture.Unstated++
			case complete:
				r.Capture.Complete++
			default:
				r.Capture.Incomplete++
			}
			if run.HarnessFingerprint != "" {
				fingerprints[run.HarnessFingerprint] = true
			}
			if run.Model != "" {
				models[run.Model] = true
			}
			if run.Label != "" {
				labels[run.Label] = true
			}
			if t, ok := parseTime(run.CapturedAt); ok {
				if minT.IsZero() || t.Before(minT) {
					minT = t
				}
				if maxT.IsZero() || t.After(maxT) {
					maxT = t
				}
			}
			for _, a := range run.Assertions {
				r.Inputs.Assertions++
				ib := byID[a.ID]
				if ib == nil {
					ib = &invariantBuilder{runsChecked: map[string]bool{}, sources: map[string]bool{}}
					byID[a.ID] = ib
				}
				src := source(a.Source)
				r.Sources.add(src)
				verdict, reason := effectiveVerdict(a, complete)
				ib.runsChecked[run.RunID] = true
				ib.sources[src] = true
				if a.Claim != "" {
					ib.claim = a.Claim
				}
				switch verdict {
				case VerdictPass:
					ib.passed++
					r.Totals.Passed++
				case VerdictFail:
					ib.failed++
					r.Totals.Failed++
					ib.failures = append(ib.failures, ResultRef{
						RunID: run.RunID, Label: run.Label, Source: src, Detail: a.Detail})
				default:
					ib.inconclusive++
					r.Totals.Inconclusive++
					ib.unproven = append(ib.unproven, ResultRef{
						RunID: run.RunID, Label: run.Label, Source: src, Detail: joinDetail(a.Detail, reason)})
				}
			}
		}
	}

	r.Inputs.DistinctClaims = len(byID)
	r.Inputs.Labels = len(labels)
	r.Inputs.HarnessFingerprint = sortedKeys(fingerprints)
	r.Inputs.Models = sortedKeys(models)
	if !minT.IsZero() {
		r.Window.From = minT.Format(time.RFC3339)
		r.Window.To = maxT.Format(time.RFC3339)
		r.Window.Seconds = int64(maxT.Sub(minT).Seconds())
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ib := byID[id]
		claim := ib.claim
		if claim == "" {
			claim = titleize(id)
		}
		r.Invariants = append(r.Invariants, Invariant{
			ID:           id,
			Claim:        claim,
			RunsChecked:  len(ib.runsChecked),
			Passed:       ib.passed,
			Failed:       ib.failed,
			Inconclusive: ib.inconclusive,
			Sources:      ib.sortedSources(),
			Failures:     sortedRefs(ib.failures),
			Unproven:     sortedRefs(ib.unproven),
		})
	}
	return r
}

// Proven reports whether every result passed under the report's rules.
func (r *Report) Proven() bool { return r.Totals.Failed == 0 && r.Totals.Inconclusive == 0 }

type invariantBuilder struct {
	claim        string
	passed       int
	failed       int
	inconclusive int
	runsChecked  map[string]bool
	sources      map[string]bool
	failures     []ResultRef
	unproven     []ResultRef
}

func (b *invariantBuilder) sortedSources() []string { return sortedKeys(b.sources) }

func effectiveVerdict(a Assertion, captureComplete bool) (string, string) {
	v := strings.ToLower(strings.TrimSpace(a.Verdict))
	switch v {
	case VerdictPass, VerdictFail, VerdictInconclusive:
	default:
		return VerdictInconclusive, fmt.Sprintf("unrecognized verdict %q", a.Verdict)
	}
	if v == VerdictPass && !captureComplete && strings.EqualFold(a.Kind, KindAbsent) {
		return VerdictInconclusive, "capture incomplete, absence not proven"
	}
	return v, ""
}

func source(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SourceWitness:
		return SourceWitness
	case SourceTestimony:
		return SourceTestimony
	default:
		return SourceOther
	}
}

func (s *SourceTotal) add(src string) {
	switch src {
	case SourceWitness:
		s.Witness++
	case SourceTestimony:
		s.Testimony++
	default:
		s.Other++
	}
}

func joinDetail(detail, reason string) string {
	switch {
	case reason == "":
		return detail
	case detail == "":
		return reason
	default:
		return detail + " — " + reason
	}
}

func sortedRefs(refs []ResultRef) []ResultRef {
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].RunID < refs[j].RunID })
	return refs
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "20060102T150405Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// titleize turns an assertion id into a readable title when the input carries
// no claim of its own: "no_denied_chunk_in_context" -> "No denied chunk in
// context".
func titleize(id string) string {
	words := strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(id))
	if len(words) == 0 {
		return id
	}
	joined := strings.Join(words, " ")
	return strings.ToUpper(joined[:1]) + joined[1:]
}
