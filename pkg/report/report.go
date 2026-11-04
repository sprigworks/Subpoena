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

// BatchGap separates two batches. Runs more than this far apart are reported
// separately: a burst five hours after the first is a different sitting, and
// checks that exist in only one of them must not be added together.
const BatchGap = 30 * time.Minute

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
	// Exercised says whether the check had anything to check in this run: for
	// an absence check, whether the situation it rules out actually arose.
	// Unset means the input did not record it, and the report says so rather
	// than letting a bare run count imply the check was meaningful here.
	Exercised *bool `json:"exercised,omitempty"`
}

// Unreadable is an input file the report was given but could not read. It is
// reported on the page and counted as a failure: a result that could not be
// read is not a pass.
type Unreadable struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Report is the aggregate, and the data file written beside the page. Nothing
// here is app-specific: a label is opaque, printed and counted.
type Report struct {
	Schema      string       `json:"schema"`
	GeneratedAt string       `json:"generated_at"`
	Window      Window       `json:"window"`
	Batches     []Batch      `json:"batches"`
	Inputs      Inputs       `json:"inputs"`
	Capture     Capture      `json:"capture"`
	Sources     SourceTotal  `json:"sources"`
	Invariants  []Invariant  `json:"invariants"`
	Unreadable  []Unreadable `json:"unreadable_inputs,omitempty"`
	Totals      Totals       `json:"totals"`
}

// Window is the span of capture times present in the input.
type Window struct {
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Seconds int64  `json:"seconds,omitempty"`
}

// Batch is one sitting: runs no more than BatchGap apart. A batch with no
// From is one whose runs carried no capture time.
type Batch struct {
	Index        int      `json:"index"`
	From         string   `json:"from,omitempty"`
	To           string   `json:"to,omitempty"`
	Runs         int      `json:"runs"`
	Results      int      `json:"results"`
	Passed       int      `json:"passed"`
	Failed       int      `json:"failed"`
	Inconclusive int      `json:"inconclusive"`
	Checks       int      `json:"checks"`
	RunsFailed   int      `json:"runs_with_a_failed_check"`
	Models       []string `json:"models,omitempty"`
	Fingerprint  []string `json:"harness_fingerprints,omitempty"`
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

// Totals counts results by effective verdict, plus runs and input files that
// did not come out clean.
type Totals struct {
	Passed         int `json:"passed"`
	Failed         int `json:"failed"`
	Inconclusive   int `json:"inconclusive"`
	RunsWithFailed int `json:"runs_with_a_failed_check,omitempty"`
	Unreadable     int `json:"unreadable_inputs,omitempty"`
}

// Invariant aggregates every result recorded for one assertion id.
type Invariant struct {
	ID           string `json:"id"`
	Claim        string `json:"claim"`
	RunsChecked  int    `json:"runs_checked"`
	Passed       int    `json:"passed"`
	Failed       int    `json:"failed"`
	Inconclusive int    `json:"inconclusive"`
	// Exercised is how many runs recorded that the check had something to
	// check. ExercisedRecorded is false when the input never said, in which
	// case Exercised means nothing and the page leaves the column blank.
	Exercised         int  `json:"exercised,omitempty"`
	ExercisedRecorded bool `json:"exercised_recorded,omitempty"`
	// RunsPerBatch is one count per batch, in the order the batches are
	// reported. A zero says the check never ran in that sitting.
	RunsPerBatch []int       `json:"runs_per_batch,omitempty"`
	Sources      []string    `json:"sources"`
	Failures     []ResultRef `json:"failures,omitempty"`
	Unproven     []ResultRef `json:"inconclusive_results,omitempty"`
}

// ResultRef points a failure back at the run that recorded it. Batch is set
// only when the report has more than one batch, so a single sitting does not
// label every line.
type ResultRef struct {
	RunID  string `json:"run_id"`
	Label  string `json:"label,omitempty"`
	Source string `json:"source"`
	Batch  int    `json:"batch,omitempty"`
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

	runs := flatten(docs)
	batchOf, accs := batches(runs)
	order := batchOrder(accs)
	pos := map[int]int{}
	for i, k := range order {
		pos[k] = i
	}

	for i, tr := range runs {
		run := tr.run
		acc := accs[batchOf[i]]
		batchPos := 0
		if acc == nil {
			acc = newBatchAcc(false)
		}
		if p, ok := pos[batchOf[i]]; ok {
			batchPos = p
		}
		r.Inputs.Runs++
		acc.runs++
		if run.Model != "" {
			acc.models[run.Model] = true
		}
		if run.HarnessFingerprint != "" {
			acc.fprs[run.HarnessFingerprint] = true
		}
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
		if tr.timed {
			if minT.IsZero() || tr.at.Before(minT) {
				minT = tr.at
			}
			if maxT.IsZero() || tr.at.After(maxT) {
				maxT = tr.at
			}
		}
		runFailed := false
		for _, a := range run.Assertions {
			r.Inputs.Assertions++
			acc.results++
			ib := byID[a.ID]
			if ib == nil {
				ib = newInvariantBuilder()
				byID[a.ID] = ib
			}
			acc.checks[a.ID] = true
			src := source(a.Source)
			r.Sources.add(src)
			verdict, reason := effectiveVerdict(a, complete)
			ib.runsChecked[run.RunID] = true
			ib.sources[src] = true
			if ib.batchRuns[batchPos] == nil {
				ib.batchRuns[batchPos] = map[string]bool{}
			}
			ib.batchRuns[batchPos][run.RunID] = true
			if a.Claim != "" {
				ib.claim = a.Claim
			}
			if a.Exercised != nil {
				ib.exercisedRecorded = true
				if *a.Exercised {
					ib.exercised++
				}
			}
			switch verdict {
			case VerdictPass:
				ib.passed++
				r.Totals.Passed++
				acc.passed++
			case VerdictFail:
				ib.failed++
				r.Totals.Failed++
				acc.failed++
				runFailed = true
				ib.failures = append(ib.failures, ResultRef{
					RunID: run.RunID, Label: run.Label, Source: src,
					Batch: shownBatch(batchPos, len(order)), Detail: a.Detail})
			default:
				ib.inconclusive++
				r.Totals.Inconclusive++
				acc.inconclusive++
				runFailed = true
				ib.unproven = append(ib.unproven, ResultRef{
					RunID: run.RunID, Label: run.Label, Source: src,
					Batch: shownBatch(batchPos, len(order)), Detail: joinDetail(a.Detail, reason)})
			}
		}
		if runFailed {
			r.Totals.RunsWithFailed++
			acc.runsFailed++
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
	r.Batches = finishBatches(accs)

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
			ID:                id,
			Claim:             claim,
			RunsChecked:       len(ib.runsChecked),
			Passed:            ib.passed,
			Failed:            ib.failed,
			Inconclusive:      ib.inconclusive,
			Exercised:         ib.exercised,
			ExercisedRecorded: ib.exercisedRecorded,
			RunsPerBatch:      ib.perBatch(len(order)),
			Sources:           ib.sortedSources(),
			Failures:          sortedRefs(ib.failures),
			Unproven:          sortedRefs(ib.unproven),
		})
	}
	return r
}

// AddUnreadable records input files that could not be read. Each counts as a
// failure: an unread file is not a pass.
func (r *Report) AddUnreadable(us []Unreadable) {
	r.Unreadable = append(r.Unreadable, us...)
	r.Totals.Unreadable = len(r.Unreadable)
}

// Proven reports whether every result passed under the report's rules and
// every input could be read.
func (r *Report) Proven() bool {
	return r.Totals.Failed == 0 && r.Totals.Inconclusive == 0 && r.Totals.Unreadable == 0
}

type timedRun struct {
	run   Run
	at    time.Time
	timed bool
}

func flatten(docs []Document) []timedRun {
	var out []timedRun
	for _, doc := range docs {
		for _, run := range doc.Runs {
			at, timed := parseTime(run.CapturedAt)
			out = append(out, timedRun{run: run, at: at, timed: timed})
		}
	}
	// Chronological, with runs carrying no time last. A batch boundary is a
	// gap in time, so sorting is what makes the batches meaningful.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].timed != out[j].timed {
			return out[i].timed
		}
		if !out[i].timed {
			return false
		}
		return out[i].at.Before(out[j].at)
	})
	return out
}

// batchAcc accumulates one batch.
type batchAcc struct {
	timed        bool
	from, to     time.Time
	runs         int
	results      int
	passed       int
	failed       int
	inconclusive int
	runsFailed   int
	checks       map[string]bool
	models       map[string]bool
	fprs         map[string]bool
}

// batches splits runs into sittings on a gap larger than BatchGap, returning
// each run's batch index and the accumulators.
func batches(runs []timedRun) ([]int, map[int]*batchAcc) {
	of := make([]int, len(runs))
	accs := map[int]*batchAcc{}
	index := -1
	untimed := -2
	var prev time.Time
	for i := range runs {
		if !runs[i].timed {
			of[i] = untimed
			if accs[untimed] == nil {
				accs[untimed] = newBatchAcc(false)
			}
			continue
		}
		if index < 0 || runs[i].at.Sub(prev) > BatchGap {
			index++
		}
		prev = runs[i].at
		of[i] = index
		if accs[index] == nil {
			accs[index] = newBatchAcc(true)
			accs[index].from, accs[index].to = runs[i].at, runs[i].at
		}
		acc := accs[index]
		if runs[i].at.Before(acc.from) {
			acc.from = runs[i].at
		}
		if runs[i].at.After(acc.to) {
			acc.to = runs[i].at
		}
	}
	return of, accs
}

func newBatchAcc(timed bool) *batchAcc {
	return &batchAcc{timed: timed, checks: map[string]bool{}, models: map[string]bool{}, fprs: map[string]bool{}}
}

// shownBatch is the batch number to print on a failure line: 0 when there is
// only one batch and the label would be noise.
func shownBatch(pos, batches int) int {
	if batches <= 1 {
		return 0
	}
	return pos + 1
}

// batchOrder is the accs keys in the order the batches are reported.
func batchOrder(accs map[int]*batchAcc) []int {
	keys := make([]int, 0, len(accs))
	for k := range accs {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func finishBatches(accs map[int]*batchAcc) []Batch {
	keys := make([]int, 0, len(accs))
	for k := range accs {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := make([]Batch, 0, len(keys))
	for i, k := range keys {
		a := accs[k]
		b := Batch{
			Index:        i + 1,
			Runs:         a.runs,
			Results:      a.results,
			Passed:       a.passed,
			Failed:       a.failed,
			Inconclusive: a.inconclusive,
			Checks:       len(a.checks),
			RunsFailed:   a.runsFailed,
			Models:       sortedKeys(a.models),
			Fingerprint:  sortedKeys(a.fprs),
		}
		if a.timed && !a.from.IsZero() {
			b.From = a.from.Format(time.RFC3339)
			b.To = a.to.Format(time.RFC3339)
		}
		out = append(out, b)
	}
	return out
}

type invariantBuilder struct {
	claim             string
	passed            int
	failed            int
	inconclusive      int
	exercised         int
	exercisedRecorded bool
	runsChecked       map[string]bool
	sources           map[string]bool
	batchRuns         map[int]map[string]bool
	failures          []ResultRef
	unproven          []ResultRef
}

func newInvariantBuilder() *invariantBuilder {
	return &invariantBuilder{
		runsChecked: map[string]bool{},
		sources:     map[string]bool{},
		batchRuns:   map[int]map[string]bool{},
	}
}

// perBatch is one count per batch position, in order.
func (b *invariantBuilder) perBatch(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = len(b.batchRuns[i])
	}
	return out
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
