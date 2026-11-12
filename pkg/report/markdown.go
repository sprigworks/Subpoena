package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Markdown renders the readable page: a short body in the reader's terms, then
// two appendices holding what each check looks for and every run that did not
// pass. Nothing is capped, so the page is complete without the data file.
func Markdown(r *Report) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	p("# Test evidence report\n\n")
	p("**What this covers.** %s, %s", plural(r.Inputs.Runs, "test run"), window(r.Window))
	if r.Window.Untimed > 0 && r.Window.From != "" {
		p("; %s no usable time, so that span leaves it out", untimed(r.Window.Untimed))
	}
	p(".\n\n")
	if len(r.Batches) > 1 {
		p("**Sittings.** %s, separated by more than %s. A check that exists in one of them is "+
			"not counted against the others.\n\n", plural(len(r.Batches), "batch"), duration(int64(BatchGap.Seconds())))
	}
	p("**What was tested.** %s", tested(r.Inputs))
	if fp := fingerprints(r.Inputs.HarnessFingerprint); fp != "" {
		p(" Harness %s.", fp)
	}
	p("\n\n")
	p("**How this was observed.** %s\n\n", observed(r.Sources))
	p("**Capture.** %s\n\n", capture(r.Capture))
	p("**Input files.** %s\n\n", inputFiles(r.Inputs, len(r.Unreadable)))
	p("**Result.** %s\n\n", result(r.Totals, r.Inputs.Runs))
	p("**Not verified.** Nothing here has been signed or tamper-checked, and none of these runs " +
		"has been through a verification step. This page restates what the run files recorded.\n\n")

	if len(r.Batches) > 1 {
		p("## Batches\n\n")
		p("| Batch | Runs | Window | Checks | Results | Passed | Failed | Inconclusive | Runs with a failure |\n")
		p("| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
		for _, bt := range r.Batches {
			p("| %d | %s | %s | %s | %s | %s | %s | %s | %s |\n", bt.Index, comma(bt.Runs),
				batchWindow(bt), comma(bt.Checks), comma(bt.Results), comma(bt.Passed), comma(bt.Failed),
				comma(bt.Inconclusive), comma(bt.RunsFailed))
		}
		p("\n")
	}

	p("## What was checked\n\n")
	perBatch := len(r.Batches) > 1
	exercised := anyExercised(r.Invariants)
	cols := []string{"Claim", "Passes if", "Runs with a result"}
	if perBatch {
		cols = append(cols, "Runs by batch")
	}
	if exercised {
		cols = append(cols, "Exercised")
	}
	cols = append(cols, "Passed", "Failed", "Inconclusive", "Observed by")
	align := make([]string, len(cols))
	for i := range align {
		align[i] = "---:"
	}
	align[0], align[1], align[len(cols)-1] = "---", "---", "---"
	p("| %s |\n", strings.Join(cols, " | "))
	p("| %s |\n", strings.Join(align, " | "))
	for _, inv := range orderedInvariants(r.Invariants) {
		row := []string{cell(inv.Claim), passesIf(inv.Kinds), comma(inv.RunsChecked)}
		if perBatch {
			row = append(row, perBatchCell(inv))
		}
		if exercised {
			row = append(row, exercisedCell(inv))
		}
		row = append(row, comma(inv.Passed), comma(inv.Failed), comma(inv.Inconclusive),
			strings.Join(inv.Sources, ", "))
		p("| %s |\n", strings.Join(row, " | "))
	}
	p("\n")
	p("A check that passes if something is **not found** also passes in any run where that thing " +
		"never came up, so a high count is not proof the check was tested. ")
	if exercised {
		p("**Exercised** is how many runs recorded having something to check; a dash means the input " +
			"did not say.\n\n")
	} else {
		p("The input does not record how often a check had anything to check, so these counts say " +
			"how often a check ran, not how often it was tested.\n\n")
	}
	if perBatch {
		p("**Runs by batch** is one count per batch, in the order of the Batches table; a zero means " +
			"the check never ran in that sitting.\n\n")
	}

	p("## What was not proven\n\n")
	failed := filterInvariants(r.Invariants, func(i Invariant) bool { return i.Failed > 0 })
	inconclusive := filterInvariants(r.Invariants, func(i Invariant) bool { return i.Inconclusive > 0 })
	if len(failed) == 0 {
		p("No check failed.\n\n")
	} else {
		p("### Failed (%s over %s)\n\n", plural(r.Totals.Failed, "result"), plural(len(failed), "check"))
		for _, inv := range failed {
			p("**%s** — %s\n\n", inv.Claim, verdictLine(inv.RunsChecked, inv.Failed, "failed"))
			listQuestions(&b, inv, inv.Failures)
		}
	}
	if len(inconclusive) == 0 {
		p("### Inconclusive\n\nNone.\n\n")
	} else {
		p("### Inconclusive (%s over %s)\n\n", plural(r.Totals.Inconclusive, "result"), plural(len(inconclusive), "check"))
		p("An inconclusive result is a failure: the run could not support the claim.\n\n")
		for _, inv := range inconclusive {
			p("**%s** — %s\n\n", inv.Claim, verdictLine(inv.RunsChecked, inv.Inconclusive, "inconclusive"))
			listQuestions(&b, inv, inv.Unproven)
		}
	}
	if len(r.Unreadable) > 0 {
		p("### Unreadable input (%s)\n\n", plural(len(r.Unreadable), "file problem"))
		p("These were given to this report and could not be used, so their results are missing. " +
			"A result that could not be read is counted as a failure, not a pass.\n\n")
		for _, u := range r.Unreadable {
			p("- `%s`: %s\n", u.Path, u.Reason)
		}
		p("\n")
	}

	p("## How to read this\n\n")
	p("- **Claim** is the wording supplied with the run results, or the check's id turned into a " +
		"sentence when none is supplied. This report does not test it against the query: Appendix A " +
		"shows what each check actually looks for.\n")
	p("- **Observed by** names the origin of a result. *testimony* is the system's own account: " +
		"a span, a return value, a log line. *witness* is an independent observer, which is " +
		"evidence; *other* is neither. A claim resting on testimony alone is not independently " +
		"confirmed, and two sources are never added together.\n")
	p("- **Inconclusive is a failure.** It is never counted as passed and never omitted.\n")
	p("- A run whose capture is not stated to be complete cannot prove an absence: a pass that " +
		"could rest on one is reported as inconclusive here.\n")
	p("- This page states what was checked and what was found. It is not a claim about anything " +
		"outside the runs listed, and a failure is a check that did not hold — not by itself a " +
		"finding about why.\n\n")

	p("## Appendix A: what each check looks for\n\n")
	for _, inv := range orderedInvariants(r.Invariants) {
		how := ""
		if rule := passesIf(inv.Kinds); rule != seeAppendix {
			how = ", passes if " + rule
		}
		p("- **%s** (`%s`)%s: %s\n", inv.Claim, inv.ID, how, queries(inv.Queries))
	}
	p("\n")

	if len(failed)+len(inconclusive) > 0 {
		p("## Appendix B: every result that did not pass\n\n")
		for _, inv := range failed {
			listRuns(&b, inv, inv.Failures, "failed")
		}
		for _, inv := range inconclusive {
			listRuns(&b, inv, inv.Unproven, "inconclusive")
		}
		p("\n")
	}
	return b.String()
}

// seeAppendix is the table's answer for a check that is not a plain found or
// not found, such as a match on the output.
const seeAppendix = "see Appendix A"

// passesIf says in a reader's words what makes a check pass. It is read from
// the kind the run recorded, so it cannot overstate the query.
func passesIf(kinds []string) string {
	if len(kinds) == 1 {
		switch kinds[0] {
		case KindExists:
			return "found"
		case KindAbsent:
			return "not found"
		}
	}
	return seeAppendix
}

// queries shows what a check looks for. A check whose query varies by question
// shows the first; the data file holds them all.
func queries(qs []string) string {
	switch len(qs) {
	case 0:
		return "no query recorded"
	case 1:
		return code(qs[0])
	}
	return fmt.Sprintf("%s (one of %d variants, by question)", code(qs[0]), len(qs))
}

func code(s string) string {
	if strings.Contains(s, "`") {
		return "`` " + s + " ``"
	}
	return "`" + s + "`"
}

// listQuestions states results that did not pass in the reader's terms: which
// question, out of how many runs that asked it, and in which batch.
func listQuestions(b *strings.Builder, inv Invariant, refs []ResultRef) {
	type tally struct {
		n       int
		batches map[int]bool
	}
	byLabel := map[string]*tally{}
	var labels []string
	for _, ref := range refs {
		t := byLabel[ref.Label]
		if t == nil {
			t = &tally{batches: map[int]bool{}}
			byLabel[ref.Label] = t
			labels = append(labels, ref.Label)
		}
		t.n++
		if ref.Batch > 0 {
			t.batches[ref.Batch] = true
		}
	}
	sort.Strings(labels)
	for _, label := range labels {
		t := byLabel[label]
		name := label
		if name == "" {
			name = "runs with no label"
		}
		fmt.Fprintf(b, "- %s: %s of %s%s\n", name, comma(t.n), plural(inv.RunsPerLabel[label], "run"), batchNote(t.batches))
	}
	b.WriteString("\n")
}

func batchNote(batches map[int]bool) string {
	if len(batches) == 0 {
		return ""
	}
	nums := make([]int, 0, len(batches))
	for n := range batches {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("%d", n)
	}
	if len(parts) == 1 {
		return " (batch " + parts[0] + ")"
	}
	return " (batches " + strings.Join(parts, ", ") + ")"
}

// listRuns is the full record: one line per result, with the run to look up
// and what was checked.
func listRuns(b *strings.Builder, inv Invariant, refs []ResultRef, verdict string) {
	for _, ref := range refs {
		where := ref.Source
		if ref.Batch > 0 {
			where = fmt.Sprintf("batch %d, %s", ref.Batch, ref.Source)
		}
		what := strings.TrimSpace(ref.Detail)
		if what == "" {
			what = "no detail recorded"
		}
		name := ""
		if ref.Label != "" {
			name = ref.Label + " "
		}
		fmt.Fprintf(b, "- `%s` %s %s(%s, `%s`): %s\n", ref.RunID, verdict, name, where, inv.ID, code(what))
	}
}

func anyExercised(invs []Invariant) bool {
	for _, inv := range invs {
		if inv.ExercisedRecorded {
			return true
		}
	}
	return false
}

func exercisedCell(inv Invariant) string {
	if !inv.ExercisedRecorded {
		return "—"
	}
	return comma(inv.Exercised)
}

// perBatchCell is one count per batch, in the order the batches are reported.
func perBatchCell(inv Invariant) string {
	parts := make([]string, len(inv.RunsPerBatch))
	for i, n := range inv.RunsPerBatch {
		parts[i] = comma(n)
	}
	return strings.Join(parts, " · ")
}

func untimed(n int) string {
	if n == 1 {
		return "1 run has"
	}
	return comma(n) + " runs have"
}

func batchWindow(bt Batch) string {
	if bt.From == "" {
		return "no run times"
	}
	from, err1 := time.Parse(time.RFC3339, bt.From)
	to, err2 := time.Parse(time.RFC3339, bt.To)
	if err1 != nil || err2 != nil {
		return bt.From + " to " + bt.To
	}
	return fmt.Sprintf("%s to %s UTC", from.Format("2006-01-02 15:04"), to.Format("15:04"))
}

func orderedInvariants(invs []Invariant) []Invariant {
	out := append([]Invariant(nil), invs...)
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Failed > 0) != (out[j].Failed > 0) {
			return out[i].Failed > 0
		}
		if (out[i].Inconclusive > 0) != (out[j].Inconclusive > 0) {
			return out[i].Inconclusive > 0
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func filterInvariants(invs []Invariant, keep func(Invariant) bool) []Invariant {
	var out []Invariant
	for _, inv := range invs {
		if keep(inv) {
			out = append(out, inv)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func window(w Window) string {
	if w.From == "" {
		return "no run times recorded"
	}
	from, err1 := time.Parse(time.RFC3339, w.From)
	to, err2 := time.Parse(time.RFC3339, w.To)
	if err1 != nil || err2 != nil {
		return w.From + " to " + w.To
	}
	return fmt.Sprintf("%s to %s UTC (%s)",
		from.Format("2006-01-02 15:04"), to.Format("15:04"), duration(w.Seconds))
}

func duration(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func tested(in Inputs) string {
	parts := []string{plural(in.Labels, "setup")}
	if len(in.Models) > 0 {
		parts = append(parts, "model "+strings.Join(in.Models, ", "))
	}
	return strings.Join(parts, "; ") + "."
}

func fingerprints(fps []string) string {
	switch len(fps) {
	case 0:
		return ""
	case 1:
		return short(fps[0])
	default:
		return fmt.Sprintf("%d differ (%s …)", len(fps), short(fps[0]))
	}
}

func short(fp string) string {
	const keep = 8
	if len(fp) > keep+8 {
		return "`" + fp[:keep+8] + "…`"
	}
	return "`" + fp + "`"
}

func observed(s SourceTotal) string {
	return fmt.Sprintf("%s from the system's own telemetry (testimony); %s from an independent witness (evidence); "+
		"%s from other checks.",
		plural(s.Testimony, "result"), plural(s.Witness, "result"), plural(s.Other, "result"))
}

func capture(c Capture) string {
	parts := []string{fmt.Sprintf("%s of %s runs reported a complete capture",
		comma(c.Complete), comma(c.Complete+c.Incomplete+c.Unstated))}
	if c.Incomplete > 0 {
		parts[0] += fmt.Sprintf("; %s reported an incomplete capture", plural(c.Incomplete, "run"))
	}
	if c.Unstated > 0 {
		parts = append(parts, fmt.Sprintf("%s did not state capture completeness", plural(c.Unstated, "run")))
	}
	return strings.Join(parts, ", ") + "."
}

// inputFiles says how many files became runs and what happened to the rest, so
// a reader can compare the count with the runs they expected.
func inputFiles(in Inputs, unreadable int) string {
	s := fmt.Sprintf("%s read as results", plural(in.FilesRead, "file"))
	if in.FilesSkipped > 0 {
		s += fmt.Sprintf("; %s set aside as not results", plural(in.FilesSkipped, "other file"))
	}
	if unreadable > 0 {
		s += fmt.Sprintf("; %s", plural(unreadable, "problem"))
	}
	return s + ". This page counts only what it was given: a run whose file is missing does not appear."
}

// result leads with what did not come out clean — an input that could not be
// read first, then how many runs a failure touched — because a share of
// results makes a bad run set look small.
func result(t Totals, runs int) string {
	total := t.Passed + t.Failed + t.Inconclusive
	var parts []string
	if t.Unreadable > 0 {
		parts = append(parts, fmt.Sprintf("%s could not be read", plural(t.Unreadable, "input file")))
	}
	switch {
	case total == 0:
		parts = append(parts, "no assertion results were read")
	case t.Failed == 0 && t.Inconclusive == 0:
		parts = append(parts, fmt.Sprintf("all %s passed", plural(total, "assertion result")))
	default:
		if runs > 0 {
			parts = append(parts, fmt.Sprintf("%s of %s runs (%s) recorded at least one failed or inconclusive check",
				comma(t.RunsWithFailed), comma(runs), percent(t.RunsWithFailed, runs)))
		}
		parts = append(parts, fmt.Sprintf("%s of %s assertion results were not proven: %s failed, %s inconclusive",
			comma(t.Failed+t.Inconclusive), comma(total), comma(t.Failed), comma(t.Inconclusive)))
	}
	s := strings.Join(parts, "; ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func percent(n, of int) string {
	if of == 0 {
		return "0%"
	}
	v := float64(n) / float64(of) * 100
	if v == float64(int(v)) {
		return fmt.Sprintf("%d%%", int(v))
	}
	return fmt.Sprintf("%.1f%%", v)
}

func verdictLine(runs, n int, word string) string {
	return fmt.Sprintf("%s of %s %s", comma(n), plural(runs, "run"), word)
}

// comma renders a count with thousands separators, for prose a reader scans.
func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func cell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	switch noun {
	case "setup":
		return fmt.Sprintf("%s setups", comma(n))
	case "batch":
		return fmt.Sprintf("%s batches", comma(n))
	}
	return fmt.Sprintf("%s %ss", comma(n), noun)
}
