package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Markdown renders the readable page. maxFailures caps the examples listed for
// one claim; 0 lists every one. The data file always holds all of them.
func Markdown(r *Report, maxFailures int) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	p("# Test evidence report\n\n")
	p("**What this covers.** %s, %s.\n\n", plural(r.Inputs.Runs, "test run"), window(r.Window))
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
	p("**Result.** %s\n\n", result(r.Totals, r.Inputs.Runs))
	p("**Not verified.** Nothing here has been signed or tamper-checked, and none of these runs " +
		"has been through a verification step. This page restates what the run files recorded.\n\n")

	if len(r.Batches) > 1 {
		p("## Batches\n\n")
		p("Each batch is one sitting. Run ids, checks present and outcomes differ between them, " +
			"so a total across batches can hide which sitting a check ever ran in.\n\n")
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
	var cols []string
	cols = append(cols, "Claim", "Runs with a result")
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
	align[0], align[len(cols)-1] = "---", "---"
	p("| %s |\n", strings.Join(cols, " | "))
	p("| %s |\n", strings.Join(align, " | "))
	for _, inv := range orderedInvariants(r.Invariants) {
		row := []string{cell(inv.Claim), comma(inv.RunsChecked)}
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
	p("A run counts here whether or not the check had anything to check in it. A passing check " +
		"for something that never happened is not evidence that it works: where the input does not " +
		"record how often a check was exercised, this page cannot say.\n\n")
	if perBatch {
		p("**Runs by batch** is one count per batch, in the order of the Batches table above; a " +
			"zero means the check never ran in that sitting.\n\n")
	}

	p("## What was not proven\n\n")
	failed := filterInvariants(r.Invariants, func(i Invariant) bool { return i.Failed > 0 })
	inconclusive := filterInvariants(r.Invariants, func(i Invariant) bool { return i.Inconclusive > 0 })
	if len(failed) == 0 {
		p("No check failed.\n\n")
	} else {
		p("### Failed (%s over %s)\n\n", plural(r.Totals.Failed, "result"), plural(len(failed), "check"))
		for _, inv := range failed {
			p("**%s** (`%s`) — %s\n\n", inv.Claim, inv.ID, verdictLine(inv.RunsChecked, inv.Failed, "failed"))
			listResults(&b, inv.Failures, maxFailures)
		}
	}
	if len(inconclusive) == 0 {
		p("### Inconclusive\n\nNone.\n\n")
	} else {
		p("### Inconclusive (%s over %s)\n\n", plural(r.Totals.Inconclusive, "result"), plural(len(inconclusive), "check"))
		p("An inconclusive result is a failure: the capture could not support the claim.\n\n")
		for _, inv := range inconclusive {
			p("**%s** (`%s`) — %s\n\n", inv.Claim, inv.ID, verdictLine(inv.RunsChecked, inv.Inconclusive, "inconclusive"))
			listResults(&b, inv.Unproven, maxFailures)
		}
	}
	if len(r.Unreadable) > 0 {
		p("### Unreadable input (%s)\n\n", plural(len(r.Unreadable), "file"))
		p("These were given to this report and could not be read, so their results are missing. " +
			"A result that could not be read is counted as a failure, not a pass.\n\n")
		for _, u := range r.Unreadable {
			p("- `%s`: %s\n", u.Path, u.Reason)
		}
		p("\n")
	}

	p("### How to read this\n\n")
	p("- **Claim** is the wording supplied with the run results, or the check's id turned into a " +
		"sentence when the input supplies none. It is not checked against the query: what was " +
		"actually checked is the query in each failed line below.\n")
	p("- **Runs with a result** says how often a check ran, not how often it had anything to test.\n")
	p("- **Observed by** names the origin of a result. *testimony* is the system's own account: " +
		"a span, a return value, a log line. *witness* is an independent observer, which is " +
		"evidence; *other* is neither. A claim resting on testimony alone is not independently " +
		"confirmed, and two sources are never added together.\n")
	p("- **Inconclusive is a failure.** It is never counted as passed and never omitted.\n")
	p("- A run whose capture is not stated to be complete cannot prove an absence: those passes " +
		"are reported as inconclusive here.\n")
	p("- This page states what was checked and what was found. It is not a claim about anything " +
		"outside the runs listed above, and a failure is a check that did not hold — not by itself " +
		"a finding about why.\n")
	return b.String()
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

// listResults prints one line per failed result: the question the run asked
// (its label), the run id, what observed it, and what was checked.
func listResults(b *strings.Builder, refs []ResultRef, max int) {
	shown := refs
	if max > 0 && len(shown) > max {
		shown = shown[:max]
	}
	for _, ref := range shown {
		what := strings.TrimSpace(ref.Detail)
		if what == "" {
			what = "no detail recorded"
		}
		where := ref.Source
		if ref.Batch > 0 {
			where = fmt.Sprintf("batch %d, %s", ref.Batch, ref.Source)
		}
		if ref.Label != "" {
			fmt.Fprintf(b, "- **%s** — run `%s` (%s), checked: %s\n", ref.Label, ref.RunID, where, what)
			continue
		}
		fmt.Fprintf(b, "- run `%s` (%s), checked: %s\n", ref.RunID, where, what)
	}
	if max > 0 && len(refs) > max {
		fmt.Fprintf(b, "- … and %s more, in the data file.\n", plural(len(refs)-max, "result"))
	}
	b.WriteString("\n")
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

// result leads with what did not come out clean — an input that could not be
// read first, then how many runs a failure touched — because a share of
// results makes a bad run set look small.
func result(t Totals, runs int) string {
	total := t.Passed + t.Failed + t.Inconclusive
	var parts []string
	if t.Unreadable > 0 {
		parts = append(parts, fmt.Sprintf("%s could not be read", plural(t.Unreadable, "input file")))
	}
	if t.Failed == 0 && t.Inconclusive == 0 {
		parts = append(parts, fmt.Sprintf("all %s passed", plural(total, "assertion result")))
	} else {
		parts = append(parts, fmt.Sprintf("%s of %s assertion results were not proven: %s failed, %s inconclusive",
			comma(t.Failed+t.Inconclusive), comma(total), comma(t.Failed), comma(t.Inconclusive)))
	}
	if runs > 0 && (t.Failed > 0 || t.Inconclusive > 0) {
		parts = append(parts, fmt.Sprintf("%s of %s runs (%s) recorded at least one failed or inconclusive check",
			comma(t.RunsWithFailed), comma(runs), percent(t.RunsWithFailed, runs)))
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
