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
	p("**What was tested.** %s", tested(r.Inputs))
	if fp := fingerprints(r.Inputs.HarnessFingerprint); fp != "" {
		p(" Harness %s.", fp)
	}
	p("\n\n")
	p("**How this was observed.** %s\n\n", observed(r.Sources))
	p("**Capture.** %s\n\n", capture(r.Capture))
	p("**Result.** %s\n\n", result(r.Totals))

	p("## What was checked\n\n")
	p("| Claim | Runs checked | Passed | Failed | Inconclusive | Observed by |\n")
	p("| --- | ---: | ---: | ---: | ---: | --- |\n")
	for _, inv := range orderedInvariants(r.Invariants) {
		p("| %s | %s | %s | %s | %s | %s |\n",
			cell(inv.Claim), comma(inv.RunsChecked), comma(inv.Passed), comma(inv.Failed), comma(inv.Inconclusive), strings.Join(inv.Sources, ", "))
	}
	p("\n")

	p("## What was not proven\n\n")
	failed := filterInvariants(r.Invariants, func(i Invariant) bool { return i.Failed > 0 })
	inconclusive := filterInvariants(r.Invariants, func(i Invariant) bool { return i.Inconclusive > 0 })
	if len(failed) == 0 {
		p("No claim failed.\n\n")
	} else {
		p("### Failed (%s over %s)\n\n", plural(r.Totals.Failed, "result"), plural(len(failed), "claim"))
		for _, inv := range failed {
			p("**%s** (`%s`) — %s\n\n", inv.Claim, inv.ID, verdictLine(inv.RunsChecked, inv.Failed, "failed"))
			listResults(&b, inv.Failures, maxFailures)
		}
	}
	if len(inconclusive) == 0 {
		p("### Inconclusive\n\nNone.\n\n")
	} else {
		p("### Inconclusive (%s over %s)\n\n", plural(r.Totals.Inconclusive, "result"), plural(len(inconclusive), "claim"))
		p("An inconclusive result is a failure: the capture could not support the claim.\n\n")
		for _, inv := range inconclusive {
			p("**%s** (`%s`) — %s\n\n", inv.Claim, inv.ID, verdictLine(inv.RunsChecked, inv.Inconclusive, "inconclusive"))
			listResults(&b, inv.Unproven, maxFailures)
		}
	}

	p("---\n\n")
	p("## How to read this\n\n")
	p("- **Observed by** names the origin of a result. *testimony* is the system's own account: " +
		"a span, a return value, a log line. *witness* is an independent observer, which is evidence; " +
		"*other* is neither. A claim resting on testimony alone is not independently confirmed.\n")
	p("- **Inconclusive is a failure.** It is never counted as passed and never omitted.\n")
	p("- A run whose capture is not stated to be complete cannot prove an absence: those passes are " +
		"reported as inconclusive here.\n")
	p("- This page states what was checked and what was found. It is not a claim about anything " +
		"outside the runs listed above.\n")
	return b.String()
}

func listResults(b *strings.Builder, refs []ResultRef, max int) {
	shown := refs
	if max > 0 && len(shown) > max {
		shown = shown[:max]
	}
	for _, ref := range shown {
		detail := strings.TrimSpace(ref.Detail)
		if detail == "" {
			detail = "no detail recorded"
		}
		fmt.Fprintf(b, "- `%s` (%s): %s\n", ref.RunID, ref.Source, detail)
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

func result(t Totals) string {
	total := t.Passed + t.Failed + t.Inconclusive
	if t.Failed == 0 && t.Inconclusive == 0 {
		return fmt.Sprintf("All %s passed.", plural(total, "assertion result"))
	}
	return fmt.Sprintf("%s of %s assertion results were not proven: %s failed, %s inconclusive.",
		comma(t.Failed+t.Inconclusive), comma(total), comma(t.Failed), comma(t.Inconclusive))
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
	}
	return fmt.Sprintf("%s %ss", comma(n), noun)
}
