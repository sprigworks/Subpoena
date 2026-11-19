// Command subpoena-report turns the results of many assertion runs into one
// readable page and one machine-readable data file. See docs/evidence-reports.md.
//
//	subpoena-report [-from subpoena|run-results] [-claims file.json] \
//	                [-md out.md] [-json out.json] [-fail-on any|fail|inconclusive|none] <path>...
//
// A path is a Subpoena results document, a run-results file, a glob, or a
// directory to walk. With neither -md nor -json the page goes to standard
// output.
//
// Exit status: 0 nothing failed under -fail-on, 1 a result failed or was
// inconclusive or an input could not be read, 2 usage or load error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sprigworks/subpoena/pkg/report"
)

func main() { os.Exit(run(os.Args[1:])) }

//subpoena:enforcement_point
func run(args []string) int {
	fs := flag.NewFlagSet("subpoena-report", flag.ContinueOnError)
	from := fs.String("from", report.FormatSubpoena, "input format: subpoena or run-results")
	claimsPath := fs.String("claims", "", "JSON object mapping an assertion id to a sentence, for input with no claim")
	mdPath := fs.String("md", "", "write the readable page here (default: standard output)")
	jsonPath := fs.String("json", "", "write the machine-readable data file here")
	failOn := fs.String("fail-on", "any", "exit 1 on any|fail|inconclusive|none")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subpoena-report [-from subpoena|run-results] [-claims file.json] [-md out.md] [-json out.json] [-fail-on any|fail|inconclusive|none] <path>...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	switch *failOn {
	case "any", "fail", "inconclusive", "none":
	default:
		fmt.Fprintf(os.Stderr, "subpoena-report: -fail-on %q: want any, fail, inconclusive or none\n", *failOn)
		return 2
	}

	var claims map[string]string
	if *claimsPath != "" {
		c, err := report.LoadClaims(*claimsPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "subpoena-report:", err)
			return 2
		}
		claims = c
	}

	doc, notes, err := report.Load(*from, fs.Args(), claims)
	if err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-report:", err)
		return 2
	}
	rep := report.Build(doc)
	rep.AddLoadNotes(notes) //subpoena:enforcement

	page := report.Markdown(rep)
	if *mdPath == "" && *jsonPath == "" {
		fmt.Print(page)
	}
	if *mdPath != "" {
		if err := os.WriteFile(*mdPath, []byte(page), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "subpoena-report:", err)
			return 2
		}
	}
	if *jsonPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "subpoena-report:", err)
			return 2
		}
		if err := os.WriteFile(*jsonPath, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "subpoena-report:", err)
			return 2
		}
	}

	fmt.Fprintf(os.Stderr, "subpoena-report: %d runs, %d results: %d passed, %d failed, %d inconclusive",
		rep.Inputs.Runs, rep.Inputs.Assertions, rep.Totals.Passed, rep.Totals.Failed, rep.Totals.Inconclusive)
	if n := len(notes.Unreadable); n > 0 {
		fmt.Fprintf(os.Stderr, ", %d input file(s) unreadable", n)
	}
	if n := len(notes.Skipped); n > 0 {
		fmt.Fprintf(os.Stderr, " (%d file(s) not in this format)", n)
	}
	fmt.Fprintln(os.Stderr)
	for _, u := range notes.Unreadable {
		fmt.Fprintf(os.Stderr, "subpoena-report: unreadable: %s: %s\n", u.Path, u.Reason)
	}
	if *mdPath != "" || *jsonPath != "" {
		fmt.Fprintf(os.Stderr, "subpoena-report: wrote %s\n", written(*mdPath, *jsonPath))
	}

	if exitFor(*failOn, rep.Totals) {
		return 1
	}
	return 0
}

func written(md, js string) string {
	switch {
	case md != "" && js != "":
		return md + " and " + js
	case md != "":
		return md
	default:
		return js
	}
}

// exitFor reports whether the run should exit 1. An unreadable input is a
// failure under every setting that looks at failures at all: a result nobody
// could read is neither a pass nor something -fail-on can select away.
//
//subpoena:enforcement_point
func exitFor(failOn string, t report.Totals) bool {
	if failOn == "none" {
		return false
	}
	if t.Unreadable > 0 { //subpoena:enforcement_guard false
		return true
	}
	if t.Inconclusive > 0 && failOn != "fail" { //subpoena:enforcement_guard false
		return true
	}
	if t.Failed > 0 && failOn != "inconclusive" { //subpoena:enforcement_guard false
		return true
	}
	return false
}
