// Reading failures out of go test output, and keeping the evidence.

package cross

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// testText turns go test -json output back into the plain text go test
// prints. Lines that are not JSON events (the go command's own messages) are
// kept as they are.
func testText(raw string) string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		var ev struct{ Action, Output string }
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &ev) == nil {
			if ev.Action != exitAction {
				b.WriteString(ev.Output)
			}
			continue
		}
		if line != "" {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// failMsgRE matches a test's failure message, "    file_test.go:12: msg".
var failMsgRE = regexp.MustCompile(`^\s+[^\s:]+\.go:\d+: (.*)$`)

// openFailMsgRE matches that message after text a test printed with no newline:
// go test gives the two as one line, "partial    file_test.go:12: msg". Only a
// test with a fail event is read, and a line that can be a message's own further
// text is indented, so this is the line's start, and the indent is go test's. The
// open text and the message reach cross as one event, so nothing tells this from a
// printed "INFO    server.go:42: msg", and such a line counts only as settled says.
var openFailMsgRE = regexp.MustCompile(`^\S(?:.*?\S)? {4,}[^\s:]+\.go:\d+: (.*)$`)

// maxFailureText bounds the text read from under a blank head line.
const maxFailureText = 300

// emptyFailure stands in for a failure that printed no text at all.
const emptyFailure = "(the failure printed no text; -evidence-dir keeps the test's output)"

// failure is one failure message of a failed test.
type failure struct {
	pkg  string
	test string
	head string // text on the file:line, the only place a tag is read
	text string // what to print: head, or for a blank head the lines under it
	more bool   // lines still extend text
	open bool   // read after text on its line: the whole line can be printed text
}

// addLine reads one line of a failed test's output after a blank head: the
// text of a multi-line t.Errorf, or testify's Error field. testify puts the
// whole report under the head, as "\tLabel:\tvalue" lines with a value's
// further lines under an empty label. A line with less indent is not part of
// the message: it is output from the code under test.
func (f *failure) addLine(line string) {
	if !strings.HasPrefix(line, "        ") {
		return
	}
	body := strings.TrimSpace(line)
	if label, value, ok := strings.Cut(body, "\t"); ok && strings.HasSuffix(strings.TrimSpace(label), ":") {
		f.more = strings.TrimSpace(label) == "Error:"
		if f.more {
			f.text = strings.TrimSpace(value)
		}
		return
	}
	if f.more {
		f.text = strings.TrimSpace(f.text + " " + body)
		f.more = len(f.text) < maxFailureText
	}
}

// firstFailure reads go test -json output for the first failure message of
// a test that failed (a skipped or passing test's log lines don't count).
// crashed is true when no failed test gave one cleanly: the binary died by a
// panic, a runtime fatal error or os.Exit, or failed without a message. A
// package whose binary died gives no kills at all, since a test's log lines
// before its panic look just like failure messages, and so does an assertion
// library's report: go test -json carries both as plain text, which the code
// under test can print. t.Log and t.Error print the same way, so a failed test's log line counts as its first
// failure: tagged, it can set ev; untagged, it hides a witness failure after it.
// That is within a package, whose output is in order. Packages run apart and finish
// in any order, so one's plain failure hides nothing of another's: ev is witness if
// any package's first failure is, and otherwise the first failure by package.
func firstFailure(raw, key string) (ev Evidence, msg string, crashed bool) {
	fs := inPackageOrder(settled(failures(raw), key))
	if len(fs) == 0 {
		return "", "", true
	}
	ev, msg = judge(fs[0], key)
	for i, f := range fs {
		if i == 0 || f.pkg == fs[i-1].pkg {
			continue
		}
		if e, m := judge(f, key); e == EvidenceWitness && ev != EvidenceWitness {
			ev, msg = e, m
		}
	}
	return ev, msg, false
}

// settled is fs without the open lines that say nothing. An open line can be a log
// line the code under test printed, and read as a failure it would stand ahead of
// the test's real one and push a witness kill down to self-report. It is needed
// only where a test has no other message, as a failure after open text then has
// none, so a test with a clean line goes by that, subtests included. The harness's
// own failure after open text stays: its mark proves it, and printing text ahead of
// it must not lose it. What this gives up: a plain failure after open text no longer
// stands ahead of a witness failure in its test, which did happen. See
// docs/architecture.md.
//
//subpoena:enforcement_point
func settled(fs []failure, key string) []failure {
	clean := map[testID]bool{}
	for _, f := range fs {
		if !f.open {
			clean[idOf(f.pkg, f.test)] = true
		}
	}
	var out []failure
	for _, f := range fs {
		if f.open && clean[idOf(f.pkg, f.test)] && !harnessWitness(f.head, key) {
			continue //subpoena:enforcement
		}
		out = append(out, f)
	}
	return out
}

// judge is the kind of evidence a failure is, and its message.
func judge(f failure, key string) (Evidence, string) {
	msg := crossmark.Strip(f.text)
	if msg == "" {
		msg = emptyFailure
	}
	switch {
	case harnessWitness(f.head, key):
		return EvidenceWitness, msg
	case strings.HasPrefix(f.head, "testimony:"):
		return EvidenceTestimony, msg
	default:
		return EvidenceOther, msg
	}
}

// harnessWitness reports whether head is a witness failure the harness wrote: a
// tag and the mark of the key of the run head came from. A line the code under test printed has the
// shape of a t.Log and can hold the tag, so the tag alone is no evidence.
//
//subpoena:enforcement_point
func harnessWitness(head, key string) bool {
	if !crossmark.Verify(key, head) {
		return false //subpoena:enforcement
	}
	return strings.HasPrefix(head, "witness:")
}

// witnessFailure returns the first witness failure of a failed test, or "" if
// there is none.
func witnessFailure(raw, key string) string {
	for _, f := range failures(raw) {
		if harnessWitness(f.head, key) {
			return crossmark.Strip(f.head)
		}
	}
	return ""
}

// failures lists, in order, the failure messages of failed tests.
func failures(raw string) []failure {
	fs, _ := readFailures(raw)
	return fs
}

// readFailures is failures, and the packages that died. A package gives none if
// it has no exit event of 1: a test binary that exited 0 failed nothing, whatever
// fail events its output made, and the exit code is the part printed text cannot
// reach. A package also gives none, whatever came first, if its test binary exited
// with anything but 1, or a crash line sits in the output of a test that did not pass: Ginkgo runs
// a suite as one test, in random order, so order must not decide. The exit code
// sees a real panic wherever its text fell, even beside an open line. The text
// is for a panic that something recovered, as Ginkgo does, and only a test that
// did not pass can hold one: a binary that died ended no test with a pass, and
// in one that lived, a passing test's line is a log line.
//
//subpoena:enforcement_point
func readFailures(raw string) ([]failure, map[string]bool) {
	type event struct {
		Action, Package, Test, Output string
	}
	type key = eventKey
	var evs []event
	crash, dead := map[key]bool{}, map[string]bool{}
	open := map[key]int{} // test -> index in evs of its line still being read
	for _, line := range strings.Split(raw, "\n") {
		var e event
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		e.Output = ansiRE.ReplaceAllString(e.Output, "")
		k := key{e.Package, e.Test}
		// go test -json cuts a long line into several events, and a mark sits at
		// the end of its line: a line is read whole. Crash lines below are still
		// read per event, so text an open line ran into cannot hide one.
		if n, ok := open[k]; ok && e.Action == "output" {
			evs[n].Output += e.Output
			if strings.HasSuffix(e.Output, "\n") {
				delete(open, k)
			}
		} else {
			evs = append(evs, e)
			if e.Action == "output" && !strings.HasSuffix(e.Output, "\n") {
				open[k] = len(evs) - 1
			}
		}
		switch e.Action {
		case "output":
			if crashLine(e.Output) {
				crash[k] = true
			}
		case exitAction:
			if e.Output != "1" {
				dead[e.Package] = true //subpoena:enforcement
			}
		}
	}
	ends := endings(raw)
	for k := range crash {
		if crashStands(ends, k) {
			dead[k[0]] = true //subpoena:enforcement
		}
	}
	var fs []failure
	blank := map[key]int{}   // test -> index in fs of the blank head being read
	suite := map[key]bool{}  // test -> Ginkgo's "Running Suite:" banner seen
	ginkgo := map[key]bool{} // test -> a Ginkgo spec's failure report has opened
	report := map[key]int{}  // test -> index in fs of that report's failure
	gomega := map[key]int{}  // test -> index in fs of the Ginkgo message being read
	example := map[key]int{} // test -> index in fs of the Example report being read
	for _, e := range evs {
		k := key{e.Package, e.Test}
		// A package's own key fails too, but its output came from no test: a
		// line there is what TestMain, init or the code they ran printed.
		if e.Test == "" {
			continue //subpoena:enforcement
		}
		if e.Action != "output" || !ends[k].failed {
			continue
		}
		line := strings.TrimRight(e.Output, "\n")
		if n, ok := example[k]; ok {
			if len(fs[n].text) < maxFailureText {
				fs[n].text = strings.TrimSpace(fs[n].text + " " + strings.TrimSpace(line))
			}
			continue
		}
		if line == exampleReport && exampleRE.MatchString(e.Test) {
			example[k] = len(fs)
			fs = append(fs, failure{pkg: e.Package, test: e.Test, text: line})
			continue
		}
		if ginkgoSuiteRE.MatchString(line) {
			suite[k] = true
		} else if suite[k] && ginkgoReportRE.MatchString(line) {
			ginkgo[k] = true
			delete(report, k)
		} else if m := ginkgoFailedRE.FindStringSubmatch(line); m != nil && ginkgo[k] && !strings.HasPrefix(m[1], "in [") {
			delete(blank, k)
			if n, ok := report[k]; ok {
				// The timeline above the message prints the spec's own log
				// lines as they came, so one line of a report can hold what
				// another does. The last is the message, and no tag stands.
				fs[n].head, fs[n].text = "", m[1]
			} else {
				report[k] = len(fs)
				fs = append(fs, failure{pkg: e.Package, test: e.Test, head: m[1], text: m[1]})
			}
			gomega[k] = report[k]
		} else if n, ok := gomega[k]; ok {
			if ginkgoAtRE.MatchString(line) || len(fs[n].text) >= maxFailureText {
				delete(gomega, k)
			} else {
				fs[n].text = strings.TrimSpace(fs[n].text + " " + strings.TrimSpace(line))
			}
		} else if m, open := failLine(line); m != nil {
			delete(blank, k)
			if m[1] == "" {
				blank[k] = len(fs)
			}
			fs = append(fs, failure{pkg: e.Package, test: e.Test, head: m[1], text: m[1], more: true, open: open})
		} else if n, ok := blank[k]; ok {
			fs[n].addLine(line)
		}
	}
	exited := exitedOne(raw)
	var clean []failure
	for _, f := range fs {
		if dead[f.pkg] {
			continue //subpoena:enforcement
		}
		if !exited[f.pkg] {
			continue //subpoena:enforcement
		}
		clean = append(clean, f)
	}
	return clean, dead
}

// crashLine reports whether an output event, ANSI colour gone, opens a crash report.
func crashLine(output string) bool {
	return crashRE.MatchString(output) || ginkgoPanicRE.MatchString(output) || recoveredPanicRE.MatchString(output)
}

// crashEvents gives an exit event of exitCrashLine for each failed package with a
// crash line in its output, a test's or not, in a run that reached it. readFailures takes a passing test's line for a
// log line, but a framed "=== NAME" line can put a real crash line on any test, one
// that passed or one that will, and no reading of the output tells that from a log
// line. RequireWitness asks for what holds against printed text, so it reads the
// line as a crash wherever it sits. The cost: a passing test that prints such a line,
// as crashLine reads one, beside a witness failure in its package, reads crashed.
// Without RequireWitness the line stays a log line. See docs/architecture.md.
//
//subpoena:enforcement_point
func crashEvents(raw string) string {
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Output string }
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &e) == nil && e.Action == "output" {
			seen[e.Package] = seen[e.Package] || crashLine(ansiRE.ReplaceAllString(e.Output, ""))
		}
	}
	ends := endings(raw)
	var b strings.Builder
	for _, pkg := range slices.Sorted(maps.Keys(seen)) {
		if seen[pkg] && ends[eventKey{pkg, ""}].failed {
			b.WriteString(exitEvent(pkg, exitCrashLine) + "\n") //subpoena:enforcement
		}
	}
	return b.String()
}

// failLine is the match of a failure message on line, nil if it holds none, and
// whether it came after open text.
func failLine(line string) ([]string, bool) {
	if m := failMsgRE.FindStringSubmatch(line); m != nil {
		return m, false
	}
	return openFailMsgRE.FindStringSubmatch(line), true
}

// A failed Example has no file:line. Package testing compares its output and prints
// "got:", then that output, then what it wanted. An Example fails no other way but
// by a panic, which the exit code sees, so this is a clean failure. The head stays
// blank: all below "got:" is what the code printed, so no tag is read there.
const exampleReport = "got:"

var exampleRE = regexp.MustCompile(`^Example[^/]*$`)

// crashRE matches the first line of a panic or a runtime fatal error.
var crashRE = regexp.MustCompile(`^(panic|fatal error): `)

// recoveredPanicRE matches the failure testify's suite makes of a panic it recovered,
// through t.Errorf, so at go test's indent with a file and line, not at column 0. It
// has no anchor, so text printed with no newline cannot hide it. As with Ginkgo's
// [PANICKED], a crash is what it reports, and a failed test's own line saying the same
// costs a kill.
var recoveredPanicRE = regexp.MustCompile(`\S+\.go:\d+: test panicked: `)

// Ginkgo v2's failure report. It runs a whole suite as one test, which opens with
// "Running Suite:", and colours its report, even under go test: a report counts
// only under that banner. "• [FAILED] [0.001 seconds]" opens a spec's report
// and "[FAILED] msg" gives the message below it, down to "In [It] at:". A
// timeline above it can hold "[FAILED] in [It] - file:line", which names no
// failure of its own. It recovers a spec's panic, which it reports as
// "• [PANICKED]".
var (
	ansiRE         = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	ginkgoSuiteRE  = regexp.MustCompile(`^Running Suite: `)
	ginkgoReportRE = regexp.MustCompile(`^\s*• \[FAILED\] \[`)
	ginkgoFailedRE = regexp.MustCompile(`^\s*\[FAILED\] (.*)$`)
	ginkgoAtRE     = regexp.MustCompile(`^\s*In \[`)
	ginkgoPanicRE  = regexp.MustCompile(`^\s*• \[PANICKED\] \[`)
)

// exitAction is the action of an event cross adds to go test -json output,
// carrying a failed package's exit code. go test prints no "exit status" line
// for a test binary that printed anything, and its events hold no exit code, so
// cross runs each binary under -exec with a wrapper that records it (runner). The events
// are top-level lines: what a test prints is carried inside an Output, so the
// code under test cannot write one.
const exitAction = "subpoena-exit"

// exitUnknown is the code of a failed package whose binary left no record. The
// wrapper's other word for a code, 1-before-testing-ended, is an exit 1 from a
// binary that never finished testing: anything but "1" is a death.
const exitUnknown = "unknown"

// exitCrashLine is the code crashEvents gives a package, after its real one.
const exitCrashLine = "crash-line"

func exitEvent(pkg, code string) string {
	b, _ := json.Marshal(struct{ Action, Package, Output string }{exitAction, pkg, code})
	return string(b)
}

// baselineReason says why a baseline run failed. Timeouts come first and
// apart, since a timeout on a busy host is not a red test, and their output
// can be empty. raw is go test -json output, which also shows what was still
// running when go test was stopped.
func baselineReason(raw string, err error) string {
	text := failedOutput(raw)
	reason := err.Error()
	switch {
	case errors.Is(err, errTimeout):
		reason += "; raise -timeout. A timeout on a busy host is not a red test"
	case testTimeoutRE.MatchString(text):
		reason = "a test binary timed out at go test's own limit, which is not a red test"
	}
	if open := unfinished(raw); timedOut(text, err) && len(open) > 0 {
		reason += "\nstill running: " + strings.Join(open, ", ")
	}
	if text == "" {
		return reason + "\ngo test printed nothing"
	}
	if at := testTimeoutRE.FindStringIndex(text); at != nil {
		// Its first lines name the running tests; a goroutine dump follows.
		lines := strings.Split(text[at[0]:], "\n")
		return reason + "\n" + strings.Join(lines[:min(40, len(lines))], "\n")
	}
	return reason + "\n" + tail(text, 40)
}

// failedOutput is the output that can say why go test failed: go's own
// messages, build output, and what failed tests and packages printed. go test
// -json is verbose, and a passing test's log says nothing of why a run went red.
func failedOutput(raw string) string {
	type event struct{ Action, Package, Test, Output string }
	passed := map[[2]string]bool{}
	var evs []event
	var b strings.Builder
	for _, l := range strings.Split(raw, "\n") {
		var e event
		if !strings.HasPrefix(l, "{") || json.Unmarshal([]byte(l), &e) != nil {
			e = event{Action: "go", Output: l + "\n"}
			if l == "" {
				continue
			}
		}
		evs = append(evs, e)
		if e.Action == "pass" {
			passed[[2]string{e.Package, e.Test}] = true
		}
	}
	for _, e := range evs {
		if e.Action != "output" && e.Action != "build-output" && e.Action != "go" {
			continue
		}
		if !passed[[2]string{e.Package, e.Test}] && !passed[[2]string{e.Package, ""}] && !framingRE.MatchString(e.Output) {
			b.WriteString(e.Output)
		}
	}
	return strings.TrimRight(ansiRE.ReplaceAllString(b.String(), ""), "\n")
}

// framingRE matches the lines go test adds around a test's own output.
var framingRE = regexp.MustCompile(`^(=== (RUN|PAUSE|CONT|NAME)|\s*--- (PASS|SKIP)|PASS$|ok\s|\?\s)`)

// crashOutput says what to show for a crashed run: the output of the package
// that died, not the last lines of the run, which go test -json interleaves
// across packages. From a crash line if there is one (a panic's own lines are
// the useful ones), or else the package's last n lines, as after log.Fatal,
// which leaves no crash line. A panic in a test that passed is no crash.
func crashOutput(raw string, n int) string {
	type key = eventKey
	lines := map[string][]string{}
	crashAt := map[key]int{}
	var crashes []key
	failedPkg := ""
	for _, l := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test, Output string }
		if !strings.HasPrefix(l, "{") || json.Unmarshal([]byte(l), &e) != nil {
			continue
		}
		k := key{e.Package, e.Test}
		switch e.Action {
		case "fail":
			if e.Test == "" && failedPkg == "" {
				failedPkg = e.Package
			}
		case "output":
			text := strings.TrimRight(ansiRE.ReplaceAllString(e.Output, ""), "\n")
			if framingRE.MatchString(text) {
				continue
			}
			if _, seen := crashAt[k]; !seen && crashRE.MatchString(text) {
				crashAt[k] = len(lines[e.Package])
				crashes = append(crashes, k)
			}
			lines[e.Package] = append(lines[e.Package], text)
		}
	}
	ends := endings(raw)
	for _, k := range crashes {
		if crashStands(ends, k) {
			out := lines[k[0]][crashAt[k]:]
			return "package " + k[0] + ":\n" + strings.Join(out[:min(n, len(out))], "\n")
		}
	}
	if failedPkg == "" {
		return tail(testText(raw), n)
	}
	return "package " + failedPkg + ":\n" + tail(strings.Join(lines[failedPkg], "\n"), n)
}

// unfinished lists, from go test -json output, the packages and tests that
// started and never passed, failed or skipped.
func unfinished(raw string) []string {
	var order []string
	open := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test string }
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		name := strings.TrimSpace(e.Package + " " + e.Test)
		switch e.Action {
		case "start", "run":
			if !open[name] {
				open[name] = true
				order = append(order, name)
			}
		case "pass", "fail", "skip":
			delete(open, name)
		}
	}
	var out []string
	for _, name := range order {
		if open[name] {
			out = append(out, name)
		}
	}
	return out
}

// keepEvidence writes raw to Options.EvidenceDir, if set, and returns the path.
func keepEvidence(o Options, ms []Mutant, label, raw string) (string, error) {
	if o.EvidenceDir == "" {
		return "", nil
	}
	n := o.runs.Add(1)
	m := ms[0]
	name := fmt.Sprintf("%03d-%s-%s-%d", n, strings.NewReplacer("/", "_", ".", "_").Replace(m.File), m.Func, m.Line)
	if len(ms) > 1 {
		name += fmt.Sprintf("-with%d", len(ms)-1)
	}
	if err := os.MkdirAll(o.EvidenceDir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(o.EvidenceDir, name+label+".jsonl")
	return p, os.WriteFile(p, []byte(raw), 0o644)
}
