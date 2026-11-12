// Reading a mutant run: reruns, test endings, and whether a red run is a kill.

package cross

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"path"
	"regexp"
	"slices"
	"strings"
)

// redOutput is what to show of a run that cost a kill: the tests that failed in it,
// its first failure, then its end. The end alone can hide them, as go test -json gives
// a test's end when it ends, so in a long suite the last lines are the slowest tests'
// passes. The report's failing line is no help: it names the mutant's first run.
func redOutput(run testRun) string {
	out := tail(testText(run.raw), 20)
	if len(failEvents(run.raw)) == 0 {
		return out
	}
	_, msg, _ := firstFailure(run.raw, run.key)
	if msg = oneLine(msg); len(msg) > maxShownFailure {
		msg = msg[:maxShownFailure] + "..."
	}
	return fmt.Sprintf("failed in this run: %s\nfirst failure: %s\n%s", strings.Join(failingTests(run.raw), ", "), msg, out)
}

// maxShownFailure bounds redOutput's first failure, which can be a whole struct.
const maxShownFailure = 500

// rerunArgs is the command of rerun n without the mutant, from the mutant run's: whole
// the first time and the failed packages after, each without -test.failfast. A
// TestMain that calls m.Run again gets a run of nothing under that flag, exit 0 after
// a real failure, so with it a suite that is red by itself reads green here. A rerun
// that passes runs the same tests either way, so the flag saves nothing.
func rerunArgs(args, failed []string, n int) []string {
	whole := args[:max(0, len(args)-2)]
	if n == 0 || len(failed) == 0 {
		return whole
	}
	return slices.Concat(whole[:len(whole)-1], failed)
}

// lastTries is what runs when a repeat stops short, in order: the first run's own
// command, then for each package with a test of first, that command in that package
// alone, then that package's failed tests alone. Every package runs in the first
// two, so a hang there hangs them both, and a test name reaches any package that has
// it, as does a TestMain. Going a package at a time leaves all of that out, and no
// package's hang can cost another's kill. The command goes before the tests, as a
// test can need what ran before it in its package. With one package, the command
// in it is the command.
func lastTries(args []string, raw string, first map[testID]bool) [][]string {
	whole := args[:len(args)-2]
	byPackage := map[string]map[testID]bool{}
	for k := range first {
		if byPackage[k.pkg] == nil {
			byPackage[k.pkg] = map[testID]bool{}
		}
		byPackage[k.pkg][k] = true
	}
	tries := [][]string{args}
	several := len(packagesIn(raw)) > 1
	for _, pkg := range slices.Sorted(maps.Keys(byPackage)) {
		if several {
			tries = append(tries, slices.Concat(args[:len(args)-3], []string{pkg}, args[len(args)-2:]))
		}
		only := onlyTests(whole, byPackage[pkg])
		tries = append(tries, slices.Concat(only[:len(only)-1], []string{pkg}))
	}
	return tries
}

// noTestsLine is what package testing prints when an m.Run ran nothing at all.
const noTestsLine = "testing: warning: no tests to run\n"

// testsSeen is what a run's events say of each package that passed.
type testsSeen struct {
	passed bool // it has a pass event of its own: one with no test files has a skip, but under -cover a pass
	tests  bool // a Test or a Fuzz ran
	shown  bool // m.Run's output reached go test: an Example or a Benchmark ran, or noTestsLine or a coverage line
}

// coverageRE matches the line a package gives under -cover: package testing's, or go
// test's for a package with no test files, which passes there and has no skip.
var coverageRE = regexp.MustCompile(`^(\t\S+\t\t)?coverage: (\[no statements\]|[0-9.]+% of statements)`)

// packageTests reads testsSeen from raw. An Example or a Benchmark is not a test
// here: package testing stops Tests and Fuzz seeds under -test.failfast and runs
// those anyway, so a second m.Run after a real failure can show them and nothing else.
func packageTests(raw string) map[string]testsSeen {
	seen := map[string]testsSeen{}
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test, Output string }
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		s := seen[e.Package]
		switch {
		case e.Action == "run" && (exampleRE.MatchString(e.Test) || strings.HasPrefix(e.Test, "Benchmark")):
			s.shown = true
		case e.Action == "run":
			s.tests = true
		case e.Action == "output" && e.Test == "" && (e.Output == noTestsLine || coverageRE.MatchString(e.Output)):
			s.shown = true
		case e.Action == "pass" && e.Test == "":
			s.passed = true
		}
		seen[e.Package] = s
	}
	return seen
}

// noTestPackages is the packages a green baseline shows to have no test: they
// passed, no Test or Fuzz ran, and m.Run's output reached go test, so that is not
// because it went elsewhere. The baseline has no -test.failfast, so a second m.Run
// runs what a first one did. A package whose m.Run says nothing is not among them,
// and neither is one whose TestMain never calls it, so every survivor of the target
// pays for a run it may not need. That is the side to lose on.
//
//subpoena:enforcement_point
func noTestPackages(raw string) map[string]bool {
	none := map[string]bool{}
	for pkg, s := range packageTests(raw) {
		if s.passed && !s.tests && s.shown { //subpoena:enforcement_guard false
			none[pkg] = true
		}
	}
	return none
}

// quietPackages lists the packages of a green run that have tests and ran none,
// sorted. That is all a kill looks like when a first m.Run's output went nowhere and
// -test.failfast stopped the second. Any other package ran its tests where go test
// could see them, so its green is what it says. A package with no test files has a
// skip and no pass, or under -cover a pass and a coverage line, and noTests is the
// baseline's packages with no test: their events are the same as this signature's.
// This reads the whole run, so any package here that shows no test on a green
// baseline, a TestMain gate that exits without m.Run included, costs every survivor
// of the target one more run and a flake one more first try. A TestMain that prints a
// run line, framed or ahead of a quiet first m.Run plain, can hide the signature, as
// it can print a test's whole run: see docs/architecture.md.
//
//subpoena:enforcement_point
func quietPackages(raw string, noTests map[string]bool) []string {
	var quiet []string
	for pkg, s := range packageTests(raw) {
		if s.tests || !s.passed {
			continue
		}
		if noTests[pkg] {
			continue //subpoena:enforcement
		}
		quiet = append(quiet, pkg)
	}
	slices.Sort(quiet)
	return quiet
}

// passAfterFail reports whether a package with a failed test also said PASS.
func passAfterFail(raw string) bool {
	ends := endings(raw)
	for _, pkg := range failedPackages(raw) {
		if ends[eventKey{pkg, ""}].saidPass {
			return true
		}
	}
	return false
}

// packagesIn lists the packages with an event in raw.
func packagesIn(raw string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Package string }
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &e) == nil && e.Package != "" {
			seen[e.Package] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// onlyTests is a whole command, its packages last, narrowed to tests. The last
// -run is the one go reads, so this one replaces a selection's, of which tests is
// a part. A test name in another package runs there too, so lastTries gives it one
// package at a time.
func onlyTests(whole []string, tests map[testID]bool) []string {
	names := map[string]bool{}
	for k := range tests {
		names[regexp.QuoteMeta(k.test)] = true
	}
	if len(names) == 0 {
		return whole
	}
	filter := "^(" + strings.Join(slices.Sorted(maps.Keys(names)), "|") + ")$"
	last := len(whole) - 1
	return slices.Concat(whole[:last], []string{"-run", filter}, whole[last:])
}

// separateProgramHint is the likely reason no failed test's binary links the
// mutated code.
const separateProgramHint = "a suite that runs the code as a separate program links none of it, so cross cannot count its kills"

// noFinish is notAKill's reason for a run that hung.
const noFinish = "the run with the mutant did not finish the second time"

// notAKill says why a repeat with the mutant is not the kill the first run was,
// or "" if it is: red on a clean failure, in a test that failed the first time.
func notAKill(raw string, err error, key string, first map[testID]bool) string {
	if err == nil {
		return "the suite passed when run again with the mutant"
	}
	out := testText(raw)
	if timedOut(out, err) {
		return noFinish
	}
	if buildFailed(out) {
		return "the run with the mutant did not build the second time"
	}
	if _, _, crashed := firstFailure(raw, key); crashed {
		return "the run with the mutant crashed the second time"
	}
	for k := range failedTests(raw, key) {
		if first[k] {
			return ""
		}
	}
	return "a different test failed when run again with the mutant"
}

// finishedFailure reports whether a package of a run that timed out failed cleanly
// and ended: a failure read from a binary that exited 1 by itself. Every package
// runs, so one that hangs on the mutant says nothing of another that caught it, and
// that kill goes to the repeat like any other. A failed test in a package still
// running is no such thing, as its binary can yet die. The exit events are cross's
// own, so printed text cannot stand in for one, and failures reads no other package.
func finishedFailure(raw string) bool { return len(failures(raw)) > 0 }

// exitedOne is the packages whose binary exited 1. go test gives a package a fail
// event only if it failed, and exit events follow those, so a package with a fail
// event for a test and none of these went green, whatever its output said.
func exitedOne(raw string) map[string]bool {
	exited := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Output string }
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &e) == nil && e.Action == exitAction && e.Output == "1" {
			exited[e.Package] = true
		}
	}
	return exited
}

// stoppedShort reports whether a red run hung, gave no clean failure, or lost a
// package to a crash while another failed cleanly, so its tests did not all get
// to say.
func stoppedShort(raw string, err error, key string) bool {
	if err == nil {
		return false
	}
	out := testText(raw)
	if buildFailed(out) {
		return false
	}
	_, _, crashed := firstFailure(raw, key)
	_, dead := readFailures(raw)
	return crashed || len(dead) > 0 || timedOut(out, err)
}

// testID names a test across a run: its package and its top-level name. A
// subtest counts as its test, as a Python test's parameters do.
type testID struct{ pkg, test string }

func idOf(pkg, test string) testID {
	name, _, _ := strings.Cut(test, "/")
	return testID{pkg, name}
}

// failedTests is the tests go test reported failed, from its fail events: printed
// text can name a test that did not fail. A package that gave no clean failure
// has none here, since the test a crash ended is not a test that noticed.
//
// go test makes a fail or pass event of any "--- FAIL:" or "--- PASS:" line that
// carries the byte the test binary frames its own lines with, and a test can print
// that byte, so neither event alone is proof. A fail event counts only for a test
// that ran, and a pass ends a test: a test with both reads as not failed, in either
// order, as the two can't be told apart by what is printed where. A printed pass can
// so cost a real plain kill, which reads unconfirmed, and the run stays red. That is
// the side to lose on: the other way a fail printed after a real pass, by TestMain
// say, is a kill no test made. Only a witness failure outlives a pass, as its mark
// is what printed text does not have, and not once another test has started between
// the pass and the fail: a framed line can move a real message to a test that passed,
// and that test noticed nothing. A test that prints the run line and the fail
// line of a test that never ran has events go test cannot tell from the real thing,
// and a binary that said PASS is what gives those away: m.Run says it only when every
// test passed, so a binary that said it and exited 1 did so in TestMain, and failed
// no test. Under -test.failfast a second m.Run says it after a real failure, which is
// why confirmKill asks a run without it. Printing PASS can cost a kill. Hiding it, by
// swapping os.Stdout around m.Run, can make one, and no output shows that: only
// RequireWitness stops it. So can such a pair of lines beside a real failure in its
// package. See docs/architecture.md.
//
//subpoena:enforcement_point
func failedTests(raw, key string) map[testID]bool {
	clean, marked := map[string]bool{}, map[eventKey]bool{}
	for _, f := range failures(raw) {
		clean[f.pkg] = true
		if harnessWitness(f.head, key) {
			marked[eventKey{f.pkg, f.test}] = true
		}
	}
	tests := map[testID]bool{}
	ends := endings(raw)
	for k, e := range ends {
		if k[1] == "" || !e.failed || !clean[k[0]] {
			continue
		}
		if !e.ran {
			continue //subpoena:enforcement
		}
		if (e.passed || e.skipped) && (!marked[k] || e.lateFail) {
			continue //subpoena:enforcement
		}
		if ends[eventKey{k[0], ""}].saidPass && !marked[k] {
			continue //subpoena:enforcement
		}
		tests[idOf(k[0], k[1])] = true
	}
	return tests
}

// eventKey is a test by its exact name in its package, subtests apart.
type eventKey [2]string

// ending is what a test's events say happened to it. Any of it can be printed text.
// lateFail is a fail event after a pass with another test started in between, a
// subtest of its own aside.
// start, paused, from and to are where it first ran, first paused, first continued
// after a pause and last ended, as positions in the run, 0 if it did not: from is
// what makes it parallel.
type ending struct {
	ran, passed, skipped, failed, lateFail, saidPass bool
	start, paused, from, to                          int
}

// cleanPass reports whether the test passed and nothing says otherwise. A pass with
// a fail beside it can be printed, ahead of the real fail or after it, so that is not
// a test to take at its word: a line in it can be what it seems.
func (e ending) cleanPass() bool { return e.passed && !e.failed }

// last is where the test ended. A test with no end was still running.
func (e ending) last() int {
	if e.to == 0 {
		return math.MaxInt
	}
	return e.to
}

// began is where the test began to run beside others: where it first continued if it
// paused, as a paused test is doing nothing, and where it started if not. 0 if it did
// neither.
func (e ending) began() int {
	if e.from > 0 || e.paused > 0 {
		return e.from
	}
	return e.start
}

// beside reports whether the two tests were running at once. Sequential tests do not
// overlap: one ends before the next starts, and a parallel test continues only after
// the sequential tests around it, unless a second m.Run repeats their names, as a name
// has one start and one end. Subtests started from goroutines do, with no pause or
// cont, and one that pauses after it worked counts from its cont. A parallel subtest ends a little after the next one continues, so this can say
// yes to subtests that took turns under -parallel 1, which costs a kill and makes none.
func (e ending) beside(o ending) bool {
	a, b := e.began(), o.began()
	return a > 0 && b > 0 && a < o.last() && b < e.last()
}

// holds reports whether c, a test whose name goes on from e's, is e's subtest. A
// subtest starts while its parent runs and ends before it, and a failed one fails its
// parent. A name alone does not say: go keeps a slash in a subtest's name, so
// "read/all" can be the sibling of "read", and a sibling of a parallel test starts
// while that test is paused.
//
//subpoena:enforcement_point
func (e ending) holds(c ending) bool {
	if !e.ran || c.start < e.start || c.last() > e.last() || c.failed && !e.failed {
		return false //subpoena:enforcement
	}
	if e.paused != 0 && c.start >= e.paused && (e.from == 0 || c.start <= e.from) {
		return false //subpoena:enforcement
	}
	return true
}

// besideFailure reports whether a test that did not pass ran beside k. Package
// testing's own frames carry a line printed with no frame to whichever test printed
// last, so a parallel test's panic line can land on a test that passed, and no reading
// of that line tells it from a log line. Where the two tests part, the two branches
// must have run at once: subtests in turn inside one parallel test did not, and a test
// does not run beside its own subtests.
//
//subpoena:enforcement_point
func besideFailure(ends map[eventKey]ending, k eventKey) bool {
	for o, e := range ends {
		if o[0] != k[0] || o[1] == "" || !e.failed {
			continue
		}
		a, b, ok := branches(ends, k[0], k[1], o[1])
		if ok && ends[eventKey{k[0], a}].beside(ends[eventKey{k[0], b}]) {
			return true //subpoena:enforcement
		}
	}
	return false
}

// branches gives the tests of pkg that hold a and b where the two part. ok is false
// for a test and its own subtest, which do not part.
func branches(ends map[eventKey]ending, pkg, a, b string) (string, string, bool) {
	x, y := lineage(ends, pkg, a), lineage(ends, pkg, b)
	for i := range min(len(x), len(y)) {
		if x[i] != y[i] {
			return x[i], y[i], true
		}
	}
	return "", "", false
}

// lineage is the tests that hold a test, top-level first, then the test. It is read
// from the tests that ran and not cut from the name on "/", which go keeps in a
// subtest's name: "T/GET_/admin" is a subtest of T, and no test "T/GET_" exists.
func lineage(ends map[eventKey]ending, pkg, test string) []string {
	var line []string
	for i, c := range test {
		if c == '/' && ends[eventKey{pkg, test[:i]}].holds(ends[eventKey{pkg, test}]) {
			line = append(line, test[:i])
		}
	}
	return append(line, test)
}

// crashStands reports whether a crash line on k is a crash: on a test that passed
// with nothing beside it to have put it there, it is a log line.
func crashStands(ends map[eventKey]ending, k eventKey) bool {
	return !ends[k].cleanPass() || besideFailure(ends, k)
}

// endings reads the events of each test in raw, and of each package under an empty
// test name. It is the one reading of how a test
// ended, for failedTests, the crash rule and what a crash shows.
//
//subpoena:enforcement_point
func endings(raw string) map[eventKey]ending {
	all, ended := map[eventKey]ending{}, map[eventKey]bool{}
	for i, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test, Output string }
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		k := eventKey{e.Package, e.Test}
		end := all[k]
		switch e.Action {
		case "output":
			end.saidPass = end.saidPass || e.Output == "PASS\n"
		case "run":
			end.ran = true
			if end.start == 0 {
				end.start = i + 1
			}
			for p := range ended {
				if p[0] == e.Package && !strings.HasPrefix(e.Test, p[1]+"/") {
					delete(ended, p) //subpoena:enforcement
				}
			}
		case "pause":
			if end.paused == 0 {
				end.paused = i + 1
			}
		case "cont":
			if end.from == 0 {
				end.from = i + 1
			}
		case "pass":
			end.passed, ended[k], end.to = true, true, i+1
		case "skip":
			end.skipped, ended[k], end.to = true, true, i+1
		case "fail":
			end.failed, end.to = true, i+1
			end.lateFail = end.lateFail || (end.passed || end.skipped) && !ended[k]
		}
		all[k] = end
	}
	return all
}

// repeatEvidence is the kind and message of a repeat's evidence from the tests of
// first: witness if any of them gave it, wherever it ran, read as each test's own
// first failure. go test -json gives packages in finish order, so that order decides
// nothing here, and a test that was not in first was never what the first run's
// evidence came from. With no witness it is the first of them by package.
//
//subpoena:enforcement_point
func repeatEvidence(raw, key string, first map[testID]bool) (Evidence, string) {
	failedNow := failedTests(raw, key)
	seen := map[testID]bool{}
	ev, msg := EvidenceOther, emptyFailure
	found := false
	for _, f := range inPackageOrder(settled(failures(raw), key)) {
		id := idOf(f.pkg, f.test)
		if !first[id] || !failedNow[id] {
			continue //subpoena:enforcement
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		e, m := judge(f, key)
		if e == EvidenceWitness {
			return e, m
		}
		if !found {
			ev, msg, found = e, m, true
		}
	}
	return ev, msg
}

// inPackageOrder sorts failures by package and keeps each package's own order. A
// package's output is in the order it happened; go test -json gives packages in
// the order they finished, which is timing.
func inPackageOrder(fs []failure) []failure {
	fs = slices.Clone(fs)
	slices.SortStableFunc(fs, func(a, b failure) int { return strings.Compare(a.pkg, b.pkg) })
	return fs
}

// failEvent is a test's fail event.
type failEvent struct{ Action, Package, Test string }

// failEvents lists the fail events of tests in raw, in order.
func failEvents(raw string) []failEvent {
	var evs []failEvent
	for _, line := range strings.Split(raw, "\n") {
		var e failEvent
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &e) == nil && e.Action == "fail" && e.Test != "" {
			evs = append(evs, e)
		}
	}
	return evs
}

// failedPackages lists the packages in raw with a failed test whose binary exited
// 1. A printed fail in a green package is no failure, and must not stand as the
// failed package that links the mutant for a red one that does not.
//
//subpoena:enforcement_point
func failedPackages(raw string) []string {
	exited := exitedOne(raw)
	var failed []string
	for _, e := range failEvents(raw) {
		if !exited[e.Package] {
			continue //subpoena:enforcement
		}
		if !slices.Contains(failed, e.Package) {
			failed = append(failed, e.Package)
		}
	}
	return failed
}

// linksMutant says why no failed package's test binary links a mutated package,
// or "" if one does. Go list's -test form names the test binary's whole
// dependency set. A suite that runs the code as a separate program links none of
// it, so its kills read as unconfirmed: that costs a kill, and a false one costs
// more. A failure with no test named, or a list that fails, decides nothing here.
func linksMutant(ctx context.Context, o Options, sb sandbox, failed []string, ms []Mutant) (string, error) {
	if len(failed) == 0 {
		return "", nil
	}
	pkgs := map[string]bool{}
	for _, m := range ms {
		out, err := goIn(ctx, o.Timeout, sb, "list", "-f", "{{.ImportPath}}", "./"+path.Dir(m.File))
		if ctx.Err() != nil {
			return "", fmt.Errorf("cross: run stopped: %w", ctx.Err())
		}
		if err != nil {
			return "", nil
		}
		pkgs[strings.TrimSpace(out)] = true
	}
	out, err := goIn(ctx, o.Timeout, sb, append([]string{"list", "-deps", "-test", "-f", "{{.ImportPath}}"}, failed...)...)
	if ctx.Err() != nil {
		return "", fmt.Errorf("cross: run stopped: %w", ctx.Err())
	}
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(out, "\n") {
		name, _, _ := strings.Cut(strings.TrimSpace(line), " ") // "p [p.test]" is p
		if pkgs[name] {
			return "", nil
		}
	}
	return fmt.Sprintf("the failed tests' binaries do not link the mutated code: %s", strings.Join(failed, ", ")), nil
}
