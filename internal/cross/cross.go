// Package cross implements cross-examination. For each enforcement point it builds
// a mutant with the enforcement statement removed and requires that the test
// suite goes red. A suite that stays green cannot tell enforced from
// unenforced behaviour, whatever its spans say.
//
// v0 locates the statement to remove with a second marker: a comment
// //subpoena:enforcement on the statement's first line, inside a function
// marked //subpoena:enforcement_point.
//
// A removed return the function cannot end without is replaced by a return of
// zero values when that only turns an error to nil: return nil, ErrDenied
// becomes a return of nil, nil. No other return has a stand-in, since zero can be
// the refusal itself: return p.Check(u) would become return false.
//
// A guard is marked on its if line with //subpoena:enforcement_guard true (or
// false): the mutant forces the condition to that bypass value. The value is
// a reviewed claim, like the markers: a wrong one forces enforcement on, which
// only an allowed-path test notices, and the refusal goes unexamined. Either marker
// may name a group (group=<name>) of layers that together make one guarantee;
// cross also mutates the whole group, and a layer that survives alone but is
// caught with the group is reported as masked, naming the layer that masks it.
package cross

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Markers.
const (
	MarkerEnforcementPoint = "subpoena:enforcement_point"
	MarkerEnforcement      = "subpoena:enforcement"
	MarkerGuard            = "subpoena:enforcement_guard"
)

// maxGroup bounds a layer group, so the search for masking layers (one run per
// pair of members) stays small.
const maxGroup = 8

// Outcome of one mutant.
type Outcome string

const (
	// Killed means the mutant made the suite fail: the enforcement is covered.
	Killed Outcome = "enforcement-mutant-killed"
	// KilledBySelfReport means a clean failure lacked independent witness evidence.
	KilledBySelfReport Outcome = "enforcement-mutant-killed-by-self-report"
	// Survived means the suite stayed green with enforcement removed.
	Survived Outcome = "enforcement-mutant-survived"
	// Invalid means the mutant did not compile; it proves nothing either way.
	Invalid Outcome = "enforcement-mutant-invalid"
	// TimedOut means the suite did not finish within Options.Timeout. A hang
	// may be the mutant's doing or the host's, so it is not a kill.
	TimedOut Outcome = "enforcement-mutant-timeout"
	// Crashed means the suite went red with no clean failure message: a test
	// binary died (panic, runtime fatal error, os.Exit), or a test failed
	// without saying why. A crash is not evidence that the enforcement is tested, so it
	// fails the run like a survivor.
	Crashed Outcome = "enforcement-mutant-crashed"
	// Masked means the layer survived alone but its group's mutant was killed:
	// another declared layer catches the bypass. MaskedBy names it.
	Masked Outcome = "enforcement-layer-masked"
)

// Mutant is one planned removal, or for a guard, one forced condition.
type Mutant struct {
	Func    string // enclosing function name
	File    string // path relative to the module root
	Line    int
	Removed string // the source text removed; for a guard, the condition
	Bypass  string // "true" or "false" for a guard; empty for a removal
	Group   string // layer group from group=<name>; empty if none
	start   int    // byte offsets of the statement (guard: condition) in File
	end     int
	point   int    // byte offset of the enclosing function declaration in File
	src     []byte // file bytes the offsets were computed from; not a later reread
	// zero is the return of zero values that can stand in for a removed return,
	// "" if there is none (see zeroReturn); fnEnd is the offset of its function's closing brace,
	// which is where the compiler reports a missing return. useZero applies it.
	zero    string
	fnEnd   int
	useZero bool
}

// Name identifies the mutant in reports: function, file and line.
func (m Mutant) Name() string { return fmt.Sprintf("%s (%s:%d)", m.Func, m.File, m.Line) }

// replacement is the text the mutant puts in place of Removed. A forced
// condition keeps the original expression, so variables it uses stay used.
func (m Mutant) replacement() string {
	if m.useZero {
		return m.zero + " /* replaced by subpoena-cross */"
	}
	switch m.Bypass {
	case "true":
		return "(" + m.Removed + ") || true /* forced by subpoena-cross */"
	case "false":
		return "(" + m.Removed + ") && false /* forced by subpoena-cross */"
	}
	return "/* removed by subpoena-cross */"
}

// Result is the outcome of running one mutant.
type Result struct {
	Mutant  Mutant
	With    []Mutant // further layers applied together with Mutant (group runs)
	Group   string   // set on a whole-group run
	Outcome Outcome
	Failing []string // names of failing tests, for Killed
	// Evidence is the kind of the first failure in a Killed run, and
	// FirstFailure that failure's message.
	Evidence     Evidence
	FirstFailure string
	// LaterWitness is a witness failure that came after a FirstFailure of
	// another kind. It never upgrades the kill: an exit code that ended a test
	// first is the failure this field sits beside, and so is a t.Log, which go
	// test prints the same way. It only tells the reader where to look.
	LaterWitness string
	// ZeroReturns lists the zero-value returns that stood in for returns the
	// function could not end without, so a mutant could compile.
	ZeroReturns []string
	// Hint says what to do about an Invalid result, when cross can tell.
	Hint string
	// EvidenceFile is where the full go test -json output was kept, if
	// Options.EvidenceDir is set.
	EvidenceFile string
	Output       string // tail of go output, for Survived/Invalid
	// Unfinished names, for TimedOut, each package and test that had started
	// and not ended when the timeout hit: go test buffers a package's output,
	// so Output alone is often empty.
	Unfinished []string
	// MaskedBy names, for Masked, each layer whose removal together with this
	// one turned the suite red. Empty when only the layers together did.
	MaskedBy []string
	// Accepted is the reason from MaskedFile when a masked layer is listed.
	Accepted string
}

// Evidence is what turned a mutant's suite red first, read from the first
// failure message. The harness tags its messages (pkg/harness TagWitness,
// TagTestimony); a test can tag its own the same way. An untagged message is
// Other: an exit code, an audit row, a target record, or output.
type Evidence string

const (
	EvidenceWitness   Evidence = "witness"
	EvidenceTestimony Evidence = "testimony"
	EvidenceOther     Evidence = "other"
)

// Report is the outcome of a whole cross-examination.
type Report struct {
	ModuleRoot        string
	Target            string // target directory relative to the module root
	EnforcementPoints int    // functions marked //subpoena:enforcement_point
	// Snapshot hashes mutant-bearing files only, from the bytes discovery
	// parsed. It is not a hash of the full source tree, test files, or
	// external module replacements.
	Snapshot []SourceFile
	Results  []Result
	// StaleAccepted lists entries of the masked-layer file (MaskedFile) that
	// matched no masked layer. They fail the run, so the file cannot go stale.
	StaleAccepted []string
}

// MaskedFile, in the target directory, lists masked layers accepted as
// covered only together with their group, one per line, each with a reason:
//
//	<file> | <func> | group=<group> | <removed text or condition> | <reason>
//
// It is a reviewed claim, like a marker. Lines starting with # are comments.
const MaskedFile = "cross-masked.txt"

// SourceFile is one mutant-bearing file frozen at discovery. Offsets are valid
// only for these bytes. Files with no mutant, and modules pulled in by replace,
// are absent.
type SourceFile struct {
	Path   string
	SHA256 string
}

// Failed reports whether any mutant survived, was invalid or timed out, any
// masked layer is not accepted in MaskedFile, or an entry there is stale.
//
//subpoena:enforcement_point
func (r *Report) Failed() bool {
	for _, x := range r.Results {
		if x.Outcome == Masked && x.Accepted != "" {
			continue
		}
		if x.Outcome != Killed {
			return true //subpoena:enforcement
		}
	}
	if len(r.StaleAccepted) > 0 {
		return true //subpoena:enforcement
	}
	return false
}

// Options configure a run.
type Options struct {
	// RequireWitness accepts kills only when their first failure is witness evidence.
	RequireWitness bool
	Target         string        // directory to cross-examine, inside a Go module
	Timeout        time.Duration // per go command, and so per mutant run; 5 minutes if zero
	Log            io.Writer     // progress; io.Discard if nil
	// EvidenceDir, if set, keeps the full go test -json output of every
	// mutant run there, killed ones included, one file per run.
	EvidenceDir string
	// Jobs is how many single mutants run at once, each in its own copy of
	// the module; 1 if zero. Group runs stay sequential. Load can flip a
	// verdict either way: a polling witness sees less on a busy host (a kill
	// becomes a survivor, which fails the run), and a timing-sensitive test
	// can fail under contention (a survivor becomes a kill). Gate on -j 1, or
	// confirm kills there.
	Jobs int
	// Select runs each mutant against only the tests that executed its line
	// in a per-test coverage pass after the baseline (see select.go).
	Select   bool
	selected map[string][]string // Mutant.Name() -> tests, when Select
	runs     *atomic.Int64       // numbers the evidence files
	// afterDiscover, if set, runs after the snapshot is taken and before
	// baseline. Tests use it to edit the live tree. Production leaves it nil.
	afterDiscover func(liveRoot string)
	// beforeMutate, if set, runs after baseline and before a mutant is written.
	// Tests use it to edit the snapshot copy. Production leaves it nil.
	beforeMutate func(tmpRoot string)
}

// Run cross-examines the suite.
//
//subpoena:enforcement_point
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Minute
	}
	o.runs = new(atomic.Int64)
	if o.Jobs < 1 {
		o.Jobs = 1
	}
	o.Log = &lockedWriter{w: o.Log}
	target, err := filepath.Abs(o.Target)
	if err != nil {
		return nil, err
	}
	root, err := moduleRoot(target)
	if err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(root, target)
	rep := &Report{ModuleRoot: root, Target: filepath.ToSlash(rel)}

	tmp, err := os.MkdirTemp("", "subpoena-cross-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyTree(root, tmp); err != nil {
		return nil, fmt.Errorf("cross: copy tree: %w", err)
	}
	// Discovery reads this copy, not the live tree. The offsets and the
	// mutation use the same bytes, so later live edits cannot move them.
	// copyTree is not an atomic snapshot of the whole module.
	mutants, err := FindMutants(tmp, filepath.Join(tmp, rel))
	if err != nil {
		return nil, err
	}
	if len(mutants) == 0 {
		return nil, fmt.Errorf("cross: no //%s functions under %s; cross-examination would be vacuous", MarkerEnforcementPoint, o.Target) //subpoena:enforcement
	}
	points := map[string]bool{}
	for _, m := range mutants {
		points[fmt.Sprintf("%s:%d", m.File, m.point)] = true
	}
	rep.EnforcementPoints = len(points)
	rep.Snapshot = snapshotOf(mutants)
	groups, err := groupsOf(mutants)
	if err != nil {
		return nil, err
	}

	if err := absoluteReplaces(ctx, root, tmp); err != nil {
		return nil, err
	}
	// A GOWORK file inside the module (e.g. go.work.sandbox) was copied along
	// with the tree; point each copy's builds at its own copied file so its
	// `use .` resolves to the mutated tree, not the original.
	// A GOWORK file outside the module can never `use` the temp copy, so it is
	// disabled for the copy's builds.
	inCopy := func(dir string) sandbox {
		sb := sandbox{dir: dir}
		if work := os.Getenv("GOWORK"); work != "" && work != "off" {
			sb.work = "off"
			if rel, err := filepath.Rel(root, work); err == nil && !strings.HasPrefix(rel, "..") {
				sb.work = filepath.Join(dir, rel)
			}
		}
		return sb
	}
	primary := inCopy(tmp)
	// Further workers get copies of the discovery copy, made after the
	// replaces were rewritten: the same bytes, so the drift check holds.
	workers := []sandbox{primary}
	for i := 1; i < min(o.Jobs, len(mutants)); i++ {
		dir, err := os.MkdirTemp("", "subpoena-cross-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		if err := copyTree(tmp, dir); err != nil {
			return nil, fmt.Errorf("cross: copy tree: %w", err)
		}
		workers = append(workers, inCopy(dir))
	}

	pkgs := "./" + rep.Target + "/..."
	if rep.Target == "." {
		pkgs = "./..."
	}
	fmt.Fprintf(o.Log, "baseline: go test %s\n", pkgs)
	if o.afterDiscover != nil {
		o.afterDiscover(root)
	}
	// The verdict is kept apart from the return so that cross-examining
	// this function (make cross-self) can remove the return and still compile.
	var baselineErr error
	if raw, err := goIn(ctx, o.Timeout, primary, "test", "-json", "-count=1", pkgs); err != nil {
		baselineErr = fmt.Errorf("cross: baseline suite is not green, cannot judge mutants: %s", baselineReason(raw, err))
	}
	if baselineErr != nil {
		return nil, baselineErr //subpoena:enforcement
	}

	if o.Select {
		fmt.Fprintf(o.Log, "select: running each test alone with coverage\n")
		if o.selected, err = selectTests(ctx, o, primary, pkgs, mutants); err != nil {
			return nil, err
		}
		if err := checkSubsets(ctx, o, primary, pkgs, mutants); err != nil {
			return nil, err
		}
	}
	single := map[string]int{} // Mutant.Name() -> index in rep.Results
	results, err := runSingles(ctx, o, workers, pkgs, mutants)
	if err != nil {
		return nil, err
	}
	if o.Select {
		// A test can stop a mutant without its coverage showing the line (in
		// a subprocess, say), so anything but a kill is judged again on the
		// whole suite. Group runs use the whole suite too: a survivor that
		// selection made could otherwise come back as an accepted masked layer.
		results, err = confirmOnWholeSuite(ctx, o, workers, pkgs, mutants, results)
		if err != nil {
			return nil, err
		}
		o.selected = nil
	}
	for i, m := range mutants {
		single[m.Name()] = len(rep.Results)
		rep.Results = append(rep.Results, results[i])
	}

	// Layer groups. The whole group runs as one mutant. A layer that survived
	// alone can only be masked by other layers that also survived alone: a
	// run that includes a layer killed on its own is red because of that
	// layer, and says nothing about the rest. So the layers that survived
	// alone run together, and then in pairs, to name what masks what.
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		members := groups[g]
		res, err := runCase(ctx, o, primary, pkgs, members)
		if err != nil {
			return nil, err
		}
		res.Group = g
		rep.Results = append(rep.Results, res)
		var alone []Mutant
		for _, m := range members {
			if rep.Results[single[m.Name()]].Outcome == Survived {
				alone = append(alone, m)
			}
		}
		if len(alone) < 2 {
			continue
		}
		if len(alone) < len(members) {
			if res, err = runCase(ctx, o, primary, pkgs, alone); err != nil {
				return nil, err
			}
			res.Group = g
			rep.Results = append(rep.Results, res)
		}
		if res.Outcome != Killed {
			continue // survived together: they stay survivors; anything else fails as it is
		}
		pairs := map[[2]string]Outcome{}
		for _, m := range alone {
			var by []string
			for _, other := range alone {
				if other.Name() == m.Name() {
					continue
				}
				key := [2]string{m.Name(), other.Name()}
				if key[0] > key[1] {
					key[0], key[1] = key[1], key[0]
				}
				out, seen := pairs[key]
				if !seen {
					pair, err := runCase(ctx, o, primary, pkgs, []Mutant{m, other})
					if err != nil {
						return nil, err
					}
					out, pairs[key] = pair.Outcome, pair.Outcome
					if out != Killed && out != Survived {
						// A pair that did not build or timed out decides
						// nothing; report it, and it fails the run.
						pair.Group = g
						rep.Results = append(rep.Results, pair)
					}
				}
				if out == Killed {
					by = append(by, other.Name())
				}
			}
			rep.Results[single[m.Name()]].Outcome, rep.Results[single[m.Name()]].MaskedBy = Masked, by
		}
	}
	if err := acceptMasked(rep, filepath.Join(tmp, rel, MaskedFile)); err != nil {
		return nil, err
	}
	return rep, nil
}

// runCase applies the mutants together to the snapshot copy, builds, runs the
// suite and restores the snapshot. The first mutant is the Result's Mutant;
// the rest are With. A canceled ctx is an error, never a verdict: the go
// command it stopped proves nothing about the mutant.
//
//subpoena:enforcement_point
func runCase(ctx context.Context, o Options, sb sandbox, pkgs string, ms []Mutant) (res Result, err error) {
	tmp := sb.dir
	res = Result{Mutant: ms[0], With: ms[1:]}
	byFile := map[string][]Mutant{}
	var files []string
	for _, m := range ms {
		if _, ok := byFile[m.File]; !ok {
			files = append(files, m.File)
		}
		byFile[m.File] = append(byFile[m.File], m)
	}
	if o.beforeMutate != nil {
		o.beforeMutate(tmp)
	}
	mutated := map[string][]byte{}
	for _, file := range files {
		path := filepath.Join(tmp, filepath.FromSlash(file))
		onDisk, err := os.ReadFile(path)
		if err != nil {
			return res, err
		}
		if !bytes.Equal(onDisk, byFile[file][0].src) {
			return res, fmt.Errorf("cross: %s: snapshot drift: copy no longer matches discovery bytes", file) //subpoena:enforcement
		}
		b, err := applyMutants(byFile[file][0].src, byFile[file])
		if err != nil {
			return res, fmt.Errorf("cross: %s: %w", file, err)
		}
		mutated[file] = b
	}
	// Restore every touched file to the snapshot, not a later reread, however
	// this case ends.
	defer func() {
		for _, file := range files {
			if werr := os.WriteFile(filepath.Join(tmp, filepath.FromSlash(file)), byFile[file][0].src, 0o644); werr != nil && err == nil {
				err = fmt.Errorf("cross: restore %s: %w", file, werr)
			}
		}
	}()
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(tmp, filepath.FromSlash(file)), mutated[file], 0o644); err != nil {
			return res, err
		}
	}
	for _, m := range ms {
		if m.Bypass != "" {
			fmt.Fprintf(o.Log, "mutant: %s forced %q to %s\n", m.Name(), oneLine(m.Removed), m.Bypass)
		} else {
			fmt.Fprintf(o.Log, "mutant: %s removed %q\n", m.Name(), oneLine(m.Removed))
		}
	}
	if len(ms) > 1 {
		fmt.Fprintf(o.Log, "  (%d layers together)\n", len(ms))
	}

	out, err := goIn(ctx, o.Timeout, sb, "build", pkgs)
	if err != nil {
		// Removing a statement may leave a function with no return at its end,
		// or an import unused (the removed line was its only use). Stand in a
		// zero-value return, drop those imports, and build again. A zero return
		// is one line, as the removal's comment is, so the line numbers in out
		// still hold for the imports.
		retry := false
		for _, file := range files {
			changed := false
			if ms, ok := zeroMissingReturns(byFile[file], file, out); ok {
				b, err := applyMutants(ms[0].src, ms)
				if err != nil {
					return res, fmt.Errorf("cross: %s: %w", file, err)
				}
				byFile[file], mutated[file], changed = ms, b, true
				for _, m := range ms {
					if m.useZero {
						res.ZeroReturns = append(res.ZeroReturns, m.zero)
						fmt.Fprintf(o.Log, "  %s cannot end without a return: %s\n", m.Name(), m.zero)
					}
				}
			}
			if b, ok := pruneUnusedImports(mutated[file], file, out); ok {
				mutated[file], changed = b, true
			}
			if changed {
				if err := os.WriteFile(filepath.Join(tmp, filepath.FromSlash(file)), mutated[file], 0o644); err != nil {
					return res, err
				}
				retry = true
			}
		}
		if retry {
			out, err = goIn(ctx, o.Timeout, sb, "build", pkgs)
		}
	}
	var testOut string
	var testErr error
	if err == nil {
		args := []string{"test", "-json", "-count=1", "-failfast"}
		if f := runFilter(o.selected, ms); f != "" {
			args = append(args, "-run", f)
			fmt.Fprintf(o.Log, "  selected tests: %s\n", f)
		}
		testOut, testErr = goIn(ctx, o.Timeout, sb, append(args, pkgs)...)
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("cross: run stopped: %w", ctx.Err()) //subpoena:enforcement
	}
	if err != nil {
		if timedOut(out, err) {
			res.Outcome, res.Output = TimedOut, tail(out, 20)
		} else {
			res.Outcome, res.Output = Invalid, tail(out, 20) //subpoena:enforcement
			if missingReturnRE.MatchString(out) {
				res.Hint = finalReturnHint
			}
		}
	} else {
		raw, err := testOut, testErr
		var ferr error
		if res.EvidenceFile, ferr = keepEvidence(o, ms, raw); ferr != nil {
			return res, ferr
		}
		out := testText(raw)
		if err != nil {
			// -failfast: one red test is a kill, so the rest of a package's
			// tests need not run. Other packages still run to the end.
			switch {
			case timedOut(out, err):
				res.Outcome, res.Output = TimedOut, tail(out, 20) //subpoena:enforcement
				res.Unfinished = unfinished(raw)
			case buildFailed(out):
				res.Outcome, res.Output = Invalid, tail(out, 20)
			default:
				ev, msg, crashed := firstFailure(raw)
				if crashed {
					res.Outcome, res.Output = Crashed, crashOutput(raw, 20) //subpoena:enforcement
				} else {
					res.Outcome, res.Failing = Killed, failingTests(out)
					res.Evidence, res.FirstFailure = ev, msg
					if ev != EvidenceWitness {
						res.LaterWitness = witnessFailure(raw)
					}
					if o.RequireWitness && ev != EvidenceWitness {
						res.Outcome = KilledBySelfReport //subpoena:enforcement
					}
				}
			}
		} else {
			res.Outcome, res.Output = Survived, tail(out, 20)
		}
	}
	if res.Outcome == TimedOut && orphansOnTimeout {
		return res, fmt.Errorf("cross: %s timed out, and on this platform its test binary may still be running and could fail later mutants; rerun with a larger -timeout or on a unix host", ms[0].Name())
	}
	return res, nil
}

// testText turns go test -json output back into the plain text go test
// prints. Lines that are not JSON events (the go command's own messages) are
// kept as they are.
func testText(raw string) string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		var ev struct{ Output string }
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &ev) == nil {
			b.WriteString(ev.Output)
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

// maxFailureText bounds the text read from under a blank head line.
const maxFailureText = 300

// emptyFailure stands in for a failure that printed no text at all.
const emptyFailure = "(the failure printed no text; -evidence-dir keeps the test's output)"

// failure is one failure message of a failed test.
type failure struct {
	pkg  string
	head string // text on the file:line, the only place a tag is read
	text string // what to print: head, or for a blank head the lines under it
	more bool   // lines still extend text
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
// package with a crash line anywhere in its output gives no kills at all, since
// a test's log lines before its panic look just like failure messages, and so
// does an assertion library's report: go test -json carries both as plain text,
// which the code under test can print. t.Log and t.Error print the same way, so a failed test's log line counts as its first
// failure: tagged, it can set ev; untagged, it hides a witness failure after it.
func firstFailure(raw string) (ev Evidence, msg string, crashed bool) {
	fs := failures(raw)
	if len(fs) == 0 {
		return "", "", true
	}
	msg = fs[0].text
	if msg == "" {
		msg = emptyFailure
	}
	switch {
	case strings.HasPrefix(fs[0].head, "witness:"):
		return EvidenceWitness, msg, false
	case strings.HasPrefix(fs[0].head, "testimony:"):
		return EvidenceTestimony, msg, false
	default:
		return EvidenceOther, msg, false
	}
}

// witnessFailure returns the first witness-tagged message of a failed test,
// or "" if there is none.
func witnessFailure(raw string) string {
	for _, f := range failures(raw) {
		if strings.HasPrefix(f.head, "witness:") {
			return f.head
		}
	}
	return ""
}

// failures lists, in order, the failure messages of failed tests. A package
// with a crash line anywhere gives none, whatever came first: Ginkgo runs a
// suite as one test, in random order, so order must not decide.
//
//subpoena:enforcement_point
func failures(raw string) []failure {
	type event struct {
		Action, Package, Test, Output string
	}
	type key [2]string
	var evs []event
	failed, dead := map[key]bool{}, map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		var e event
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		e.Output = ansiRE.ReplaceAllString(e.Output, "")
		evs = append(evs, e)
		k := key{e.Package, e.Test}
		switch e.Action {
		case "fail":
			failed[k] = true
		case "output":
			if crashRE.MatchString(e.Output) || ginkgoPanicRE.MatchString(e.Output) {
				dead[e.Package] = true //subpoena:enforcement
			}
		}
	}
	var fs []failure
	blank := map[key]int{}   // test -> index in fs of the blank head being read
	suite := map[key]bool{}  // test -> Ginkgo's "Running Suite:" banner seen
	ginkgo := map[key]bool{} // test -> inside a Ginkgo spec's failure report
	gomega := map[key]int{}  // test -> index in fs of the Ginkgo message being read
	for _, e := range evs {
		k := key{e.Package, e.Test}
		if e.Action != "output" || !failed[k] {
			continue
		}
		line := strings.TrimRight(e.Output, "\n")
		if ginkgoSuiteRE.MatchString(line) {
			suite[k] = true
		} else if suite[k] && ginkgoReportRE.MatchString(line) {
			ginkgo[k] = true
		} else if m := ginkgoFailedRE.FindStringSubmatch(line); m != nil && ginkgo[k] && !strings.HasPrefix(m[1], "in [") {
			delete(ginkgo, k)
			delete(blank, k)
			gomega[k] = len(fs)
			fs = append(fs, failure{pkg: e.Package, head: m[1], text: m[1]})
		} else if n, ok := gomega[k]; ok {
			if ginkgoAtRE.MatchString(line) || len(fs[n].text) >= maxFailureText {
				delete(gomega, k)
			} else {
				fs[n].text = strings.TrimSpace(fs[n].text + " " + strings.TrimSpace(line))
			}
		} else if m := failMsgRE.FindStringSubmatch(line); m != nil {
			delete(blank, k)
			if m[1] == "" {
				blank[k] = len(fs)
			}
			fs = append(fs, failure{pkg: e.Package, head: m[1], text: m[1], more: true})
		} else if n, ok := blank[k]; ok {
			fs[n].addLine(line)
		}
	}
	var clean []failure
	for _, f := range fs {
		if dead[f.pkg] {
			continue //subpoena:enforcement
		}
		clean = append(clean, f)
	}
	return clean
}

// crashRE matches the first line of a panic or a runtime fatal error.
var crashRE = regexp.MustCompile(`^(panic|fatal error): `)

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
	type key [2]string
	lines := map[string][]string{}
	crashAt := map[key]int{}
	var crashes []key
	passed := map[key]bool{}
	failedPkg := ""
	for _, l := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test, Output string }
		if !strings.HasPrefix(l, "{") || json.Unmarshal([]byte(l), &e) != nil {
			continue
		}
		k := key{e.Package, e.Test}
		switch e.Action {
		case "pass":
			passed[k] = true
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
	for _, k := range crashes {
		if !passed[k] {
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
func keepEvidence(o Options, ms []Mutant, raw string) (string, error) {
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
	p := filepath.Join(o.EvidenceDir, name+".jsonl")
	return p, os.WriteFile(p, []byte(raw), 0o644)
}

// groupsOf collects the layer groups. A group needs at least two layers (one
// is a typo that would silently drop the group run) and at most maxGroup.
//
//subpoena:enforcement_point
func groupsOf(mutants []Mutant) (map[string][]Mutant, error) {
	groups := map[string][]Mutant{}
	for _, m := range mutants {
		if m.Group != "" {
			groups[m.Group] = append(groups[m.Group], m)
		}
	}
	for g, ms := range groups {
		if len(ms) < 2 {
			return nil, fmt.Errorf("cross: group=%s has one layer (%s); a group needs at least two", g, ms[0].Name()) //subpoena:enforcement
		}
		if len(ms) > maxGroup {
			return nil, fmt.Errorf("cross: group=%s has %d layers; at most %d", g, len(ms), maxGroup) //subpoena:enforcement
		}
	}
	return groups, nil
}

// applyMutant applies one mutant to the snapshot bytes. Run does not use this
// to detect copy drift: it compares the copy to m.src and refuses before
// calling here. This check remains so a direct caller cannot slice different
// bytes silently.
func applyMutant(src []byte, m Mutant) ([]byte, error) {
	return applyMutants(src, []Mutant{m})
}

// applyMutants applies several mutants of one file, from the end backwards so
// earlier offsets stay valid. Overlapping mutants are refused.
func applyMutants(src []byte, ms []Mutant) ([]byte, error) {
	sorted := append([]Mutant(nil), ms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].start > sorted[j].start })
	out := append([]byte{}, src...)
	for i, m := range sorted {
		if m.src != nil && !bytes.Equal(src, m.src) {
			return nil, fmt.Errorf("source drift: bytes are not the discovery snapshot")
		}
		if m.start < 0 || m.end < m.start || m.end > len(src) {
			return nil, fmt.Errorf("source drift: offsets %d:%d outside %d-byte snapshot", m.start, m.end, len(src))
		}
		if string(src[m.start:m.end]) != m.Removed {
			return nil, fmt.Errorf("source drift: offsets no longer match %q", oneLine(m.Removed))
		}
		if i > 0 && m.end > sorted[i-1].start {
			return nil, fmt.Errorf("mutants overlap: %s and %s", m.Name(), sorted[i-1].Name())
		}
		out = append(append(append([]byte{}, out[:m.start]...), []byte(m.replacement())...), out[m.end:]...)
	}
	return out, nil
}

func snapshotOf(mutants []Mutant) []SourceFile {
	seen := map[string][]byte{}
	var files []string
	for _, m := range mutants {
		if _, ok := seen[m.File]; ok {
			continue
		}
		seen[m.File] = m.src
		files = append(files, m.File)
	}
	sort.Strings(files)
	out := make([]SourceFile, 0, len(files))
	for _, file := range files {
		sum := sha256.Sum256(seen[file])
		out = append(out, SourceFile{Path: file, SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}

// FindMutants locates every //subpoena:enforcement statement inside a function
// marked as an enforcement point (MarkerEnforcementPoint), in non-test files
// under target. Its doc names the marker by constant: the marker text in a
// doc comment, even in prose, makes a function an enforcement point.
func FindMutants(root, target string) ([]Mutant, error) {
	var out []Mutant
	err := filepath.WalkDir(target, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != target && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		ms, err := mutantsInFile(root, p)
		out = append(out, ms...)
		return err
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, err
}

//subpoena:enforcement_point
func mutantsInFile(root, path string) ([]Mutant, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(root, path)
	var out []Mutant
	// placed holds the marker comments that took effect: statement and guard
	// markers inside an enforcement point, and point markers on a function.
	placed := map[*ast.Comment]bool{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Doc != nil {
			for _, c := range fd.Doc.List {
				if pointRE.MatchString(c.Text) {
					placed[c] = true
				}
			}
		}
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Doc == nil || !hasPointMarker(fd.Doc) {
			continue
		}
		found := 0
		// Marker lines inside this function. The markers share a prefix, so
		// parseMarker matches the exact comment word.
		lines := map[int]marker{}
		for _, g := range f.Comments {
			for _, c := range g.List {
				if c.Pos() <= fd.Body.Lbrace || c.End() >= fd.Body.Rbrace {
					continue
				}
				mk, ok, err := parseMarker(c.Text)
				if err != nil {
					return nil, fmt.Errorf("cross: %s:%d: %w", rel, fset.Position(c.Pos()).Line, err) //subpoena:enforcement
				}
				if ok {
					lines[fset.Position(c.Pos()).Line] = mk
					placed[c] = true
				}
			}
		}
		offIf := map[int]bool{} // guard lines whose outermost statement is not an if
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			st, ok := n.(ast.Stmt)
			if !ok {
				return true
			}
			if _, isBlock := st.(*ast.BlockStmt); isBlock {
				return true
			}
			line := fset.Position(st.Pos()).Line
			mk, marked := lines[line]
			if !marked || offIf[line] {
				return true
			}
			// Take the outermost statement that starts on the marked line. A
			// guard marker takes the if and forces its condition. A statement
			// marker on `if cond { return x }` would remove the whole if, so
			// only simple statements are accepted.
			var node ast.Node = st
			if mk.guard {
				ifs, isIf := st.(*ast.IfStmt)
				if !isIf {
					// An if further in (in a closure on this line) is not
					// the statement the marker sits on: leave the line
					// unplaced, which is an error below.
					offIf[line] = true //subpoena:enforcement
					return true
				}
				node = ifs.Cond
			} else {
				switch st.(type) {
				case *ast.ReturnStmt, *ast.ExprStmt, *ast.AssignStmt, *ast.BranchStmt, *ast.IncDecStmt:
				default:
					return true
				}
			}
			delete(lines, line)
			found++
			s, e := fset.Position(node.Pos()).Offset, fset.Position(node.End()).Offset
			m := Mutant{
				Func: fd.Name.Name, File: filepath.ToSlash(rel), Line: line,
				Removed: string(src[s:e]), Bypass: mk.bypass, Group: mk.group,
				start: s, end: e, point: fset.Position(fd.Pos()).Offset, src: src,
			}
			if ret, ok := st.(*ast.ReturnStmt); ok && !mk.guard {
				m.zero, m.fnEnd = zeroReturn(src, fset, fd, ret)
			}
			out = append(out, m)
			return true
		})
		if len(lines) > 0 {
			left := make([]int, 0, len(lines))
			for line := range lines {
				left = append(left, line)
			}
			sort.Ints(left)
			return nil, fmt.Errorf("cross: %s:%d: %s", rel, left[0], misplaced(lines[left[0]], fd.Name.Name)) //subpoena:enforcement
		}
		// An enforcement point with nothing to remove would never be
		// cross-examined, and the run would still go green.
		if found == 0 {
			return nil, fmt.Errorf("cross: %s: %s is marked //%s but has no //%s statement, so it cannot be cross-examined", rel, fd.Name.Name, MarkerEnforcementPoint, MarkerEnforcement) //subpoena:enforcement
		}
	}
	// A marker that took no effect would leave its statement unexamined while
	// the run stays green: one outside an enforcement point, or a misspelt one.
	var stray error
	for _, g := range f.Comments {
		for _, c := range g.List {
			if anyMarkerRE.MatchString(c.Text) && !placed[c] && stray == nil {
				stray = fmt.Errorf("cross: %s:%d: %q is not a marker cross applies: statement and guard markers belong inside a //%s function, and the point marker on a function's doc comment", rel, fset.Position(c.Pos()).Line, c.Text, MarkerEnforcementPoint)
			}
		}
	}
	if stray != nil {
		return nil, stray //subpoena:enforcement
	}
	return out, nil
}

// zeroReturn returns the statement that can stand in for ret where the
// function cannot end without a return, and the offset of that function's
// closing brace. *new(T) is T's zero value for any T, so no type needs
// resolving. Only a refusal carried by an error has a stand-in (see
// errorRefusal). Zero is not "enforcement gone" for any other return: false can
// be the refusal, and then the stand-in forces enforcement on, and the value is
// cross's own choice, with no review behind it as a guard's bypass value has.
//
//subpoena:enforcement_point
func zeroReturn(src []byte, fset *token.FileSet, fd *ast.FuncDecl, ret *ast.ReturnStmt) (string, int) {
	typ, body := fd.Type, fd.Body
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.FuncLit); ok && lit.Body.Pos() <= ret.Pos() && ret.Pos() < lit.Body.End() {
			typ, body = lit.Type, lit.Body
		}
		return true
	})
	end := fset.Position(body.Rbrace).Offset
	if typ.Results == nil {
		return "", end
	}
	var zeros []string
	var isError []bool
	for _, field := range typ.Results.List {
		text := string(src[fset.Position(field.Type.Pos()).Offset:fset.Position(field.Type.End()).Offset])
		if strings.Contains(text, "\n") {
			return "", end // one line only: the line numbers of a retried build depend on it
		}
		for range max(1, len(field.Names)) {
			zeros = append(zeros, "*new("+text+")")
			isError = append(isError, text == "error")
		}
	}
	if !errorRefusal(ret.Results, isError) {
		return "", end //subpoena:enforcement
	}
	return "return " + strings.Join(zeros, ", "), end
}

// errorRefusal reports whether a return's only news is an error, so that its
// zero values turn a possible refusal into nil and change nothing else. Every
// other result must already be plainly zero: a value beside the error can carry
// the decision. A bare return, and one call spread over the results, say
// nothing about which result is which.
func errorRefusal(results []ast.Expr, isError []bool) bool {
	if len(results) != len(isError) {
		return false
	}
	refusal := false
	for i, e := range results {
		if isZeroValue(e) {
			continue
		}
		if !isError[i] {
			return false
		}
		refusal = true
	}
	return refusal
}

// isZeroValue reports whether e is plainly a zero value. A named constant that
// happens to be zero is not seen here.
func isZeroValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "nil" || x.Name == "false"
	case *ast.BasicLit:
		return x.Value == "0" || x.Value == `""` || x.Value == "``"
	case *ast.CompositeLit:
		return len(x.Elts) == 0
	}
	return false
}

// misplaced says why a marker matched no statement.
func misplaced(mk marker, fn string) string {
	if mk.guard {
		return fmt.Sprintf("//%s in %s is not on an if line", MarkerGuard, fn)
	}
	return fmt.Sprintf("//%s in %s is not on a simple statement line", MarkerEnforcement, fn)
}

// marker is a parsed //subpoena:enforcement or //subpoena:enforcement_guard.
type marker struct {
	guard  bool
	bypass string // guard only: "true" or "false"
	group  string
}

var (
	enforcementRE = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerEnforcement) + `(\s|$)`)
	guardRE       = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerGuard) + `(\s|$)`)
	groupRE       = regexp.MustCompile(`^group=([A-Za-z0-9_.-]+)$`)
	pointRE       = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerEnforcementPoint) + `(\s|$)`)
	anyMarkerRE   = regexp.MustCompile(`^//\s*subpoena:enforcement`)
)

func isEnforcementComment(text string) bool { return enforcementRE.MatchString(text) }

// parseMarker reads a statement or guard marker. ok is false for any other
// comment. Arguments it does not understand are an error, not ignored: a
// misspelt group would otherwise drop the layer from its group silently.
//
//subpoena:enforcement_point
func parseMarker(text string) (mk marker, ok bool, err error) {
	var args []string
	switch {
	case guardRE.MatchString(text):
		args = strings.Fields(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(text, "//")), MarkerGuard))
		mk.guard = true
		if len(args) > 0 {
			mk.bypass, args = args[0], args[1:]
		}
		if mk.bypass != "true" && mk.bypass != "false" {
			return mk, false, fmt.Errorf("//%s needs the bypass value first: true or false", MarkerGuard) //subpoena:enforcement
		}
	case enforcementRE.MatchString(text):
		args = strings.Fields(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(text, "//")), MarkerEnforcement))
	default:
		return mk, false, nil
	}
	for _, a := range args {
		name := ""
		if g := groupRE.FindStringSubmatch(a); g != nil {
			name = g[1]
		}
		if name == "" || mk.group != "" {
			return mk, false, fmt.Errorf("marker argument %q: want at most one group=<name>", a) //subpoena:enforcement
		}
		mk.group = name
	}
	return mk, true, nil
}

// hasPointMarker reports whether a doc comment mentions the enforcement-point
// marker anywhere, as subpoena-lint does (internal/lint commentHas). Matching
// loosely fails closed: anything lint treats as an enforcement point must have
// a statement to cross-examine.
func hasPointMarker(g *ast.CommentGroup) bool {
	for _, c := range g.List {
		if strings.Contains(c.Text, MarkerEnforcementPoint) {
			return true
		}
	}
	return false
}

// absoluteReplaces rewrites the copy's go.mod so that a replace pointing at a
// relative directory (replace example.com/x => ../x, common while developing
// against a local checkout) still points at that directory from the temp
// copy, where the relative path would resolve to nothing.
func absoluteReplaces(ctx context.Context, root, tmp string) error {
	out, err := goCmd(ctx, time.Minute, root, "mod", "edit", "-json")
	if err != nil {
		return fmt.Errorf("cross: read go.mod: %s", tail(out, 10))
	}
	var mod struct {
		Replace []struct {
			Old, New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal([]byte(out), &mod); err != nil {
		return fmt.Errorf("cross: read go.mod: %w", err)
	}
	for _, r := range mod.Replace {
		if r.New.Version != "" || !(strings.HasPrefix(r.New.Path, "./") || strings.HasPrefix(r.New.Path, "../")) {
			continue
		}
		old := r.Old.Path
		if r.Old.Version != "" {
			old += "@" + r.Old.Version
		}
		abs := filepath.Join(root, filepath.FromSlash(r.New.Path))
		if out, err := goCmd(ctx, time.Minute, tmp, "mod", "edit", "-replace="+old+"="+abs); err != nil {
			return fmt.Errorf("cross: rewrite replace %s: %s", old, tail(out, 10))
		}
	}
	return nil
}

var missingReturnRE = regexp.MustCompile(`(?m)^(?:\./)?(\S+\.go):(\d+):\d+: missing return$`)

// finalReturnHint is the advice for a return with no stand-in.
const finalReturnHint = "the function cannot end without this return, and it already returns zero values, so no mutant can stand in for it; " +
	"mark the if that reaches it with //" + MarkerGuard + ", or move the decision into an if that can carry the marker"

// zeroMissingReturns turns on the zero-value return of each mutant whose
// function the compiler reports as missing a return, and reports whether it
// turned on any. A return the function can do without stays removed: a stand-in
// there would end the function where the mutant must carry on.
func zeroMissingReturns(ms []Mutant, file, buildOut string) ([]Mutant, bool) {
	lines := map[int]bool{}
	for _, m := range missingReturnRE.FindAllStringSubmatch(buildOut, -1) {
		if reportedFile(m[1], file) {
			var n int
			fmt.Sscan(m[2], &n)
			lines[n] = true
		}
	}
	out := slices.Clone(ms)
	changed := false
	for i, m := range out {
		if m.zero != "" && lines[lineAfterRemovals(m.fnEnd, ms)] {
			out[i].useZero, changed = true, true
		}
	}
	return out, changed
}

// lineAfterRemovals is the line of a snapshot offset once ms are applied: a
// removed statement leaves one line however many it spanned.
func lineAfterRemovals(offset int, ms []Mutant) int {
	src := ms[0].src
	line := 1 + bytes.Count(src[:offset], []byte("\n"))
	for _, m := range ms {
		if m.Bypass == "" && m.end <= offset {
			line -= bytes.Count(src[m.start:m.end], []byte("\n"))
		}
	}
	return line
}

// reportedFile reports whether a path in compiler output is file, a
// module-relative path.
func reportedFile(reported, file string) bool {
	r, f := filepath.ToSlash(filepath.Clean(reported)), filepath.ToSlash(filepath.Clean(file))
	return r == f || strings.HasSuffix(f, "/"+r)
}

var unusedImportRE = regexp.MustCompile(`(?m)^(?:\./)?(\S+\.go):(\d+):\d+: "[^"]+" imported (?:as \S+ )?and not used`)

// pruneUnusedImports removes from src (the mutated file, at module-relative
// path file) the import lines the compiler output reports as unused, and
// reports whether it removed any. Only lines in the mutated file are touched,
// and only import specs on a line of their own.
func pruneUnusedImports(src []byte, file, buildOut string) ([]byte, bool) {
	drop := map[int]bool{}
	for _, m := range unusedImportRE.FindAllStringSubmatch(buildOut, -1) {
		if !reportedFile(m[1], file) {
			continue
		}
		var n int
		fmt.Sscan(m[2], &n)
		drop[n] = true
	}
	if len(drop) == 0 {
		return nil, false
	}
	lines := strings.SplitAfter(string(src), "\n")
	var b strings.Builder
	removed := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if drop[i+1] && (strings.HasPrefix(t, `"`) || strings.HasPrefix(t, "import ") || (len(t) > 0 && strings.Contains(t, ` "`))) {
			removed = true
			continue
		}
		b.WriteString(l)
	}
	return []byte(b.String()), removed
}

func moduleRoot(dir string) (string, error) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("cross: no go.mod above %s", dir)
		}
	}
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

// sandbox is one copy of the module that mutants are run in, and the GOWORK
// its go commands use ("" to inherit the environment's).
type sandbox struct {
	dir, work string
}

// runSingles runs each mutant alone, on as many copies as there are workers,
// and returns the results in mutants' order. The first error stops the rest.
//
//subpoena:enforcement_point
func runSingles(ctx context.Context, o Options, workers []sandbox, pkgs string, mutants []Mutant) ([]Result, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	results := make([]Result, len(mutants))
	next := make(chan int)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	for _, sb := range workers {
		wg.Add(1)
		go func(sb sandbox) {
			defer wg.Done()
			for i := range next {
				if ctx.Err() != nil {
					continue
				}
				res, err := runCase(ctx, o, sb, pkgs, []Mutant{mutants[i]})
				if err != nil {
					once.Do(func() { firstErr = err; cancel(err) })
					continue
				}
				results[i] = res
			}
		}(sb)
	}
feed:
	for i := range mutants {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	// A cancel can stop the feed between two runs, with no run left to
	// report it: unrun mutants must not come back as zero results.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cross: run stopped: %w", err) //subpoena:enforcement
	}
	return results, nil
}

// goIn runs go in a sandbox copy.
func goIn(ctx context.Context, timeout time.Duration, sb sandbox, args ...string) (string, error) {
	var env []string
	if sb.work != "" {
		env = append(os.Environ(), "GOWORK="+sb.work)
	}
	return goCmdEnv(ctx, timeout, sb.dir, env, args...)
}

// lockedWriter serializes progress lines from parallel mutants.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// errTimeout is returned by goCmd when the command ran past its timeout.
var errTimeout = errors.New("timed out")

func goCmd(ctx context.Context, timeout time.Duration, dir string, args ...string) (string, error) {
	return goCmdEnv(ctx, timeout, dir, nil, args...)
}

// goCmdEnv is goCmd with an environment; nil inherits this process's.
func goCmdEnv(ctx context.Context, timeout time.Duration, dir string, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = env
	killGroupOnCancel(cmd)
	// A process left holding the output pipe must not hold up the verdict.
	cmd.WaitDelay = 5 * time.Second
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("go %s: %w after %v", args[0], errTimeout, timeout)
	}
	return buf.String(), err
}

// testTimeoutRE matches the test binary's own -timeout panic.
var testTimeoutRE = regexp.MustCompile(`(?m)^panic: test timed out after `)

// timedOut reports whether a failed go test run ended by a timeout, either
// goCmd's or the test binary's own, rather than by a failing test.
func timedOut(out string, err error) bool {
	return errors.Is(err, errTimeout) || testTimeoutRE.MatchString(out)
}

var (
	failRE  = regexp.MustCompile(`(?m)^\s*--- FAIL: (\S+)`)
	buildRE = regexp.MustCompile(`\[(build|setup) failed\]`)
)

func buildFailed(out string) bool { return buildRE.MatchString(out) }

func failingTests(out string) []string {
	var names []string
	seen := map[string]bool{}
	for _, m := range failRE.FindAllStringSubmatch(out, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	if len(names) == 0 {
		names = []string{"(package failed without a named test failure)"}
	}
	return names
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// acceptMasked marks masked layers listed in the masked-layer file as
// accepted, and records entries that match no masked layer as stale. A
// missing file accepts nothing.
//
//subpoena:enforcement_point
func acceptMasked(rep *Report, path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	reasons := map[string]string{}
	var order []string
	bad := 0 // first malformed line; the verdict is kept apart from the return, as in Run
	ambiguous := ""
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " | ", 5)
		if len(f) != 5 || !strings.HasPrefix(strings.TrimSpace(f[2]), "group=") || strings.TrimSpace(f[4]) == "" {
			bad = i + 1
			break
		}
		key := maskedKey(strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.TrimPrefix(strings.TrimSpace(f[2]), "group="), f[3])
		if _, dup := reasons[key]; dup {
			bad = i + 1
			break
		}
		reasons[key] = strings.TrimSpace(f[4])
		order = append(order, key)
	}
	if bad > 0 {
		return fmt.Errorf("cross: %s:%d: want <file> | <func> | group=<group> | <removed text> | <reason>, each layer listed once", MaskedFile, bad) //subpoena:enforcement
	}
	// One entry accepts one layer. Two masked layers with the same key (the
	// same text twice in one function) cannot be told apart, so neither is.
	layers := map[string]int{}
	for _, r := range rep.Results {
		if r.Outcome == Masked {
			layers[maskedKey(r.Mutant.File, r.Mutant.Func, r.Mutant.Group, r.Mutant.Removed)]++
		}
	}
	for key := range reasons {
		if layers[key] > 1 {
			delete(reasons, key)
			ambiguous = key
		}
	}
	if ambiguous != "" {
		return fmt.Errorf("cross: %s: %q matches %d masked layers; an entry accepts one layer, so make the removed text unique", MaskedFile, ambiguous, layers[ambiguous]) //subpoena:enforcement
	}
	used := map[string]bool{}
	for i, r := range rep.Results {
		if r.Outcome != Masked {
			continue
		}
		key := maskedKey(r.Mutant.File, r.Mutant.Func, r.Mutant.Group, r.Mutant.Removed)
		if reason, ok := reasons[key]; ok {
			rep.Results[i].Accepted = reason
			used[key] = true
		}
	}
	for _, key := range order {
		if !used[key] {
			rep.StaleAccepted = append(rep.StaleAccepted, key)
		}
	}
	return nil
}

func maskedKey(file, fn, group, removed string) string {
	return file + " | " + fn + " | group=" + group + " | " + oneLine(removed)
}
