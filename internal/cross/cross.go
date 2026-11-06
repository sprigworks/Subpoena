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
// the refusal itself (return p.Check(u) would become return false), and a call
// can be the work the allowed path needs (return s.Authorize(admins)).
//
// A kill says a test noticed the mutant, not that the test examined the refusal.
// Removing an early return or an assignment can stop the allowed path too, as a
// wrong guard value does, and then a test of the allowed path alone kills it.
// Nothing in the output tells the two apart: docs/architecture.md, "What a kill
// does not prove".
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
	"crypto/rand"
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
	"maps"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// Markers.
const (
	MarkerEnforcementPoint = "subpoena:enforcement_point"
	MarkerEnforcement      = "subpoena:enforcement"
	MarkerGuard            = "subpoena:enforcement_guard"
)

// killRepeats is how many times a kill's whole test command runs again with the
// mutant, on a fresh copy. A red run the mutant caused is red again; a rare flake
// is not, and this is what stops one: runs without the mutant pass a flake that
// fails one time in twenty-five nearly every time.
var killRepeats = 1

// killReruns is how many times a kill's failed packages run again without the
// mutant, each on a fresh copy. One rerun catches a test that fails half the
// time only half the time, so it is more than one. Together with killRepeats
// these narrow a flake's way to a kill, and do not close it. See
// docs/architecture.md.
var killReruns = 3

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
	// Unconfirmed means the suite went red on an assertion, but the kill did not
	// hold: run again with the mutant on a fresh copy it was no clean failure of a
	// test that failed the first time, or it failed in a rerun without the mutant,
	// or no failed test's binary links the mutated code. Leftover state or a flake,
	// so the mutant may have had no part in it. A kill it is not.
	Unconfirmed Outcome = "enforcement-mutant-unconfirmed"
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
	Func string // enclosing function name
	File string // path relative to the module root
	Line int
	// Upstream is Line with the marker-only lines above it taken out: the line
	// in the source before anyone marked it, if markers are all that was added.
	Upstream int
	Removed  string // the source text removed; for a guard, the condition
	Bypass   string // "true" or "false" for a guard; empty for a removal
	Group    string // layer group from group=<name>; empty if none
	start    int    // byte offsets of the statement (guard: condition) in File
	end      int
	point    int    // byte offset of the enclosing function declaration in File
	src      []byte // file bytes the offsets were computed from; not a later reread
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
	// Why says why a kill is Unconfirmed, or why a witness kill came back
	// KilledBySelfReport from its repeat.
	Why string
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
	// Hung says an Unconfirmed result's last tries all hung, with each failed
	// package alone, so nothing shows the red was a flake or the mutant's.
	Hung bool

	// Hint says what to do about an Invalid or Unconfirmed result, when cross
	// can tell.
	Hint string
	// EvidenceFile is where the full go test -json output was kept, if
	// Options.EvidenceDir is set. RepeatEvidence is the same for each run with the
	// mutant after the first, in order: a verdict can rest on one of those.
	EvidenceFile   string
	RepeatEvidence []string
	Output         string // tail of go output, for Survived/Invalid
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
// TagTestimony). A witness tag counts only with the harness's mark on it
// (internal/crossmark): a test reports a witness of its own through
// harness.WitnessErrorf, and the same text printed by anything else is Other. An
// untagged message is Other too: an exit code, an audit row, a target record, or
// output.
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
	Markers           int    // statement and guard markers in the source of the mutated files
	// Unplaced lists, as file:line, markers in those files that made no mutant.
	Unplaced []string
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
	// RequireWitness accepts kills only when a package's first failure is witness
	// evidence, and a test of that run gives witness evidence on the repeat too.
	RequireWitness bool
	Target         string // directory to cross-examine, inside a Go module
	// Timeout bounds each go command; 5 minutes if zero. A kill is a build and
	// 1+killRepeats+killReruns test commands, one more for a green first run that
	// goes again and for each repeat that crashed or hung, so a mutant can take that
	// many times as long.
	Timeout time.Duration
	Log     io.Writer // progress; io.Discard if nil
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
	noTests  map[string]bool     // packages the baseline showed to have no test to run
	runs     *atomic.Int64       // numbers the evidence files
	key      string              // a sandbox's key until runner.test gives it its own
	run      *runner             // starts every test binary of the run
	modPath  string              // the module's path, as go reads it
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
	o.key = rand.Text()
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
	defer removeTree(tmp)
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
	rep.Markers, rep.Unplaced = markerCount(mutants)
	rep.Snapshot = snapshotOf(mutants)
	groups, err := groupsOf(mutants)
	if err != nil {
		return nil, err
	}

	if err := absoluteReplaces(ctx, root, tmp); err != nil {
		return nil, err
	}
	if o.modPath, err = modulePath(ctx, root); err != nil {
		return nil, err
	}
	if o.run, err = newRunner(ctx, root); err != nil {
		return nil, err
	}
	defer o.run.remove()
	// A GOWORK file inside the module (e.g. go.work.sandbox) was copied along
	// with the tree; point each copy's builds at its own copied file so its
	// `use .` resolves to the mutated tree, not the original.
	// A GOWORK file outside the module can never `use` the temp copy, so it is
	// disabled for the copy's builds.
	inCopy := func(dir string) sandbox {
		sb := sandbox{dir: dir, key: o.key}
		if work := os.Getenv("GOWORK"); work != "" && work != "off" {
			sb.work = "off"
			if rel, err := filepath.Rel(root, work); err == nil && !strings.HasPrefix(rel, "..") {
				sb.work = filepath.Join(dir, rel)
			}
		}
		return sb
	}
	// A tree fresh could not remove goes here, so it ends with the run.
	stale, err := os.MkdirTemp("", "subpoena-cross-stale-")
	if err != nil {
		return nil, err
	}
	defer removeLeftovers(o.Log, stale)
	// Nothing runs in the discovery copy. Each worker has a directory that a
	// fresh copy of it replaces before every run, made after the replaces were
	// rewritten: the same bytes, so the drift check holds, and no case sees what
	// a test left in another. The directory stays, so the build cache holds too.
	var workers []sandbox
	for range max(1, min(o.Jobs, len(mutants))) {
		dir, err := os.MkdirTemp("", "subpoena-cross-")
		if err != nil {
			return nil, err
		}
		defer removeLeftovers(o.Log, dir)
		sb := inCopy(dir)
		sb.template, sb.stale = tmp, stale
		workers = append(workers, sb)
	}
	primary := workers[0]

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
	if err := primary.fresh(); err != nil {
		return nil, err
	}
	var baselineErr error
	baseline, err := o.run.test(ctx, o, primary, "-json", "-count=1", pkgs)
	if err != nil {
		baselineErr = fmt.Errorf("cross: baseline suite is not green, cannot judge mutants: %s", baselineReason(baseline.raw, err))
	}
	if baselineErr != nil {
		return nil, baselineErr //subpoena:enforcement
	}
	o.noTests = noTestPackages(baseline.raw)
	// go test passes a package it has no tests for, but each mutant is built
	// first, so a fault there would come back as every mutant invalid.
	var buildErr error
	if out, err := goIn(ctx, o.Timeout, primary, "build", "-buildvcs=false", pkgs); err != nil {
		buildErr = fmt.Errorf("cross: baseline does not build, cannot judge mutants: %s", tail(out, 20))
	}
	if buildErr != nil {
		return nil, buildErr //subpoena:enforcement
	}

	if o.Select {
		if err := primary.fresh(); err != nil {
			return nil, err
		}
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

// runCase applies the mutants together to a fresh copy of the snapshot, builds
// and runs the suite, and runs a kill's test command again with and without the
// mutants. The first mutant is the Result's Mutant; the rest are With. A
// canceled ctx is an error, never a verdict: the go command it stopped proves
// nothing about the mutant.
//
//subpoena:enforcement_point
func runCase(ctx context.Context, o Options, sb sandbox, pkgs string, ms []Mutant) (res Result, err error) {
	tmp := sb.dir
	res = Result{Mutant: ms[0], With: ms[1:]}
	if err := sb.fresh(); err != nil {
		return res, err
	}
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

	out, err := goIn(ctx, o.Timeout, sb, "build", "-buildvcs=false", pkgs)
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
			out, err = goIn(ctx, o.Timeout, sb, "build", "-buildvcs=false", pkgs)
		}
	}
	var tested testRun
	var testErr error
	var testArgs []string
	var filter string
	if err == nil {
		// -failfast to go test would also skip each package not yet started, as
		// soon as one failed, and which ones that is depends on the build. So go
		// test's own is off, GOFLAGS or not, and each test binary stops by itself.
		testArgs = []string{"-json", "-count=1", "-failfast=false"}
		if filter = runFilter(o.selected, ms); filter != "" {
			testArgs = append(testArgs, "-run", filter)
			fmt.Fprintf(o.Log, "  selected tests: %s\n", filter)
		}
		testArgs = append(testArgs, pkgs, "-args", "-test.failfast")
		tested, testErr = o.run.test(ctx, o, sb, testArgs...)
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
		run, err := tested, testErr
		raw := run.raw
		var ferr error
		if res.EvidenceFile, ferr = keepEvidence(o, ms, "", raw); ferr != nil {
			return res, ferr
		}
		again := len(failEvents(raw)) > 0 || filter == "" && len(quietPackages(raw, o.noTests)) > 0
		if err == nil && again { //subpoena:enforcement_guard false
			// Green with a failed test in it, or with a package that has tests and ran
			// none. -test.failfast is why either can be: a TestMain that calls m.Run
			// again gets a run of nothing, and exit 0, and a first m.Run that threw its
			// output away leaves no fail event to say so. So the run goes again as it
			// would have run, on a fresh copy, as what the first run left there must
			// not turn a survivor red. Red there still has to hold as a kill, so printed
			// text that made a fail event buys only this run. Any other green is a
			// survivor. A selected run does not look for quiet packages: one with no
			// selected test reads the same, and a mutant selection did not kill runs
			// the whole suite next, which comes here with no filter.
			fmt.Fprintf(o.Log, "  green with a failed test in it or a package that ran none; running without -test.failfast\n")
			if err := sb.freshMutant(mutated); err != nil {
				return res, err
			}
			run, err = o.run.test(ctx, o, sb, testArgs[:len(testArgs)-2]...)
			if ctx.Err() != nil {
				return res, fmt.Errorf("cross: run stopped: %w", ctx.Err())
			}
			raw = run.raw
			file, ferr := keepEvidence(o, ms, "-repeat", raw)
			if ferr != nil {
				return res, ferr
			}
			if file != "" {
				res.RepeatEvidence = append(res.RepeatEvidence, file)
			}
		}
		out := testText(raw)
		if err != nil {
			// -test.failfast: one red test is a kill, so the rest of a package's
			// tests need not run. Other packages still run to the end.
			switch {
			case timedOut(out, err) && (orphansOnTimeout || buildFailed(out) || !finishedFailure(raw)):
				res.Outcome, res.Output = TimedOut, tail(out, 20) //subpoena:enforcement
				res.Unfinished = unfinished(raw)
			case buildFailed(out):
				res.Outcome, res.Output = Invalid, tail(out, 20)
			default:
				if timedOut(out, err) {
					fmt.Fprintf(o.Log, "  did not finish, but a package failed and finished; the repeat decides: still running: %s\n", strings.Join(unfinished(raw), ", "))
				}
				ev, msg, crashed := firstFailure(raw, run.key)
				if crashed {
					res.Outcome, res.Output = Crashed, crashOutput(raw, 20) //subpoena:enforcement
				} else {
					res.Outcome, res.Failing = Killed, failingTests(raw)
					res.Evidence, res.FirstFailure = ev, msg
					if ev != EvidenceWitness {
						res.LaterWitness = witnessFailure(raw, run.key)
					}
					if o.RequireWitness && ev != EvidenceWitness {
						res.Outcome = KilledBySelfReport //subpoena:enforcement
					}
					if err := confirmKill(ctx, o, sb, testArgs, run, ms, mutated, &res); err != nil {
						return res, err
					}
				}
			}
		} else {
			res.Outcome, res.Output = Survived, tail(out, 20)
		}
	}
	res.Output = crossmark.Strip(res.Output)
	if res.Outcome == TimedOut && orphansOnTimeout {
		return res, fmt.Errorf("cross: %s timed out, and on this platform its test binary may still be running and could fail later mutants; rerun with a larger -timeout or on a unix host", ms[0].Name())
	}
	return res, nil
}

// confirmKill asks a kill to hold, and says why in res.Why if it does not. A
// failed test's binary must link the mutated code. Then the mutant run's whole
// command runs again with the mutant on a fresh copy, killRepeats times: the run
// must be a clean kill again with a test of the first run among the failed, or
// the red was not the mutant's. The copy is fresh because a flake that left a file
// behind would otherwise confirm itself. The command is whole because a failure
// can need a test in another package, and it has no -failfast because a test that
// catches the mutant is then sure to run, whatever test stopped the first run:
// under -shuffle another can come first. If a package of the repeat died or the
// run hung, that says nothing of the tests it took with it, so lastTries goes, each
// by the same rule: a flake still has to fail twice in one test. Under RequireWitness a test of the first run must give witness evidence
// on the repeat too, wherever it ran, or only one of the two runs had any. Then
// killReruns runs without the mutant, each on a fresh copy and without -test.failfast
// (rerunArgs): the first the whole command, and the rest the failed packages. One
// that fails or does not finish was red for a reason other than the mutant, or may
// have been.
//
//subpoena:enforcement_point
func confirmKill(ctx context.Context, o Options, sb sandbox, args []string, run testRun, ms []Mutant, mutated map[string][]byte, res *Result) error {
	failed := failedPackages(run.raw)
	why, err := linksMutant(ctx, o, sb, failed, ms)
	if err != nil {
		return err
	}
	if why != "" {
		res.Why, res.Hint = why, separateProgramHint
		res.Outcome = Unconfirmed //subpoena:enforcement
		return nil
	}
	whole := args[:max(0, len(args)-2)] // without -test.failfast
	withMutant := func(a []string) (testRun, error, error) {
		if err := sb.freshMutant(mutated); err != nil {
			return testRun{}, nil, err
		}
		out, runErr := o.run.test(ctx, o, sb, a...)
		if ctx.Err() != nil {
			return testRun{}, nil, fmt.Errorf("cross: run stopped: %w", ctx.Err())
		}
		file, err := keepEvidence(o, ms, "-repeat", out.raw)
		if err != nil {
			return testRun{}, nil, err
		}
		if file != "" {
			res.RepeatEvidence = append(res.RepeatEvidence, file)
		}
		return out, runErr, nil
	}
	first := failedTests(run.raw, run.key)
	if len(first) == 0 && passAfterFail(run.raw) {
		// -test.failfast can make the PASS: a TestMain that calls m.Run again gets a
		// run of nothing, which says it after a real failure. So the failed tests come
		// from the run as it would have gone, by the same rules, and the repeat below
		// still has to fail one of them. A binary that says PASS there too gives none.
		fmt.Fprintf(o.Log, "  a package failed a test and said PASS; running without -test.failfast\n")
		out, _, err := withMutant(whole)
		if err != nil {
			return err
		}
		first = failedTests(out.raw, out.key)
	}
	for n := range killRepeats {
		fmt.Fprintf(o.Log, "  repeat %d of %d with the mutant\n", n+1, killRepeats)
		out, runErr, err := withMutant(whole)
		if err != nil {
			return err
		}
		why := notAKill(out.raw, runErr, out.key, first)
		hung := false // every last try hung
		asked := o.RequireWitness && res.Outcome == Killed
		reason := why
		if why == "" && asked {
			if ev, _ := repeatEvidence(out.raw, out.key, first); ev != EvidenceWitness {
				reason = "no test of the first run gave witness evidence on the repeat"
			}
		}
		if reason != "" && stoppedShort(out.raw, runErr, out.key) {
			// With no -failfast the repeat reaches tests the first run never did,
			// and the mutant can crash or hang one of them, or -shuffle can put one
			// first. That says nothing of the test that failed, so that test
			// decides. The first run's own command goes first, as the test can need
			// what ran before it. Then the test goes alone, with what can crash it
			// left out, for when the command too reaches that crash.
			fmt.Fprintf(o.Log, "  %s; running the first run's command again, then its failed tests\n", reason)
			hung = true
			for _, a := range lastTries(args, run.raw, first) {
				again, againErr, err := withMutant(a)
				if err != nil {
					return err
				}
				if r := notAKill(again.raw, againErr, again.key, first); r != "" {
					// A try that finished says more than one that hung.
					if r != noFinish {
						hung = false
						if why == noFinish {
							why = r
						}
					}
					continue
				}
				out, why = again, ""
				if ev, _ := repeatEvidence(again.raw, again.key, first); !asked || ev == EvidenceWitness {
					break
				}
			}
		}
		if why != "" {
			res.Why, res.Output = why, tail(testText(out.raw), 20)
			res.Outcome = Unconfirmed //subpoena:enforcement
			res.Hung = hung || why == noFinish
			return nil
		}
		if asked {
			if ev, msg := repeatEvidence(out.raw, out.key, first); ev != EvidenceWitness {
				res.Evidence, res.FirstFailure = ev, msg
				res.Why, res.Output = "the first run's first evidence was witness, and no test of that run gave any on the repeat", tail(testText(out.raw), 20)
				res.Outcome = KilledBySelfReport //subpoena:enforcement
			}
		}
	}
	for n := range killReruns {
		if err := sb.fresh(); err != nil {
			return err
		}
		fmt.Fprintf(o.Log, "  rerun %d of %d without the mutant\n", n+1, killReruns)
		out, err := o.run.test(ctx, o, sb, rerunArgs(args, failed, n)...)
		if ctx.Err() != nil {
			return fmt.Errorf("cross: run stopped: %w", ctx.Err())
		}
		if err != nil {
			res.Why, res.Output = "the suite failed without the mutant", tail(testText(out.raw), 20)
			res.Outcome = Unconfirmed //subpoena:enforcement
			return nil
		}
	}
	return nil
}

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
	passed bool // it has a pass event of its own: one with no test files has a skip
	tests  bool // a Test or a Fuzz ran
	shown  bool // m.Run's output reached go test: an Example ran, or noTestsLine
}

// packageTests reads testsSeen from raw. An Example is not a test here: package
// testing stops Tests and Fuzz seeds under -test.failfast and runs Examples anyway,
// so a second m.Run after a real failure can show them and nothing else.
func packageTests(raw string) map[string]testsSeen {
	seen := map[string]testsSeen{}
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test, Output string }
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		s := seen[e.Package]
		switch {
		case e.Action == "run" && exampleRE.MatchString(e.Test):
			s.shown = true
		case e.Action == "run":
			s.tests = true
		case e.Action == "output" && e.Test == "" && e.Output == noTestsLine:
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
// so it pays for a run it may not need. That is the side to lose on.
func noTestPackages(raw string) map[string]bool {
	none := map[string]bool{}
	for pkg, s := range packageTests(raw) {
		if s.passed && !s.tests && s.shown {
			none[pkg] = true
		}
	}
	return none
}

// quietPackages lists the packages of a green run that have tests and ran none,
// sorted. That is all a kill looks like when a first m.Run's output went nowhere and
// -test.failfast stopped the second. Any other package ran its tests where go test
// could see them, so its green is what it says. A package with no test files has a
// skip and no pass, and noTests is the baseline's packages with no test: their events
// are the same as this signature's. A TestMain that prints a framed run line can hide
// the signature, as it can print a test's whole run: see docs/architecture.md.
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
// the sequential tests around it. Subtests started from goroutines do, with no pause or
// cont. A parallel subtest ends a little after the next one continues, so this can say
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
func (e ending) holds(c ending) bool {
	if !e.ran || c.start < e.start || c.last() > e.last() || c.failed && !e.failed {
		return false
	}
	return e.paused == 0 || c.start < e.paused || c.start > e.from && e.from > 0
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
// line as a crash wherever it sits. The cost: a passing test that prints such a line
// at the start of a line, beside a witness failure in its package, reads crashed.
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
				mk, ok, err := parseMarker(markerText(src, fset.Position(c.Pos()).Offset, c.Text))
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
				Func: fd.Name.Name, File: filepath.ToSlash(rel), Line: line, Upstream: upstreamLine(src, line),
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
			if strayMarker(src, fset.Position(c.Pos()).Offset, c.Text) && !placed[c] && stray == nil {
				stray = fmt.Errorf("cross: %s:%d: %q is not a marker cross applies: statement and guard markers belong inside a //%s function, and the point marker on a function's doc comment; %s", rel, fset.Position(c.Pos()).Line, c.Text, MarkerEnforcementPoint, proseHint)
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
	if !tailReturn(body.List, ret) {
		return "", end //subpoena:enforcement
	}
	return "return " + strings.Join(zeros, ", "), end
}

// tailReturn reports whether ret is one the function cannot end without: it
// ends list, or a branch of the statement that ends list, by the language's
// rule for a terminating statement. Any other return can go. In a group with one
// that cannot, the compiler names the same function end for both, and a stand-in
// here would stop the mutant where it must carry on.
func tailReturn(list []ast.Stmt, ret *ast.ReturnStmt) bool {
	if len(list) == 0 {
		return false
	}
	clauses := func(body *ast.BlockStmt) bool {
		return slices.ContainsFunc(body.List, func(s ast.Stmt) bool {
			switch c := s.(type) {
			case *ast.CaseClause:
				return tailReturn(c.Body, ret)
			case *ast.CommClause:
				return tailReturn(c.Body, ret)
			}
			return false
		})
	}
	switch s := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return s == ret
	case *ast.BlockStmt:
		return tailReturn(s.List, ret)
	case *ast.LabeledStmt:
		return tailReturn([]ast.Stmt{s.Stmt}, ret)
	case *ast.IfStmt:
		return tailReturn(s.Body.List, ret) || s.Else != nil && tailReturn([]ast.Stmt{s.Else}, ret)
	case *ast.SwitchStmt:
		return clauses(s.Body)
	case *ast.TypeSwitchStmt:
		return clauses(s.Body)
	case *ast.SelectStmt:
		return clauses(s.Body)
	}
	return false
}

// errorRefusal reports whether a return's only news is an error, so that its
// zero values turn a possible refusal into nil and change nothing else. Every
// other result must already be plainly zero: a value beside the error can carry
// the decision. A call in the error can be the work itself (return
// s.Authorize(admins) opens the session), so the stand-in would drop what the
// allowed path needs. Cross cannot see what a call does, so that holds for
// fmt.Errorf too. A bare return, and one call spread over the results, say
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
		if !isError[i] || doesWork(e) {
			return false
		}
		refusal = true
	}
	return refusal
}

// doesWork reports whether evaluating e can do anything: a call, or a receive.
func doesWork(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			found = true
		case *ast.UnaryExpr:
			found = found || x.Op == token.ARROW
		}
		return !found
	})
	return found
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
	anyMarkerRE   = regexp.MustCompile(`^//\s*subpoena\s*:\s*enforc`)
	// ownMarkerRE is anyMarkerRE for a comment on a line of its own, where a space
	// by the colon says prose: subpoena: enforcement points are listed in docs.
	ownMarkerRE = regexp.MustCompile(`^//\s*subpoena:enforc`)
	// nearMarkerRE reads a comment in a marker's shape: two words about a colon,
	// and arguments that nearMarker checks. A comment that goes on is prose.
	nearMarkerRE = regexp.MustCompile(`^//\s*([A-Za-z]+)\s*:\s*([A-Za-z_]+)((?:\s+\S+)*)\s*$`)
	// trailingRE finds a marker after an upstream comment on a line of code, as
	// loosely as anyMarkerRE, so a misspelt one there is an error too:
	// return nil // why //subpoena:enforcement
	trailingRE = regexp.MustCompile(`//\s*subpoena\s*:\s*enforc`)
	// onlyMarkerRE reads source lines: the lines marking added.
	onlyMarkerRE = regexp.MustCompile(`^\s*//\s*subpoena:enforcement`)
	// directiveRE is go/ast's form of a directive, as //go:noinline.
	directiveRE = regexp.MustCompile(`^//[a-z0-9]+:[a-z0-9]`)
)

// proseHint ends a marker error, since cross cannot tell the two apart.
const proseHint = "a comment that starts with a marker, or names one on a line of code, reads as one, so if this is prose, reword it"

// markerText is a comment's marker, or its text if it has none. On a line of
// code that is the end of the comment when a marker follows upstream's text, so
// marking a line removes none of it. Arguments stay, so a bad one is an error. A
// comment on a line of its own that mentions a marker is prose, and so is one that
// names the point marker, which no line of code can carry.
func markerText(src []byte, offset int, text string) string {
	if ownLine(src, offset) || !strings.HasPrefix(text, "//") {
		return text
	}
	for _, loc := range trailingRE.FindAllStringIndex(text, -1) {
		if found := strings.TrimSpace(text[loc[0]:]); !pointRE.MatchString(found) {
			return found
		}
	}
	for i := range text {
		if strings.HasPrefix(text[i:], "//") && nearMarker(text[i:]) && !pointRE.MatchString(text[i:]) {
			return text[i:]
		}
	}
	return text
}

// ownLine reports whether nothing comes before offset on its line.
func ownLine(src []byte, offset int) bool {
	start := bytes.LastIndexByte(src[:offset], '\n') + 1
	return len(bytes.TrimSpace(src[start:offset])) == 0
}

// strayMarker reports whether a comment reads as a marker. One that took no
// effect is an error, so this must not catch prose where it can tell: on a line
// of its own a comment is one only if it is written as a marker is, or nearMarker
// says it is. On a line of code the words alone are enough, since a mark goes after
// upstream's text there.
func strayMarker(src []byte, offset int, text string) bool {
	text = markerText(src, offset, text)
	if nearMarker(text) {
		return true
	}
	if ownLine(src, offset) {
		return ownMarkerRE.MatchString(text)
	}
	return anyMarkerRE.MatchString(text)
}

// nearMarker reports whether text is a marker with its words in the wrong case or
// with two letters swapped, in a marker's shape and with nothing but a marker's
// arguments after them, so a sentence that opens with those words is no match.
func nearMarker(text string) bool {
	m := nearMarkerRE.FindStringSubmatch(text)
	if m == nil {
		return false
	}
	for _, arg := range strings.Fields(m[3]) {
		if arg != "true" && arg != "false" && !strings.HasPrefix(arg, "group=") {
			return false
		}
	}
	return swapped(strings.ToLower(m[1]), func(s string) bool { return s == "subpoena" }) &&
		swapped(strings.ToLower(m[2]), func(s string) bool { return strings.HasPrefix(s, "enforc") })
}

// swapped reports whether s, or s with two neighbouring letters swapped, is ok.
func swapped(s string, ok func(string) bool) bool {
	if ok(s) {
		return true
	}
	b := []byte(s)
	for i := 0; i+1 < len(b); i++ {
		b[i], b[i+1] = b[i+1], b[i]
		if ok(string(b)) {
			return true
		}
		b[i], b[i+1] = b[i+1], b[i]
	}
	return false
}

// upstreamLine is line with the lines marking added above it taken out: a
// marker-only line, and the empty // gofmt puts before one in a doc comment. That
// // stays if a directive follows the marker: gofmt wants it there anyway.
func upstreamLine(src []byte, line int) int {
	up := line
	lines := bytes.Split(src, []byte("\n"))
	for i := 0; i < line-1 && i < len(lines); i++ {
		if !onlyMarkerRE.Match(lines[i]) {
			continue
		}
		up--
		if i > 0 && string(bytes.TrimSpace(lines[i-1])) == "//" && !beforeDirective(lines, i) {
			up--
		}
	}
	return up
}

// beforeDirective reports whether the first line after the marker-only lines from
// line i on is a directive.
func beforeDirective(lines [][]byte, i int) bool {
	for i < len(lines) && onlyMarkerRE.Match(lines[i]) {
		i++
	}
	return i < len(lines) && directiveRE.Match(bytes.TrimSpace(lines[i]))
}

// markerCount counts the statement and guard markers in the comments of the
// mutated files, and names those that made no mutant. A marker that took no effect
// is an error where cross can tell; this is for what it cannot. The parser says
// what a comment is: a block comment or a string that shows a marker holds none.
func markerCount(ms []Mutant) (int, []string) {
	lines := map[string]map[int]bool{}
	src := map[string][]byte{}
	for _, m := range ms {
		if lines[m.File] == nil {
			lines[m.File], src[m.File] = map[int]bool{}, m.src
		}
		lines[m.File][m.Line] = true
	}
	n := 0
	var unplaced []string
	for _, file := range slices.Sorted(maps.Keys(src)) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, src[file], parser.ParseComments)
		if err != nil {
			continue // discovery parsed these bytes
		}
		for _, g := range f.Comments {
			for _, c := range g.List {
				at := fset.Position(c.Pos())
				text := markerText(src[file], at.Offset, c.Text)
				if enforcementRE.MatchString(text) || guardRE.MatchString(text) {
					n++
					if !lines[file][at.Line] {
						unplaced = append(unplaced, fmt.Sprintf("%s:%d", file, at.Line))
					}
				}
			}
		}
	}
	return n, unplaced
}

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
			return mk, false, fmt.Errorf("marker argument %q: want at most one group=<name>; %s", a, proseHint) //subpoena:enforcement
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
const finalReturnHint = "the function cannot end without this return, and cross replaces one only where that plainly turns an error to nil, so no mutant can stand in for it; " +
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

// sandbox is one copy of the module that mutants are run in, the GOWORK its go
// commands use ("" to inherit the environment's), the discovery copy it is made
// from, the run's directory for trees it could not remove, and the run's key.
type sandbox struct {
	dir, work, template, stale string
	key                        string // handed to test binaries, to sign witness failures
}

// fresh replaces the copy with the discovery copy, so a run sees nothing an
// earlier run left. The path stays: the go build cache keys on it.
func (sb sandbox) fresh() error {
	if err := removeTree(sb.dir); err != nil {
		// A detached child can still be writing there. Move the tree aside, into
		// the run's own directory, and the child writes on unseen until the run
		// ends and removeLeftovers takes it.
		aside, terr := os.MkdirTemp(sb.stale, "copy-")
		if terr != nil {
			return fmt.Errorf("cross: reset copy: %w", err)
		}
		if rerr := os.Rename(sb.dir, filepath.Join(aside, "copy")); rerr != nil {
			return fmt.Errorf("cross: reset copy: %w", err)
		}
	}
	if err := copyTree(sb.template, sb.dir); err != nil {
		return fmt.Errorf("cross: copy tree: %w", err)
	}
	return nil
}

// freshMutant is fresh with the mutated files written back.
func (sb sandbox) freshMutant(mutated map[string][]byte) error {
	if err := sb.fresh(); err != nil {
		return err
	}
	for file, b := range mutated {
		if err := os.WriteFile(filepath.Join(sb.dir, filepath.FromSlash(file)), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// removeLeftovers removes a tree of the run as it ends. A detached child can be
// writing there, and each try can lose to it, but a tree that goes once is gone:
// the child's directory went with it. The tree holds mutated source, so one that
// will not go is named.
func removeLeftovers(log io.Writer, dir string) {
	for range removeTries {
		if removeTree(dir) == nil {
			return
		}
		time.Sleep(removeWait)
	}
	fmt.Fprintf(log, "cross: could not remove %s, which holds mutated source: a process a test started may still be writing there\n", dir)
}

// removeTries and removeWait bound removeLeftovers.
const (
	removeTries = 50
	removeWait  = 100 * time.Millisecond
)

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
	env := append(os.Environ(), crossmark.Env+"="+sb.key)
	if sb.work != "" {
		env = append(env, "GOWORK="+sb.work)
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

// buildRE matches go test's own line. The text alone can be anything a test or a
// panic printed.
var buildRE = regexp.MustCompile(`(?m)^FAIL\s+\S+\s+\[(build|setup) failed\]$`)

func buildFailed(out string) bool { return buildRE.MatchString(out) }

// failingTests names the tests that failed in raw, from their fail events.
func failingTests(raw string) []string {
	var names []string
	for _, e := range failEvents(raw) {
		if !slices.Contains(names, e.Test) {
			names = append(names, e.Test)
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
