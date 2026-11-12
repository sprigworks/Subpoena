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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// Total is the number of mutants discovery found. A sharded run judges
	// only its share of them; Shard and Shards (1-based) say which, and are
	// zero when the run is not sharded.
	Total         int
	Shard, Shards int
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
	// goes again, for a first run that said PASS after a failure and left no failed
	// test, and for each repeat that crashed or hung, so a mutant can take that many
	// times as long.
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
	// Shard and Shards, when Shards > 0, judge only shard Shard of Shards
	// (1-based) of the mutants: see shardOf. Every shard of one snapshot
	// splits the mutants the same way, so the shards together judge each once.
	Shard, Shards int
	noTests       map[string]bool // packages the baseline showed to have no test to run
	runs          *atomic.Int64   // numbers the evidence files
	key           string          // a sandbox's key until runner.test gives it its own
	run           *runner         // starts every test binary of the run
	modPath       string          // the module's path, as go reads it
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
	rep.Total = len(mutants)
	var elsewhere map[string]bool
	if o.Shards > 0 {
		if mutants, elsewhere, err = shardOf(mutants, o.Shard, o.Shards); err != nil {
			return nil, err
		}
		for g := range elsewhere {
			delete(groups, g)
		}
		rep.Shard, rep.Shards = o.Shard, o.Shards
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
	if err := acceptMasked(rep, filepath.Join(tmp, rel, MaskedFile), elsewhere); err != nil {
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
			res.Why, res.Output = why, redOutput(out)
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
			res.Why, res.Output = "the suite failed without the mutant", redOutput(out)
			res.Outcome = Unconfirmed //subpoena:enforcement
			return nil
		}
	}
	return nil
}
