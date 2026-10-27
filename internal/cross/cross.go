// Package cross implements cross-examination. For each enforcement point it builds
// a mutant with the enforcement statement removed and requires that the test
// suite goes red. A suite that stays green cannot tell enforced from
// unenforced behaviour, whatever its spans say.
//
// v0 locates the statement to remove with a second marker: a comment
// //subpoena:enforcement on the statement's first line, inside a function
// marked //subpoena:enforcement_point.
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
}

// Name identifies the mutant in reports: function, file and line.
func (m Mutant) Name() string { return fmt.Sprintf("%s (%s:%d)", m.Func, m.File, m.Line) }

// replacement is the text the mutant puts in place of Removed. A forced
// condition keeps the original expression, so variables it uses stay used.
func (m Mutant) replacement() string {
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
	// EvidenceFile is where the full go test -json output was kept, if
	// Options.EvidenceDir is set.
	EvidenceFile string
	Output       string // tail of go output, for Survived/Invalid
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
//	<file> | <func> | <removed text or condition> | <reason>
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
	Target  string        // directory to cross-examine, inside a Go module
	Timeout time.Duration // per go command, and so per mutant run; 5 minutes if zero
	Log     io.Writer     // progress; io.Discard if nil
	// EvidenceDir, if set, keeps the full go test -json output of every
	// mutant run there, killed ones included, one file per run.
	EvidenceDir string
	// Jobs is how many single mutants run at once, each in its own copy of
	// the module; 1 if zero. Group runs stay sequential. A polling witness
	// sees less on a busy host, so a higher value can turn a kill into a
	// survivor (which fails the run), never the reverse.
	Jobs int
	runs *atomic.Int64 // numbers the evidence files
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
	for i := 1; i < o.Jobs; i++ {
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
	if out, err := goIn(ctx, o.Timeout, primary, "test", "-count=1", pkgs); err != nil {
		baselineErr = fmt.Errorf("cross: baseline suite is not green, cannot judge mutants:\n%s", tail(out, 40))
	}
	if baselineErr != nil {
		return nil, baselineErr //subpoena:enforcement
	}

	single := map[string]int{} // Mutant.Name() -> index in rep.Results
	results, err := runSingles(ctx, o, workers, pkgs, mutants)
	if err != nil {
		return nil, err
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
		// Removing a statement may leave an import unused (the removed line
		// was its only use); drop those imports and build again.
		pruned := false
		for _, file := range files {
			if b, ok := pruneUnusedImports(mutated[file], file, out); ok {
				if err := os.WriteFile(filepath.Join(tmp, filepath.FromSlash(file)), b, 0o644); err != nil {
					return res, err
				}
				pruned = true
			}
		}
		if pruned {
			out, err = goIn(ctx, o.Timeout, sb, "build", pkgs)
		}
	}
	var testOut string
	var testErr error
	if err == nil {
		testOut, testErr = goIn(ctx, o.Timeout, sb, "test", "-json", "-count=1", "-failfast", pkgs)
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("cross: run stopped: %w", ctx.Err()) //subpoena:enforcement
	}
	if err != nil {
		if timedOut(out, err) {
			res.Outcome, res.Output = TimedOut, tail(out, 20)
		} else {
			res.Outcome, res.Output = Invalid, tail(out, 20) //subpoena:enforcement
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
			case buildFailed(out):
				res.Outcome, res.Output = Invalid, tail(out, 20)
			default:
				ev, msg, crashed := firstFailure(raw)
				if crashed {
					res.Outcome, res.Output = Crashed, tail(out, 20) //subpoena:enforcement
				} else {
					res.Outcome, res.Failing = Killed, failingTests(out)
					res.Evidence, res.FirstFailure = ev, msg
				}
			}
		} else {
			res.Outcome, res.Output = Survived, tail(out, 20)
		}
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

// firstFailure reads go test -json output for the first failure message of
// a test that failed (a skipped or passing test's log lines don't count).
// crashed is true when no failed test gave one cleanly: the binary died by a
// panic, a runtime fatal error or os.Exit, or failed without a message. A
// package whose binary crashed (a crash line from a failed or unfinished
// test, or outside any test) gives no kills at all, since a test's log lines
// before its panic look just like failure messages. t.Log and t.Error print
// the same way, so a failed test's tagged log line can still set ev.
//
//subpoena:enforcement_point
func firstFailure(raw string) (ev Evidence, msg string, crashed bool) {
	type event struct {
		Action, Package, Test, Output string
	}
	type key [2]string
	var evs []event
	failed, ended, crash := map[key]bool{}, map[key]bool{}, map[key]bool{}
	for _, line := range strings.Split(raw, "\n") {
		var e event
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		evs = append(evs, e)
		k := key{e.Package, e.Test}
		switch e.Action {
		case "fail":
			failed[k], ended[k] = true, true
		case "pass", "skip":
			ended[k] = true
		case "output":
			if crashRE.MatchString(e.Output) {
				crash[k] = true
			}
		}
	}
	dead := map[string]bool{}
	for k := range crash {
		if k[1] == "" || failed[k] || !ended[k] {
			dead[k[0]] = true //subpoena:enforcement
		}
	}
	for _, e := range evs {
		if e.Action != "output" || dead[e.Package] || !failed[key{e.Package, e.Test}] {
			continue
		}
		m := failMsgRE.FindStringSubmatch(strings.TrimRight(e.Output, "\n"))
		if m == nil {
			continue
		}
		switch {
		case strings.HasPrefix(m[1], "witness:"):
			return EvidenceWitness, m[1], false
		case strings.HasPrefix(m[1], "testimony:"):
			return EvidenceTestimony, m[1], false
		default:
			return EvidenceOther, m[1], false
		}
	}
	return "", "", true
}

// crashRE matches the first line of a panic or a runtime fatal error.
var crashRE = regexp.MustCompile(`^(panic|fatal error): `)

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
			if !marked {
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

var unusedImportRE = regexp.MustCompile(`(?m)^(?:\./)?(\S+\.go):(\d+):\d+: "[^"]+" imported (?:as \S+ )?and not used`)

// pruneUnusedImports removes from src (the mutated file, at module-relative
// path file) the import lines the compiler output reports as unused, and
// reports whether it removed any. Only lines in the mutated file are touched,
// and only import specs on a line of their own.
func pruneUnusedImports(src []byte, file, buildOut string) ([]byte, bool) {
	drop := map[int]bool{}
	for _, m := range unusedImportRE.FindAllStringSubmatch(buildOut, -1) {
		if filepath.ToSlash(filepath.Clean(m[1])) != filepath.ToSlash(filepath.Clean(file)) && !strings.HasSuffix(filepath.ToSlash(file), "/"+filepath.ToSlash(m[1])) {
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
		f := strings.SplitN(line, " | ", 4)
		if len(f) != 4 || strings.TrimSpace(f[3]) == "" {
			bad = i + 1
			break
		}
		key := maskedKey(strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), f[2])
		if _, dup := reasons[key]; dup {
			bad = i + 1
			break
		}
		reasons[key] = strings.TrimSpace(f[3])
		order = append(order, key)
	}
	if bad > 0 {
		return fmt.Errorf("cross: %s:%d: want <file> | <func> | <removed text> | <reason>, each layer listed once", MaskedFile, bad) //subpoena:enforcement
	}
	// One entry accepts one layer. Two masked layers with the same key (the
	// same text twice in one function) cannot be told apart, so neither is.
	layers := map[string]int{}
	for _, r := range rep.Results {
		if r.Outcome == Masked {
			layers[maskedKey(r.Mutant.File, r.Mutant.Func, r.Mutant.Removed)]++
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
		key := maskedKey(r.Mutant.File, r.Mutant.Func, r.Mutant.Removed)
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

func maskedKey(file, fn, removed string) string {
	return file + " | " + fn + " | " + oneLine(removed)
}
