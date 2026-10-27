// Package cross implements cross-examination. For each enforcement point it builds
// a mutant with the enforcement statement removed and requires that the test
// suite goes red. A suite that stays green cannot tell enforced from
// unenforced behaviour, whatever its spans say.
//
// v0 locates the statement to remove with a second marker: a comment
// //subpoena:enforcement on the statement's first line, inside a function
// marked //subpoena:enforcement_point.
package cross

import (
	"bytes"
	"context"
	"encoding/json"
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
	"time"
)

// Markers.
const (
	MarkerEnforcementPoint = "subpoena:enforcement_point"
	MarkerEnforcement      = "subpoena:enforcement"
)

// Outcome of one mutant.
type Outcome string

const (
	// Killed means the mutant made the suite fail: the enforcement is covered.
	Killed Outcome = "enforcement-mutant-killed"
	// Survived means the suite stayed green with enforcement removed.
	Survived Outcome = "enforcement-mutant-survived"
	// Invalid means the mutant did not compile; it proves nothing either way.
	Invalid Outcome = "enforcement-mutant-invalid"
)

// Mutant is one planned removal.
type Mutant struct {
	Func    string // enclosing function name
	File    string // path relative to the module root
	Line    int
	Removed string // the source text removed
	start   int    // byte offsets of the statement in File
	end     int
	point   int // byte offset of the enclosing function declaration in File
}

// Result is the outcome of running one mutant.
type Result struct {
	Mutant  Mutant
	Outcome Outcome
	Failing []string // names of failing tests, for Killed
	Output  string   // tail of go output, for Survived/Invalid
}

// Report is the outcome of a whole cross-examination.
type Report struct {
	ModuleRoot        string
	Target            string // target directory relative to the module root
	EnforcementPoints int    // functions marked //subpoena:enforcement_point
	Results           []Result
}

// Failed reports whether any mutant survived or was invalid.
//
//subpoena:enforcement_point
func (r *Report) Failed() bool {
	for _, x := range r.Results {
		if x.Outcome != Killed {
			return true //subpoena:enforcement
		}
	}
	return false
}

// Options configure a run.
type Options struct {
	Target  string        // directory to cross-examine, inside a Go module
	Timeout time.Duration // per go command; 5 minutes if zero
	Log     io.Writer     // progress; io.Discard if nil
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

	mutants, err := FindMutants(root, target)
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

	tmp, err := os.MkdirTemp("", "subpoena-cross-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyTree(root, tmp); err != nil {
		return nil, fmt.Errorf("cross: copy tree: %w", err)
	}
	if err := absoluteReplaces(ctx, root, tmp); err != nil {
		return nil, err
	}
	// A GOWORK file inside the module (e.g. go.work.sandbox) was copied along
	// with the tree; point the copy's builds at the copied file so its `use .`
	// resolves to the mutated tree, not the original.
	// A GOWORK file outside the module can never `use` the temp copy, so it is
	// disabled for the copy's builds.
	if work := os.Getenv("GOWORK"); work != "" && work != "off" {
		defer os.Setenv("GOWORK", work)
		if rel, err := filepath.Rel(root, work); err == nil && !strings.HasPrefix(rel, "..") {
			os.Setenv("GOWORK", filepath.Join(tmp, rel))
		} else {
			os.Setenv("GOWORK", "off")
		}
	}

	pkgs := "./" + rep.Target + "/..."
	if rep.Target == "." {
		pkgs = "./..."
	}
	fmt.Fprintf(o.Log, "baseline: go test %s\n", pkgs)
	// The verdict is kept apart from the return so that cross-examining
	// this function (make cross-self) can remove the return and still compile.
	var baselineErr error
	if out, err := goCmd(ctx, o.Timeout, tmp, "test", "-count=1", pkgs); err != nil {
		baselineErr = fmt.Errorf("cross: baseline suite is not green, cannot judge mutants:\n%s", tail(out, 40))
	}
	if baselineErr != nil {
		return nil, baselineErr //subpoena:enforcement
	}

	for _, m := range mutants {
		path := filepath.Join(tmp, filepath.FromSlash(m.File))
		orig, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m.File)))
		if err != nil {
			return nil, err
		}
		mutated := append(append(append([]byte{}, orig[:m.start]...), []byte("/* removed by subpoena-cross */")...), orig[m.end:]...)
		if err := os.WriteFile(path, mutated, 0o644); err != nil {
			return nil, err
		}
		fmt.Fprintf(o.Log, "mutant: %s (%s:%d) removed %q\n", m.Func, m.File, m.Line, oneLine(m.Removed))

		res := Result{Mutant: m}
		out, err := goCmd(ctx, o.Timeout, tmp, "build", pkgs)
		if err != nil {
			// Removing the statement may leave an import unused (the removed
			// line was its only use); drop those imports and build again.
			if pruned, ok := pruneUnusedImports(mutated, m.File, out); ok {
				if err := os.WriteFile(path, pruned, 0o644); err != nil {
					return nil, err
				}
				out, err = goCmd(ctx, o.Timeout, tmp, "build", pkgs)
			}
		}
		if err != nil {
			res.Outcome, res.Output = Invalid, tail(out, 20) //subpoena:enforcement
		} else if out, err := goCmd(ctx, o.Timeout, tmp, "test", "-count=1", pkgs); err != nil {
			if buildFailed(out) {
				res.Outcome, res.Output = Invalid, tail(out, 20)
			} else {
				res.Outcome, res.Failing = Killed, failingTests(out)
			}
		} else {
			res.Outcome, res.Output = Survived, tail(out, 20)
		}
		rep.Results = append(rep.Results, res)

		if err := os.WriteFile(path, orig, 0o644); err != nil { // restore for the next mutant
			return nil, err
		}
	}
	return rep, nil
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
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Doc == nil || !hasPointMarker(fd.Doc) {
			continue
		}
		found := 0
		// Marker lines inside this function. Both markers share a prefix, so
		// match the exact comment word.
		lines := map[int]bool{}
		for _, g := range f.Comments {
			for _, c := range g.List {
				if c.Pos() > fd.Body.Lbrace && c.End() < fd.Body.Rbrace && isEnforcementComment(c.Text) {
					lines[fset.Position(c.Pos()).Line] = true
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
			if !lines[line] {
				return true
			}
			// Take the outermost statement that starts on the marked line; for
			// `if cond { return x } //marker` that would remove the whole if,
			// so only simple statements are accepted.
			switch st.(type) {
			case *ast.ReturnStmt, *ast.ExprStmt, *ast.AssignStmt, *ast.BranchStmt, *ast.IncDecStmt:
			default:
				return true
			}
			delete(lines, line)
			found++
			s, e := fset.Position(st.Pos()).Offset, fset.Position(st.End()).Offset
			out = append(out, Mutant{
				Func: fd.Name.Name, File: filepath.ToSlash(rel), Line: line,
				Removed: string(src[s:e]), start: s, end: e,
				point: fset.Position(fd.Pos()).Offset,
			})
			return true
		})
		if len(lines) > 0 {
			return nil, fmt.Errorf("cross: %s: //%s in %s is not on a simple statement line", rel, MarkerEnforcement, fd.Name.Name) //subpoena:enforcement
		}
		// An enforcement point with nothing to remove would never be
		// cross-examined, and the run would still go green.
		if found == 0 {
			return nil, fmt.Errorf("cross: %s: %s is marked //%s but has no //%s statement, so it cannot be cross-examined", rel, fd.Name.Name, MarkerEnforcementPoint, MarkerEnforcement) //subpoena:enforcement
		}
	}
	return out, nil
}

var enforcementRE = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerEnforcement) + `(\s|$)`)

func isEnforcementComment(text string) bool { return enforcementRE.MatchString(text) }

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

func goCmd(ctx context.Context, timeout time.Duration, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
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
		names = []string{"(package failed without a named test failure, e.g. panic or timeout)"}
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
