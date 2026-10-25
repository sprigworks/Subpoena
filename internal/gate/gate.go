// Package gate implements the fault gate. For each enforcement point it builds
// a mutant with the enforcement statement removed and requires that the test
// suite goes red. A suite that stays green cannot tell enforced from
// unenforced behaviour, whatever its spans say.
//
// v0 locates the statement to remove with a second marker: a comment
// //subpoena:enforcement on the statement's first line, inside a function
// marked //subpoena:enforcement_point.
package gate

import (
	"bytes"
	"context"
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
}

// Result is the outcome of running one mutant.
type Result struct {
	Mutant  Mutant
	Outcome Outcome
	Failing []string // names of failing tests, for Killed
	Output  string   // tail of go output, for Survived/Invalid
}

// Report is the outcome of a whole gate run.
type Report struct {
	ModuleRoot string
	Target     string // target directory relative to the module root
	Results    []Result
}

// Failed reports whether any mutant survived or was invalid.
func (r *Report) Failed() bool {
	for _, x := range r.Results {
		if x.Outcome != Killed {
			return true
		}
	}
	return false
}

// Options configure a run.
type Options struct {
	Target  string        // directory to gate, inside a Go module
	Timeout time.Duration // per go command; 5 minutes if zero
	Log     io.Writer     // progress; io.Discard if nil
}

// Run executes the gate.
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
		return nil, fmt.Errorf("gate: no enforcement points with a //%s statement under %s; the gate would be vacuous", MarkerEnforcement, o.Target)
	}

	tmp, err := os.MkdirTemp("", "subpoena-gate-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyTree(root, tmp); err != nil {
		return nil, fmt.Errorf("gate: copy tree: %w", err)
	}

	pkgs := "./" + rep.Target + "/..."
	if rep.Target == "." {
		pkgs = "./..."
	}
	fmt.Fprintf(o.Log, "baseline: go test %s\n", pkgs)
	if out, err := goCmd(ctx, o.Timeout, tmp, "test", "-count=1", pkgs); err != nil {
		return nil, fmt.Errorf("gate: baseline suite is not green, cannot judge mutants:\n%s", tail(out, 40))
	}

	for _, m := range mutants {
		path := filepath.Join(tmp, filepath.FromSlash(m.File))
		orig, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m.File)))
		if err != nil {
			return nil, err
		}
		mutated := append(append(append([]byte{}, orig[:m.start]...), []byte("/* removed by subpoena-gate */")...), orig[m.end:]...)
		if err := os.WriteFile(path, mutated, 0o644); err != nil {
			return nil, err
		}
		fmt.Fprintf(o.Log, "mutant: %s (%s:%d) removed %q\n", m.Func, m.File, m.Line, oneLine(m.Removed))

		res := Result{Mutant: m}
		if out, err := goCmd(ctx, o.Timeout, tmp, "build", pkgs); err != nil {
			res.Outcome, res.Output = Invalid, tail(out, 20)
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
// marked //subpoena:enforcement_point, in non-test files under target.
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
		if !ok || fd.Body == nil || fd.Doc == nil || !strings.Contains(commentText(fd.Doc), MarkerEnforcementPoint) {
			continue
		}
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
			s, e := fset.Position(st.Pos()).Offset, fset.Position(st.End()).Offset
			out = append(out, Mutant{
				Func: fd.Name.Name, File: filepath.ToSlash(rel), Line: line,
				Removed: string(src[s:e]), start: s, end: e,
			})
			return true
		})
		if len(lines) > 0 {
			return nil, fmt.Errorf("gate: %s: //%s in %s is not on a simple statement line", rel, MarkerEnforcement, fd.Name.Name)
		}
	}
	return out, nil
}

var enforcementRE = regexp.MustCompile(`^//\s*` + regexp.QuoteMeta(MarkerEnforcement) + `(\s|$)`)

func isEnforcementComment(text string) bool { return enforcementRE.MatchString(text) }

func commentText(g *ast.CommentGroup) string {
	var b strings.Builder
	for _, c := range g.List {
		b.WriteString(c.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

func moduleRoot(dir string) (string, error) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("gate: no go.mod above %s", dir)
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
