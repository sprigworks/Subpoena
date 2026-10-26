// Package lint implements subpoena-lint: static checks that keep a codebase's
// tests and telemetry honest. It uses go/ast only; precision is traded for a
// simple, readable structure, one function per rule.
package lint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule names.
const (
	RuleUnknownTelemetry       = "unknown-telemetry"
	RuleNoTraceAssertion       = "no-trace-assertion"
	RuleUnwitnessedEnforcement = "unwitnessed-enforcement"
	RuleUnguardedAbsence       = "unguarded-absence"
	RuleMissingProvenance      = "missing-provenance"
	RuleOrphanInvariant        = "orphan-invariant"
	RuleRegistryDrift          = "registry-drift"
)

// Markers recognised in source comments.
const (
	MarkerEnforcementPoint = "subpoena:enforcement_point"
)

// witnessMethods are the method names that count as "calling a Witness".
var witnessMethods = map[string]bool{"Spawned": true}

// absenceCalls are the names of absence-assertion helpers.
var absenceCalls = map[string]bool{"RequireAbsent": true, "Absent": true}

// spanStartMethods take the span name as argument index 1: tracer.Start(ctx, name).
// attributeCtors take the attribute key as argument 0: attribute.String(key, v).
var attributeCtors = map[string]bool{
	"String": true, "Bool": true, "Int": true, "Int64": true, "Float64": true,
	"StringSlice": true, "BoolSlice": true, "IntSlice": true, "Int64Slice": true, "Float64Slice": true,
}

// enumValuePrefix marks generated constants for the members of enum-typed
// attributes (ValSubpoenaWitnessCorrelationCgroup). They are valid Go names to
// reference but their values are not telemetry names.
const enumValuePrefix = "Val"

var provenanceRE = regexp.MustCompile(`^//\s*subpoena:(spec_derived|impl_derived)\b`)

// pureLogicRE marks a test file that holds only pure-logic tests, which have
// no telemetry to collect; it exempts the file from no-trace-assertion.
var pureLogicRE = regexp.MustCompile(`^//\s*subpoena:pure_logic\b`)

// telemetryImportPrefixes and telemetryImportSuffixes identify imports a
// pure_logic file may not have: the OpenTelemetry API and SDK, and Subpoena's
// harness, witness, generated names and invariants (matched by suffix, so a
// service that copied them under its own module path is covered too).
var (
	telemetryImportPrefixes = []string{"go.opentelemetry.io/"}
	telemetryImportSuffixes = []string{"/pkg/harness", "/pkg/witness", "/generated/go/semconv", "/invariants"}
)

// Finding is one lint result.
type Finding struct {
	Rule string
	Pos  token.Position
	Msg  string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d:%d: %s: %s", f.Pos.Filename, f.Pos.Line, f.Pos.Column, f.Rule, f.Msg)
}

// Registry is the set of telemetry names the generated semconv package defines.
type Registry struct {
	Values  map[string]bool   // string values: span names and attribute keys (not enum member values)
	Names   map[string]bool   // Go identifiers: SpanAgentSessionOpen, AttrSessionId, ...
	ByValue map[string]string // value -> Go identifier ("session.id" -> "AttrSessionId")
}

// LoadRegistry reads the string constants of the generated semconv package in dir.
func LoadRegistry(dir string) (*Registry, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("lint: load registry %s: %w", dir, err)
	}
	r := &Registry{Values: map[string]bool{}, Names: map[string]bool{}, ByValue: map[string]string{}}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						val, err := strconv.Unquote(lit.Value)
						if err != nil {
							continue
						}
						r.Names[id.Name] = true
						if strings.HasPrefix(id.Name, enumValuePrefix) {
							// An enum member's value ("cgroup") is not a span name or
							// attribute key, so it must not make a literal acceptable.
							continue
						}
						r.Values[val] = true
						r.ByValue[val] = id.Name
					}
				}
			}
		}
	}
	if len(r.Names) == 0 {
		return nil, fmt.Errorf("lint: no string constants found in registry package %s", dir)
	}
	return r, nil
}

type file struct {
	path   string
	ast    *ast.File
	isTest bool
}

type tree struct {
	fset  *token.FileSet
	files []file
}

// Options tune a Run.
type Options struct {
	// InvariantsDir is the directory of *.traceql invariants used by
	// orphan-invariant. If empty it is found by walking up from each root; if
	// none exists the invariant set is empty, so every TraceQL literal is an orphan.
	InvariantsDir string
}

// Run lints every .go file under each root and returns findings sorted by position.
func Run(roots []string, reg *Registry) ([]Finding, error) { return RunWith(roots, reg, Options{}) }

// RunWith is Run with explicit Options.
func RunWith(roots []string, reg *Registry, opts Options) ([]Finding, error) {
	var out []Finding
	for _, root := range roots {
		t, err := load(root)
		if err != nil {
			return nil, err
		}
		out = append(out, checkUnknownTelemetry(t, reg)...)
		out = append(out, checkNoTraceAssertion(t)...)
		out = append(out, checkUnwitnessedEnforcement(t)...)
		out = append(out, checkUnguardedAbsence(t)...)
		out = append(out, checkMissingProvenance(t)...)
		invs, err := loadInvariants(root, opts.InvariantsDir)
		if err != nil {
			return nil, err
		}
		out = append(out, checkOrphanInvariant(t, invs)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Pos, out[j].Pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Offset < b.Offset
	})
	return out, nil
}

func load(root string) (*tree, error) {
	t := &tree{fset: token.NewFileSet()}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			n := d.Name()
			if p != root && (n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(t.fset, p, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		t.files = append(t.files, file{path: p, ast: f, isTest: strings.HasSuffix(p, "_test.go")})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("lint: %w", err)
	}
	return t, nil
}

func (t *tree) finding(rule string, pos token.Pos, format string, a ...any) Finding {
	return Finding{Rule: rule, Pos: t.fset.Position(pos), Msg: fmt.Sprintf(format, a...)}
}

// calleeName returns the function or method name of a call, and the
// identifier it is selected from (the package or receiver), if simple.
func calleeName(c *ast.CallExpr) (name, recv string) {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name, ""
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			return fn.Sel.Name, id.Name
		}
		return fn.Sel.Name, ""
	}
	return "", ""
}

// ---- Rule 1: unknown-telemetry ---------------------------------------------

// checkUnknownTelemetry flags span names and attribute keys that are not
// registry constants. A string literal is accepted only if its value equals a
// registry value; a semconv.X selector is accepted only if X exists.
func checkUnknownTelemetry(t *tree, reg *Registry) []Finding {
	var out []Finding
	for _, f := range t.files {
		ast.Inspect(f.ast, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, recv := calleeName(c)
			var arg ast.Expr
			switch {
			case name == "Start" && len(c.Args) >= 2:
				arg = c.Args[1] // tracer.Start(ctx, name, ...)
			case name == "SetName" && len(c.Args) == 1:
				arg = c.Args[0]
			case recv == "attribute" && attributeCtors[name] && len(c.Args) >= 1:
				arg = c.Args[0]
			default:
				return true
			}
			if msg := badTelemetryArg(arg, reg); msg != "" {
				out = append(out, t.finding(RuleUnknownTelemetry, arg.Pos(), "%s", msg))
			}
			return true
		})
	}
	return out
}

func badTelemetryArg(arg ast.Expr, reg *Registry) string {
	switch a := arg.(type) {
	case *ast.BasicLit:
		if a.Kind != token.STRING {
			return ""
		}
		v, err := strconv.Unquote(a.Value)
		if err == nil && !reg.Values[v] {
			return fmt.Sprintf("%s is not in the registry; add it to registry/ (with review) and regenerate, do not invent telemetry", a.Value)
		}
	case *ast.SelectorExpr:
		if id, ok := a.X.(*ast.Ident); ok && id.Name == "semconv" && !reg.Names[a.Sel.Name] {
			return fmt.Sprintf("semconv.%s does not exist in the generated registry package", a.Sel.Name)
		}
	}
	return ""
}

// ---- Rule 2: no-trace-assertion --------------------------------------------

// checkNoTraceAssertion flags test files that define tests but never call
// Collect(). Files with no Test/Benchmark/Fuzz/Example functions are exempt,
// and so are files marked //subpoena:pure_logic above the package clause,
// unless they import telemetry packages, which contradicts the marker.
func checkNoTraceAssertion(t *tree) []Finding {
	var out []Finding
	for _, f := range t.files {
		if !f.isTest {
			continue
		}
		if hasHeaderMarker(f.ast, pureLogicRE) {
			if imp := telemetryImport(f.ast); imp != "" {
				out = append(out, t.finding(RuleNoTraceAssertion, f.ast.Package,
					"%s is marked //subpoena:pure_logic but imports %s; move telemetry tests to another file or drop the marker", filepath.Base(f.path), imp))
			}
			continue
		}
		if !definesTests(f.ast) || callsMethod(f.ast, map[string]bool{"Collect": true}) {
			continue
		}
		out = append(out, t.finding(RuleNoTraceAssertion, f.ast.Package,
			"%s defines tests but never calls the harness Collect(); tests must assert on collected telemetry", filepath.Base(f.path)))
	}
	return out
}

// telemetryImport returns the first import of f that is telemetry, or "".
func telemetryImport(f *ast.File) string {
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		for _, pre := range telemetryImportPrefixes {
			if strings.HasPrefix(p, pre) {
				return p
			}
		}
		for _, suf := range telemetryImportSuffixes {
			if strings.HasSuffix(p, suf) {
				return p
			}
		}
	}
	return ""
}

// hasHeaderMarker reports whether a comment above the package clause matches re.
func hasHeaderMarker(f *ast.File, re *regexp.Regexp) bool {
	for _, g := range f.Comments {
		if g.Pos() >= f.Package {
			break
		}
		for _, c := range g.List {
			if re.MatchString(c.Text) {
				return true
			}
		}
	}
	return false
}

func definesTests(f *ast.File) bool {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
			n := fd.Name.Name
			for _, p := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
				if strings.HasPrefix(n, p) {
					return true
				}
			}
		}
	}
	return false
}

func callsMethod(n ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok {
			if name, _ := calleeName(c); names[name] {
				found = true
			}
		}
		return !found
	})
	return found
}

// ---- Rule 3: unwitnessed-enforcement ---------------------------------------

// checkUnwitnessedEnforcement flags functions marked //subpoena:enforcement_point
// when no test anywhere in the tree calls a Witness method.
func checkUnwitnessedEnforcement(t *tree) []Finding {
	witnessed := false
	for _, f := range t.files {
		if f.isTest && callsMethod(f.ast, witnessMethods) {
			witnessed = true
			break
		}
	}
	if witnessed {
		return nil
	}
	var out []Finding
	for _, f := range t.files {
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Doc == nil || !commentHas(fd.Doc, MarkerEnforcementPoint) {
				continue
			}
			out = append(out, t.finding(RuleUnwitnessedEnforcement, fd.Pos(),
				"enforcement point %s has no test that calls a Witness method (Spawned); span assertions alone are testimony, not proof", fd.Name.Name))
		}
	}
	return out
}

func commentHas(g *ast.CommentGroup, marker string) bool {
	for _, c := range g.List {
		if strings.Contains(c.Text, marker) {
			return true
		}
	}
	return false
}

// ---- Rule 4: unguarded-absence ---------------------------------------------

// checkUnguardedAbsence flags an absence assertion with no Collect() earlier in
// the same top-level function. Absence over an uncollected capture proves nothing.
func checkUnguardedAbsence(t *tree) []Finding {
	var out []Finding
	for _, f := range t.files {
		if !f.isTest {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			var collects, absences []token.Pos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, _ := calleeName(c)
				switch {
				case name == "Collect":
					collects = append(collects, c.Pos())
				case absenceCalls[name]:
					absences = append(absences, c.Pos())
				}
				return true
			})
			for _, a := range absences {
				guarded := false
				for _, c := range collects {
					if c < a {
						guarded = true
					}
				}
				if !guarded {
					out = append(out, t.finding(RuleUnguardedAbsence, a,
						"absence assertion in %s without a preceding Collect() in the same function", fd.Name.Name))
				}
			}
		}
	}
	return out
}

// ---- Rule 5: missing-provenance --------------------------------------------

// checkMissingProvenance flags test files without a //subpoena:spec_derived or
// //subpoena:impl_derived marker before the package clause.
func checkMissingProvenance(t *tree) []Finding {
	var out []Finding
	for _, f := range t.files {
		if !f.isTest {
			continue
		}
		if !hasHeaderMarker(f.ast, provenanceRE) {
			out = append(out, t.finding(RuleMissingProvenance, f.ast.Package,
				"%s lacks a //subpoena:spec_derived or //subpoena:impl_derived marker above the package clause", filepath.Base(f.path)))
		}
	}
	return out
}

// FindRegistryDir walks up from start looking for generated/go/semconv.
func FindRegistryDir(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for dir := abs; ; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "generated", "go", "semconv")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand, nil
		}
		if filepath.Dir(dir) == dir {
			return "", fmt.Errorf("lint: generated/go/semconv not found above %s (use -registry)", start)
		}
	}
}
