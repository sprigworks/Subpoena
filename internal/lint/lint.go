// Package lint implements subpoena-lint: static checks that keep a codebase's
// tests and telemetry honest. Most rules use go/ast; the rules that ask
// whether a test called the harness or a witness resolve calls with go/types
// where the package type-checks. Precision is otherwise traded for a simple,
// readable structure, one function per rule.
package lint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
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
	RuleProviderOverride       = "provider-override"
	RuleDeadTelemetry          = "dead-telemetry"
)

// Markers recognised in source comments.
const (
	MarkerEnforcementPoint = "subpoena:enforcement_point"
)

// witnessCalls are the calls that count as "asking a Witness", each with the
// import that must be present for the name to count: the raw witness methods,
// and the harness absence checks that call them and check capture health.
var witnessCalls = []struct{ name, importSuffix string }{
	{"Spawned", witnessSuffix},
	{"Dialed", witnessSuffix},
	{"NoSpawn", harnessSuffix},
	{"RequireNoSpawn", harnessSuffix},
	{"NoDial", harnessSuffix},
	{"RequireNoDial", harnessSuffix},
	{"CheckNoSpawn", harnessSuffix},
	{"CheckNoDial", harnessSuffix},
	{"WatchSpawns", harnessSuffix},
}

// asksWitness reports whether f calls one of witnessCalls (see callsFrom).
func asksWitness(f file) bool {
	for _, c := range witnessCalls {
		if callsFrom(f, f.ast, c.name, c.importSuffix) {
			return true
		}
	}
	return false
}

// harnessSuffix and witnessSuffix say where the calls rules 2 to 4 look for
// are declared: Collect and the absence checks in the harness, Spawned and
// Dialed in the witness package or one under it, such as execbpf. Matched by
// suffix, so a service that vendored them under its own path is covered.
const (
	harnessSuffix = "/pkg/harness"
	witnessSuffix = "/pkg/witness"
)

// importsSuffix reports whether f imports a path ending in suffix, or a
// package below it.
func importsSuffix(f *ast.File, suffix string) bool {
	for _, imp := range f.Imports {
		if pathUnder(strings.Trim(imp.Path.Value, `"`), suffix) {
			return true
		}
	}
	return false
}

func pathUnder(p, suffix string) bool {
	return strings.HasSuffix(p, suffix) || strings.Contains(p, suffix+"/")
}

// callsFrom reports whether a call to a function or method called name, and
// declared in a package under suffix, appears in n. Where the call resolves
// with go/types, the declaring package decides, so a renamed import counts
// and a same-named method from another package does not. Where it does not
// resolve (the file was not type-checked, or the call does not compile), the
// name counts if f imports a package under suffix.
func callsFrom(f file, n ast.Node, name, suffix string) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok {
			if declared, resolved := declaredUnder(f, c, name, suffix); declared || (!resolved && sameName(c, name) && importsSuffix(f.ast, suffix)) {
				found = true
			}
		}
		return !found
	})
	return found
}

// harnessCall reports whether c calls name from the harness. Where the call
// does not resolve with go/types, the name alone counts, as unguarded-absence
// always matched it.
func harnessCall(f file, c *ast.CallExpr, name string) bool {
	declared, resolved := declaredUnder(f, c, name, harnessSuffix)
	return declared || (!resolved && sameName(c, name))
}

// declaredUnder resolves c with go/types. resolved is false if f was not
// type-checked or c's callee did not resolve; otherwise declared reports
// whether c calls name declared in a package under suffix.
func declaredUnder(f file, c *ast.CallExpr, name, suffix string) (declared, resolved bool) {
	if f.info == nil {
		return false, false
	}
	fn, ok := typeutil.Callee(f.info, c).(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false, false
	}
	return fn.Name() == name && pathUnder(fn.Pkg().Path(), suffix), true
}

// A Collect wrapper is a test helper that stops the system and the witness,
// checks capture health and then calls the harness Collect itself, so tests
// call the helper instead. Rules 2 and 4 count a call to it as a Collect.
// Only type-checked code qualifies (see isWrapper): every return must hand
// back the trace from a harness Collect (or another wrapper) called in the
// helper's own body, either directly or through a variable assigned from that
// call outside any function literal. A method called Collect that does not,
// such as a metrics Collect, is not a wrapper whatever its name. Lint does not
// prove the assignment runs on every path (it may sit under an if); that stays
// with review.

// collectCall reports whether c calls the harness Collect or a wrapper.
func (t *tree) collectCall(f file, c *ast.CallExpr) bool {
	return harnessCall(f, c, "Collect") || t.wrapperCall(f, c)
}

// callsCollect is callsFrom for Collect, counting wrappers.
func (t *tree) callsCollect(f file, n ast.Node) bool {
	if callsFrom(f, n, "Collect", harnessSuffix) {
		return true
	}
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok && t.wrapperCall(f, c) {
			found = true
		}
		return !found
	})
	return found
}

func (t *tree) wrapperCall(f file, c *ast.CallExpr) bool {
	if f.info == nil || len(t.wrappers) == 0 {
		return false
	}
	fn, ok := typeutil.Callee(f.info, c).(*types.Func)
	return ok && t.wrappers[fn.Pos()]
}

// findWrappers returns the declaration positions of the tree's Collect
// wrappers. A wrapper may call another wrapper, so it repeats until no new
// one is found.
func findWrappers(t *tree) map[token.Pos]bool {
	found := map[token.Pos]bool{}
	for {
		added := false
		for _, f := range t.files {
			if f.info == nil {
				continue
			}
			for _, d := range f.ast.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || found[fd.Name.Pos()] {
					continue
				}
				if fn, ok := f.info.Defs[fd.Name].(*types.Func); ok && isWrapper(f, fn, fd.Body, found) {
					found[fn.Pos()] = true
					added = true
				}
			}
		}
		if !added {
			return found
		}
	}
}

// collector returns the trace type a call yields if it calls the harness
// Collect or a wrapper, else nil.
func collector(f file, c *ast.CallExpr, wrappers map[token.Pos]bool) types.Type {
	fn, ok := typeutil.Callee(f.info, c).(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil
	}
	if !(fn.Name() == "Collect" && pathUnder(fn.Pkg().Path(), harnessSuffix)) && !wrappers[fn.Pos()] {
		return nil
	}
	res := fn.Type().(*types.Signature).Results()
	if res.Len() == 0 {
		return nil
	}
	return res.At(0).Type()
}

// isWrapper reports whether fn, with body, is a Collect wrapper: it has at
// least one return, and every return outside function literals hands back, in
// fn's first result of the trace type, either a direct Collect (or wrapper)
// call or a variable assigned from one in fn's own body. A return of nil, of a
// parameter, or of anything else disqualifies it.
func isWrapper(f file, fn *types.Func, body *ast.BlockStmt, wrappers map[token.Pos]bool) bool {
	var trace types.Type
	collected := map[types.Object]bool{}
	var rets []*ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			// An assignment in a literal may never run. (A deferred or go'd
			// call cannot assign, so the return rule already excludes it.)
			return false
		case *ast.AssignStmt:
			if len(n.Rhs) == 1 && len(n.Lhs) > 0 {
				if c, ok := n.Rhs[0].(*ast.CallExpr); ok {
					if tt := collector(f, c, wrappers); tt != nil {
						if id, ok := n.Lhs[0].(*ast.Ident); ok {
							if obj := f.info.ObjectOf(id); obj != nil {
								collected[obj], trace = true, tt
							}
						}
					}
				}
			}
		case *ast.ValueSpec:
			if len(n.Values) == 1 && len(n.Names) > 0 {
				if c, ok := n.Values[0].(*ast.CallExpr); ok {
					if tt := collector(f, c, wrappers); tt != nil {
						if obj := f.info.ObjectOf(n.Names[0]); obj != nil {
							collected[obj], trace = true, tt
						}
					}
				}
			}
		case *ast.ReturnStmt:
			rets = append(rets, n)
		}
		return true
	})
	res := fn.Type().(*types.Signature).Results()
	idx := -1
	for _, r := range rets {
		// return h.Collect(): the call's results are fn's results.
		if len(r.Results) == 1 {
			if c, ok := r.Results[0].(*ast.CallExpr); ok {
				if tt := collector(f, c, wrappers); tt != nil && res.Len() > 0 && types.Identical(res.At(0).Type(), tt) {
					trace = tt
					continue
				}
			}
		}
		if trace == nil {
			return false
		}
		if idx < 0 {
			for i := 0; i < res.Len(); i++ {
				if types.Identical(res.At(i).Type(), trace) {
					idx = i
					break
				}
			}
		}
		if idx < 0 || idx >= len(r.Results) {
			return false
		}
		id, ok := r.Results[idx].(*ast.Ident)
		if !ok || !collected[f.info.ObjectOf(id)] {
			return false
		}
	}
	return len(rets) > 0 && trace != nil
}

func sameName(c *ast.CallExpr, name string) bool {
	n, _ := calleeName(c)
	return n == name
}

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
	// Pos is where each identifier in ByValue is declared, for dead-telemetry.
	Pos map[string]token.Position
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
	r := &Registry{Values: map[string]bool{}, Names: map[string]bool{}, ByValue: map[string]string{}, Pos: map[string]token.Position{}}
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
						if vs.Type != nil {
							// A typed constant (semconv.TierTest) is a value of some
							// other type, never a span name or attribute key.
							continue
						}
						if strings.HasPrefix(id.Name, enumValuePrefix) {
							// An enum member's value ("cgroup") is not a span name or
							// attribute key, so it must not make a literal acceptable.
							continue
						}
						r.Values[val] = true
						r.ByValue[val] = id.Name
						r.Pos[id.Name] = fset.Position(id.Pos())
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
	info   *types.Info // nil if the file was not type-checked
}

type tree struct {
	fset  *token.FileSet
	files []file
	// untyped counts files that were not type-checked, so rules 2 to 4
	// matched calls there by name and import.
	untyped int
	// wrappers are the Collect wrappers found in the tree, by declaration
	// position (see findWrappers).
	wrappers map[token.Pos]bool
}

// Options tune a Run.
type Options struct {
	// InvariantsDir is the directory of *.traceql invariants used by
	// orphan-invariant. If empty it is found by walking up from each root; if
	// none exists the invariant set is empty, so every TraceQL literal is an orphan.
	InvariantsDir string
	// DeadTelemetry enables dead-telemetry, which assumes the roots are the
	// whole service: a registry entry no root emits is reported.
	DeadTelemetry bool
	// Warn, if set, receives a note for each root with files that were not
	// type-checked.
	Warn io.Writer
}

// Run lints every .go file under each root and returns findings sorted by position.
func Run(roots []string, reg *Registry) ([]Finding, error) { return RunWith(roots, reg, Options{}) }

// RunWith is Run with explicit Options.
func RunWith(roots []string, reg *Registry, opts Options) ([]Finding, error) {
	var out []Finding
	var trees []*tree
	for _, root := range roots {
		t, err := load(root)
		if err != nil {
			return nil, err
		}
		trees = append(trees, t)
		if t.untyped > 0 && opts.Warn != nil {
			fmt.Fprintf(opts.Warn, "subpoena-lint: %d file(s) under %s were not type-checked; Collect, witness and absence calls there were matched by name\n", t.untyped, root)
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
		out = append(out, checkProviderOverride(t)...)
	}
	if opts.DeadTelemetry {
		out = append(out, checkDeadTelemetry(trees, reg)...)
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
	typed := typeCheck(root, t.fset)
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
		isTest := strings.HasSuffix(p, "_test.go")
		if abs, err := filepath.Abs(p); err == nil {
			if tf, ok := typed[realPath(abs)]; ok {
				t.files = append(t.files, file{path: p, ast: tf.ast, isTest: isTest, info: tf.info})
				return nil
			}
		}
		f, err := parser.ParseFile(t.fset, p, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		t.untyped++
		t.files = append(t.files, file{path: p, ast: f, isTest: isTest})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("lint: %w", err)
	}
	t.wrappers = findWrappers(t)
	return t, nil
}

type typedFile struct {
	ast  *ast.File
	info *types.Info
}

// typeCheck loads the packages under root, tests included, and returns the
// syntax and type information of each file by absolute path. Packages with
// type errors keep the information that did resolve. A root outside any
// module, and files excluded by build constraints, are left out: load parses
// those itself, and rules 2 to 4 match calls there by name.
func typeCheck(root string, fset *token.FileSet) map[string]typedFile {
	out := map[string]typedFile{}
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:   root,
		Tests: true,
		Fset:  fset,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return out
	}
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil || len(pkg.Syntax) != len(pkg.CompiledGoFiles) {
			continue
		}
		for i, f := range pkg.Syntax {
			if p := realPath(pkg.CompiledGoFiles[i]); out[p].info == nil {
				out[p] = typedFile{ast: f, info: pkg.TypesInfo}
			}
		}
	}
	return out
}

// realPath resolves symlinks so the walk's paths and the go command's agree.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
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
		if !definesTests(f.ast) || t.callsCollect(f, f.ast) {
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

// ---- Rule 3: unwitnessed-enforcement ---------------------------------------

// checkUnwitnessedEnforcement flags functions marked //subpoena:enforcement_point
// when no test anywhere in the tree calls a Witness method.
func checkUnwitnessedEnforcement(t *tree) []Finding {
	witnessed := false
	for _, f := range t.files {
		if f.isTest && asksWitness(f) {
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
				"enforcement point %s has no test that asks a Witness (Spawned, Dialed, or harness.RequireNoSpawn/RequireNoDial); span assertions alone are testimony, not proof", fd.Name.Name))
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
				switch {
				case t.collectCall(f, c):
					collects = append(collects, c.Pos())
				case harnessCall(f, c, "RequireAbsent"), harnessCall(f, c, "Absent"):
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
