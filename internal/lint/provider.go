package lint

import (
	"go/ast"
	"go/token"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// ---- Rule 8: provider-override ---------------------------------------------

// providerCalls are the functions, by import path, that construct or install
// a tracer provider. Code under test that gets its tracer from anywhere but
// the harness can send its spans somewhere the assertions never look, and an
// absence assertion over the harness then passes for the wrong reason.
var providerCalls = map[string]map[string]bool{
	"go.opentelemetry.io/otel":            {"SetTracerProvider": true},
	"go.opentelemetry.io/otel/sdk/trace":  {"NewTracerProvider": true},
	"go.opentelemetry.io/otel/trace/noop": {"NewTracerProvider": true},
}

// ownProviderRE is the exemption: a comment on the call's line or the line
// above, `//subpoena:own_provider <reason>`, with a reason.
var ownProviderRE = regexp.MustCompile(`subpoena:own_provider\s+\S`)

// MarkerOwnProvider exempts one provider call from provider-override.
const MarkerOwnProvider = "subpoena:own_provider"

// importNames maps each import's local name in f to its path. Blank and dot
// imports are left out.
func importNames(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		m[name] = p
	}
	return m
}

// checkProviderOverride flags calls that construct or install a tracer
// provider outside a main package (the service's own production setup),
// unless the call carries //subpoena:own_provider with a reason.
func checkProviderOverride(t *tree) []Finding {
	var out []Finding
	for _, f := range t.files {
		if f.ast.Name.Name == "main" && !f.isTest {
			continue
		}
		imports := importNames(f.ast)
		exempt := map[int]bool{} // lines covered by an own_provider comment
		for _, g := range f.ast.Comments {
			for _, c := range g.List {
				if ownProviderRE.MatchString(c.Text) {
					l := t.fset.Position(c.Pos()).Line
					exempt[l], exempt[l+1] = true, true
				}
			}
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			p := imports[id.Name]
			if !providerCalls[p][sel.Sel.Name] || exempt[t.fset.Position(c.Pos()).Line] {
				return true
			}
			out = append(out, t.finding(RuleProviderOverride, c.Pos(),
				"%s.%s outside a main package: take the tracer from the harness, or justify it with //%s <reason>",
				path.Base(p), sel.Sel.Name, MarkerOwnProvider))
			return true
		})
	}
	return out
}

// ---- Rule 9: dead-telemetry ------------------------------------------------

// checkDeadTelemetry flags span names and attribute keys in the registry that
// no non-test file in any root references, as a semconv constant or as an
// equal string literal. A registry entry nothing emits is a contract nobody
// keeps, and a test asserting its absence passes vacuously.
func checkDeadTelemetry(trees []*tree, reg *Registry) []Finding {
	used := map[string]bool{} // Go identifiers
	for _, t := range trees {
		for _, f := range t.files {
			if f.isTest {
				continue
			}
			imports := importNames(f.ast)
			ast.Inspect(f.ast, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && strings.HasSuffix(imports[id.Name], "/generated/go/semconv") {
						used[x.Sel.Name] = true
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if v, err := strconv.Unquote(x.Value); err == nil && reg.ByValue[v] != "" {
							used[reg.ByValue[v]] = true
						}
					}
				}
				return true
			})
		}
	}
	var out []Finding
	for val, name := range reg.ByValue {
		if used[name] {
			continue
		}
		out = append(out, Finding{Rule: RuleDeadTelemetry, Pos: reg.Pos[name],
			Msg: "registry entry " + strconv.Quote(val) + " (semconv." + name + ") is emitted nowhere in the linted code"})
	}
	return out
}
