package lint

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Invariants is the set of invariant files, keyed by trimmed content.
type Invariants struct {
	Dir    string
	ByText map[string]string // trimmed TraceQL -> file name
}

// queryArgIndex says where the TraceQL string sits for each harness query or
// assert function: the Require* helpers take (tb, trace, query); the Trace
// methods take (query).
func queryArgIndex(name string) (int, bool) {
	switch name {
	case "RequireAbsent", "RequireExists":
		return 2, true
	case "Absent", "Exists", "Query":
		return 0, true
	}
	return 0, false
}

// FindInvariantsDir walks up from start looking for a directory named
// invariants that holds at least one .traceql file. It returns "" if none.
func FindInvariantsDir(start string) string {
	abs, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for dir := abs; ; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "invariants")
		if m, _ := filepath.Glob(filepath.Join(cand, "*.traceql")); len(m) > 0 {
			return cand
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
}

// LoadInvariants reads every *.traceql file in dir. An empty dir yields an
// empty set.
func LoadInvariants(dir string) (*Invariants, error) {
	inv := &Invariants{Dir: dir, ByText: map[string]string{}}
	if dir == "" {
		return inv, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.traceql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("lint: %w", err)
		}
		inv.ByText[strings.TrimSpace(string(b))] = filepath.Base(f)
	}
	return inv, nil
}

func loadInvariants(root, explicit string) (*Invariants, error) {
	dir := explicit
	if dir == "" {
		dir = FindInvariantsDir(root)
	}
	return LoadInvariants(dir)
}

// ---- Rule 6: orphan-invariant ----------------------------------------------

// checkOrphanInvariant flags a TraceQL string literal passed straight to a
// harness query or assert function in a _test.go file when it does not
// byte-match (after trimming) any file in invariants/. Promotion between tiers
// is copy and paste, so a query that is not an invariant file can never be
// promoted to OATS or an alert and silently drifts. Queries built at run time
// (fmt.Sprintf, concatenation, variables) are not literals and are not checked.
func checkOrphanInvariant(t *tree, inv *Invariants) []Finding {
	var out []Finding
	for _, f := range t.files {
		if !f.isTest {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, _ := calleeName(c)
			idx, ok := queryArgIndex(name)
			if !ok || idx >= len(c.Args) {
				return true
			}
			lit, ok := c.Args[idx].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			q, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if _, found := inv.ByText[strings.TrimSpace(q)]; !found {
				where := "no invariants/ directory with .traceql files was found"
				if inv.Dir != "" {
					where = "no file in " + inv.Dir + " matches"
				}
				out = append(out, t.finding(RuleOrphanInvariant, lit.Pos(),
					"TraceQL literal passed to %s is not an invariant (%s); load it with invariants.MustLoad(invariants.<Name>) or add invariants/<name>.traceql and run `go generate ./invariants`", name, where))
			}
			return true
		})
	}
	return out
}
