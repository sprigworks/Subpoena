package lint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---- Rule 7: registry-drift ------------------------------------------------
//
// The registry is the contract; a test must not move together with it. If one
// change set touches registry/ and also touches a _test.go file that asserts
// on a span or attribute the registry change added or altered, someone may
// have bent the contract to make a test pass. The rule does not say the change
// is wrong, only that it needs a deliberate human look (CODEOWNERS already
// requires one for registry/).
//
// v0 heuristic, deliberately simple:
//   - parse registry/**/*.yaml at the base revision and in the working tree;
//   - an identifier is "new" if absent at base, "changed" if its semantic
//     definition differs (see semanticAttr and semanticSpan; brief, note and
//     examples are ignored);
//   - map identifiers to the generated Go constants (generated/go/semconv at
//     the working tree) and report test files changed since base that
//     reference one of those constants, or its string value as a literal.
//
// Not handled: removals (the test would not compile), string literals (the
// unknown-telemetry rule already steers tests to constants, and fixture
// strings in unrelated tests would make this rule noisy), identifiers reached
// through variables, and non-span, non-attribute
// registry groups.

// DriftOptions configures CheckRegistryDrift.
type DriftOptions struct {
	// Repo is any directory inside the git repository.
	Repo string
	// Base is the revision to compare against. Empty means HEAD, i.e. the
	// working tree against HEAD. Any other value is resolved to its merge-base
	// with HEAD, so a branch is compared with where it left main.
	Base string
}

// DriftChange is one registry identifier that is new or changed.
type DriftChange struct {
	Kind string // "span" or "attribute"
	ID   string // span name or attribute id, which is also the generated constant's value
	New  bool
}

type regModel struct {
	spans map[string]string // span name -> canonical semantic JSON
	attrs map[string]string // attribute id -> canonical semantic JSON
}

type yamlFile struct {
	Groups []yamlGroup `yaml:"groups"`
}

type yamlGroup struct {
	ID         string           `yaml:"id"`
	Type       string           `yaml:"type"`
	Name       string           `yaml:"name"`
	SpanKind   string           `yaml:"span_kind"`
	Stability  string           `yaml:"stability"`
	Attributes []map[string]any `yaml:"attributes"`
}

// parseRegistryYAML adds the spans and attributes of one registry file to m.
func parseRegistryYAML(m *regModel, name string, data []byte) error {
	var f yamlFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("lint: parse %s: %w", name, err)
	}
	for _, g := range f.Groups {
		switch g.Type {
		case "attribute_group":
			for _, a := range g.Attributes {
				id, _ := a["id"].(string)
				if id != "" {
					m.attrs[id] = canonical(pick(a, "type", "stability", "deprecated", "annotations"))
				}
			}
		case "span":
			if g.Name == "" {
				continue
			}
			var refs []any
			for _, a := range g.Attributes {
				refs = append(refs, pick(a, "ref", "id", "requirement_level", "type", "annotations"))
			}
			m.spans[g.Name] = canonical(map[string]any{
				"span_kind": g.SpanKind, "stability": g.Stability, "attributes": refs,
			})
		}
	}
	return nil
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// canonical is a stable text form: encoding/json sorts map keys.
func canonical(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// DiffRegistry returns the spans and attributes that are new or changed in head
// relative to base, sorted by kind and id.
func DiffRegistry(base, head *regModel) []DriftChange {
	var out []DriftChange
	diff := func(kind string, b, h map[string]string) {
		for id, hv := range h {
			bv, existed := b[id]
			if !existed || bv != hv {
				out = append(out, DriftChange{Kind: kind, ID: id, New: !existed})
			}
		}
	}
	diff("attribute", base.attrs, head.attrs)
	diff("span", base.spans, head.spans)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func splitZ(b []byte) []string {
	var out []string
	for _, s := range strings.Split(string(b), "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isYAML(p string) bool { return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") }

// CheckRegistryDrift implements the registry-drift rule for a git repository.
func CheckRegistryDrift(o DriftOptions) ([]Finding, error) {
	if o.Repo == "" {
		o.Repo = "."
	}
	topB, err := git(o.Repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("lint: registry-drift needs a git repository: %w", err)
	}
	top := strings.TrimSpace(string(topB))
	base := "HEAD"
	if o.Base != "" && o.Base != "HEAD" {
		base = o.Base
		if mb, err := git(top, "merge-base", o.Base, "HEAD"); err == nil {
			base = strings.TrimSpace(string(mb))
		} else if _, err2 := git(top, "rev-parse", "--verify", o.Base+"^{commit}"); err2 != nil {
			return nil, fmt.Errorf("lint: unknown base revision %q", o.Base)
		}
	}

	// Registry at base. A repo with no commits yet has no HEAD: treat as empty.
	baseM := &regModel{spans: map[string]string{}, attrs: map[string]string{}}
	if _, err := git(top, "rev-parse", "--verify", base+"^{commit}"); err == nil {
		list, err := git(top, "ls-tree", "-r", "--name-only", "-z", base, "--", "registry")
		if err != nil {
			return nil, err
		}
		for _, p := range splitZ(list) {
			if !isYAML(p) {
				continue
			}
			data, err := git(top, "show", base+":"+p)
			if err != nil {
				return nil, err
			}
			if err := parseRegistryYAML(baseM, base+":"+p, data); err != nil {
				return nil, err
			}
		}
	}
	// Registry in the working tree (includes untracked files).
	headM := &regModel{spans: map[string]string{}, attrs: map[string]string{}}
	regDir := filepath.Join(top, "registry")
	if st, err := os.Stat(regDir); err == nil && st.IsDir() {
		err := filepath.WalkDir(regDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !isYAML(p) {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return parseRegistryYAML(headM, p, data)
		})
		if err != nil {
			return nil, err
		}
	}
	changes := DiffRegistry(baseM, headM)
	if len(changes) == 0 {
		return nil, nil
	}

	// Map identifiers to generated constants (working tree).
	reg, err := LoadRegistry(filepath.Join(top, "generated", "go", "semconv"))
	if err != nil {
		return nil, fmt.Errorf("lint: registry-drift: %w (run `make generate`)", err)
	}
	byConst := map[string]DriftChange{}
	for _, c := range changes {
		if name, ok := reg.ByValue[c.ID]; ok {
			byConst[name] = c
		}
	}

	// Test files changed since base: tracked changes plus untracked files.
	var tests []string
	if _, err := git(top, "rev-parse", "--verify", base+"^{commit}"); err == nil {
		d, err := git(top, "diff", "--name-only", "-z", "--diff-filter=ACMR", base, "--", "*_test.go")
		if err != nil {
			return nil, err
		}
		tests = append(tests, splitZ(d)...)
	}
	u, err := git(top, "ls-files", "--others", "--exclude-standard", "-z", "--", "*_test.go")
	if err != nil {
		return nil, err
	}
	tests = append(tests, splitZ(u)...)
	sort.Strings(tests)

	baseLabel := o.Base
	if baseLabel == "" {
		baseLabel = "HEAD"
	}
	var out []Finding
	fset := token.NewFileSet()
	for i, rel := range tests {
		if i > 0 && tests[i-1] == rel {
			continue
		}
		path := filepath.Join(top, rel)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			continue // a test that does not parse is the compiler's problem
		}
		semconvName := semconvImportName(f)
		ast.Inspect(f, func(n ast.Node) bool {
			x, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := x.X.(*ast.Ident)
			if !ok || semconvName == "" || id.Name != semconvName {
				return true
			}
			c, ok := byConst[x.Sel.Name]
			if !ok {
				return true
			}
			pos := x.Pos()
			state := "changed"
			if c.New {
				state = "new"
			}
			out = append(out, Finding{Rule: RuleRegistryDrift, Pos: fset.Position(pos),
				Msg: fmt.Sprintf("%s.%s references %s %q, which is %s in the registry/ diff against %s; the registry is the contract, so confirm the code or test is not being bent to fit (needs registry owner review)",
					semconvName, x.Sel.Name, c.Kind, c.ID, state, baseLabel)})
			return true
		})
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

// semconvImportName returns the local name under which f imports the generated
// semconv package, or "" if it does not.
func semconvImportName(f *ast.File) string {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !strings.HasSuffix(p, "generated/go/semconv") {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return "semconv"
	}
	return ""
}
