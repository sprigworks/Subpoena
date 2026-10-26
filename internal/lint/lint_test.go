//subpoena:impl_derived

package lint

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func registry(t *testing.T) *Registry {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	reg, err := LoadRegistry(filepath.Join(filepath.Dir(here), "..", "..", "generated", "go", "semconv"))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// writeTree writes files under dir and returns dir.
func writeTree(t *testing.T, files map[string]string, dir string) string {
	t.Helper()
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// lintTree writes files into a temp dir and lints it, returning the findings.
func lintTree(t *testing.T, files map[string]string) []Finding {
	t.Helper()
	dir := writeTree(t, files, t.TempDir())
	fs, err := Run([]string{dir}, registry(t))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func rules(fs []Finding) []string {
	var r []string
	for _, f := range fs {
		r = append(r, f.Rule)
	}
	return r
}

func only(t *testing.T, fs []Finding, rule string, n int) {
	t.Helper()
	if len(fs) != n {
		t.Fatalf("want %d finding(s) of %s, got %d: %v", n, rule, len(fs), fs)
	}
	for _, f := range fs {
		if f.Rule != rule {
			t.Fatalf("want rule %s, got %v", rule, fs)
		}
	}
}

func TestRegistryLoaded(t *testing.T) {
	r := registry(t)
	for _, v := range []string{"agent.session.authorize", "authorization.allowed", "session.id", "process.command_line"} {
		if !r.Values[v] {
			t.Errorf("registry missing %q", v)
		}
	}
	if !r.Names["SpanAgentSessionExec"] || r.Names["Tier"] {
		t.Error("names wrong")
	}
}

// ---- unknown-telemetry ----

func TestUnknownTelemetry(t *testing.T) {
	src := `package p
import (
	"go.opentelemetry.io/otel/attribute"
	"github.com/sprigworks/subpoena/generated/go/semconv"
)
func f(tr T, span S, ctx C) {
	tr.Start(ctx, "agent.session.invented")          // bad literal
	tr.Start(ctx, "agent.session.exec")              // literal equal to a registry value: accepted
	tr.Start(ctx, semconv.SpanAgentSessionExec)      // ok
	tr.Start(ctx, semconv.SpanAgentSessionMissing)   // bad constant
	span.SetName("nope")                             // bad
	span.SetAttributes(
		attribute.String("made.up", "x"),            // bad
		attribute.Bool(semconv.AttrAuthorizationAllowed, true), // ok
		attribute.Int("session.id", 1),              // literal in registry: ok
	)
	cmd.Start()                                       // not telemetry
	w.Start(a)                                        // one arg: not telemetry
}
`
	fs := lintTree(t, map[string]string{"a.go": src})
	only(t, fs, RuleUnknownTelemetry, 4)
	got := ""
	for _, f := range fs {
		got += f.Msg + "\n"
	}
	for _, want := range []string{"agent.session.invented", "SpanAgentSessionMissing", `"nope"`, "made.up"} {
		if !strings.Contains(got, want) {
			t.Errorf("no finding mentioning %s:\n%s", want, got)
		}
	}
}

// ---- no-trace-assertion ----

func TestNoTraceAssertion(t *testing.T) {
	bad := "//subpoena:impl_derived\npackage p\nimport \"testing\"\nfunc TestX(t *testing.T) { _ = 1 }\n"
	good := "//subpoena:impl_derived\npackage p\nimport \"testing\"\nfunc TestX(t *testing.T) { h.Collect(ctx) }\n"
	helperOnly := "//subpoena:impl_derived\npackage p\nfunc helper() {}\n"
	only(t, lintTree(t, map[string]string{"bad_test.go": bad}), RuleNoTraceAssertion, 1)
	if fs := lintTree(t, map[string]string{"good_test.go": good, "helpers_test.go": helperOnly}); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestPureLogicMarkerExemptsNoTraceAssertion(t *testing.T) {
	const tests = "import \"testing\"\nfunc TestPolicy(t *testing.T) { _ = evaluate(1) }\n"
	pure := "//subpoena:spec_derived\n//subpoena:pure_logic\n\npackage p\n" + tests
	if fs := lintTree(t, map[string]string{"policy_test.go": pure}); len(fs) != 0 {
		t.Fatalf("pure_logic file flagged: %v", fs)
	}
	// Like provenance, the marker counts only above the package clause.
	below := "//subpoena:spec_derived\npackage p\n//subpoena:pure_logic\n" + tests
	only(t, lintTree(t, map[string]string{"policy_test.go": below}), RuleNoTraceAssertion, 1)
}

func TestPureLogicMarkerWithTelemetryImportIsFlagged(t *testing.T) {
	for _, imp := range []string{
		"go.opentelemetry.io/otel/trace",
		"github.com/sprigworks/subpoena/pkg/harness",
		"github.com/sprigworks/subpoena/pkg/witness",
		"github.com/sprigworks/subpoena/generated/go/semconv",
		"example.com/svc/invariants", // a service's own copy, by path suffix
	} {
		src := "//subpoena:impl_derived\n//subpoena:pure_logic\npackage p\nimport (\n\t\"testing\"\n\t_ \"" + imp + "\"\n)\n" +
			"func TestX(t *testing.T) { h.Collect(ctx) }\n" // Collect does not excuse the contradiction
		fs := lintTree(t, map[string]string{"x_test.go": src})
		only(t, fs, RuleNoTraceAssertion, 1)
		if !strings.Contains(fs[0].Msg, imp) {
			t.Errorf("%s: finding does not name the import: %s", imp, fs[0].Msg)
		}
	}
	// A non-telemetry import is fine.
	ok := "//subpoena:impl_derived\n//subpoena:pure_logic\npackage p\nimport (\n\t\"testing\"\n\t\"strings\"\n)\nfunc TestX(t *testing.T) { _ = strings.ToUpper(\"x\") }\n"
	if fs := lintTree(t, map[string]string{"x_test.go": ok}); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

// ---- unwitnessed-enforcement ----

const enforced = `package p

// Authorize decides.
//
//subpoena:enforcement_point
func Authorize() {}
`

func TestUnwitnessedEnforcement(t *testing.T) {
	unwitnessed := "//subpoena:impl_derived\npackage p\nimport \"testing\"\nfunc TestA(t *testing.T) { h.Collect(ctx) }\n"
	witnessed := "//subpoena:impl_derived\npackage p\nimport \"testing\"\nfunc TestA(t *testing.T) { h.Collect(ctx); w.Spawned(id) }\n"

	fs := lintTree(t, map[string]string{"auth.go": enforced, "a_test.go": unwitnessed})
	only(t, fs, RuleUnwitnessedEnforcement, 1)
	if !strings.Contains(fs[0].Msg, "Authorize") {
		t.Fatalf("finding should name the function: %v", fs[0])
	}
	if fs := lintTree(t, map[string]string{"auth.go": enforced, "a_test.go": witnessed}); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
	// A Spawned call in non-test code does not count as a test witnessing it.
	only(t, lintTree(t, map[string]string{
		"auth.go": enforced, "other.go": "package p\nfunc g() { w.Spawned(1) }\n", "a_test.go": unwitnessed,
	}), RuleUnwitnessedEnforcement, 1)
	// No marker, no finding.
	if fs := lintTree(t, map[string]string{"plain.go": "package p\nfunc F() {}\n", "a_test.go": unwitnessed}); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

// ---- unguarded-absence ----

func TestUnguardedAbsence(t *testing.T) {
	head := "//subpoena:impl_derived\npackage p\nimport \"testing\"\n"
	cases := []struct {
		name string
		body string
		want int
	}{
		{"absence before collect", "func TestA(t *testing.T) { harness.RequireAbsent(t, tr, q); tr, _ = h.Collect(ctx) }", 1},
		{"no collect at all (method form)", "func TestA(t *testing.T) { tr.Absent(q) }", 1},
		{"collect first", "func TestA(t *testing.T) { tr, _ := h.Collect(ctx); harness.RequireAbsent(t, tr, q); tr.Absent(q) }", 0},
		{"collect outside closure", "func TestA(t *testing.T) { tr, _ := h.Collect(ctx); t.Run(\"x\", func(t *testing.T) { harness.RequireAbsent(t, tr, q) }) }", 0},
		{"collect in other function does not count", "func helper() { h.Collect(ctx) }\nfunc TestA(t *testing.T) { harness.RequireAbsent(t, tr, q) }", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := head + c.body + "\n"
			// Add a Collect call elsewhere so rule 2 stays quiet and only rule 4 is exercised.
			src += "func TestKeepsRule2Quiet(t *testing.T) { h.Collect(ctx) }\n"
			fs := lintTree(t, map[string]string{"a_test.go": src})
			var n int
			for _, f := range fs {
				if f.Rule == RuleUnguardedAbsence {
					n++
				} else {
					t.Errorf("unexpected finding %v", f)
				}
			}
			if n != c.want {
				t.Fatalf("want %d unguarded-absence, got %d: %v", c.want, n, fs)
			}
		})
	}
}

// ---- missing-provenance ----

func TestMissingProvenance(t *testing.T) {
	body := "package p\nimport \"testing\"\nfunc TestA(t *testing.T) { h.Collect(ctx) }\n"
	only(t, lintTree(t, map[string]string{"a_test.go": body}), RuleMissingProvenance, 1)
	only(t, lintTree(t, map[string]string{"a_test.go": "// just a comment\n" + body}), RuleMissingProvenance, 1)
	// Marker after the package clause is too late.
	only(t, lintTree(t, map[string]string{"a_test.go": "package p\n//subpoena:spec_derived\nimport \"testing\"\nfunc TestA(t *testing.T) { h.Collect(ctx) }\n"}), RuleMissingProvenance, 1)
	for _, m := range []string{"spec_derived", "impl_derived"} {
		for _, form := range []string{"//subpoena:" + m + "\n\n", "//go:build !nope\n\n//subpoena:" + m + "\n\n", "// subpoena:" + m + "\n"} {
			if fs := lintTree(t, map[string]string{"a_test.go": form + body}); len(fs) != 0 {
				t.Errorf("%q: unexpected %v", form, fs)
			}
		}
	}
	// A bogus provenance value is not accepted.
	only(t, lintTree(t, map[string]string{"a_test.go": "//subpoena:vibes_derived\n" + body}), RuleMissingProvenance, 1)
	// Non-test files need no marker.
	if fs := lintTree(t, map[string]string{"a.go": "package p\n"}); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestSkipsTestdataAndSortsFindings(t *testing.T) {
	bad := "package p\nimport \"testing\"\nfunc TestA(t *testing.T) {}\n"
	fs := lintTree(t, map[string]string{"testdata/x_test.go": bad, "b_test.go": bad, "a_test.go": bad})
	got := rules(fs)
	// Each of a_test.go and b_test.go: no-trace-assertion + missing-provenance.
	if len(got) != 4 {
		t.Fatalf("want 4 findings (testdata skipped), got %v", fs)
	}
	if !strings.HasSuffix(fs[0].Pos.Filename, "a_test.go") || !strings.HasSuffix(fs[3].Pos.Filename, "b_test.go") {
		t.Fatalf("findings not sorted: %v", fs)
	}
}

// TestGatewayExampleIsClean pins the acceptance criterion: the example lints clean.
func TestGatewayExampleIsClean(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	gw := filepath.Join(filepath.Dir(here), "..", "..", "examples", "gateway")
	fs, err := Run([]string{gw}, registry(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("examples/gateway must lint clean: %v", fs)
	}
}

// TestLintCatchesMutatedGateway guards against a vacuously clean linter: the
// real gateway with its telemetry renamed to a literal must be flagged.
func TestLintCatchesMutatedGateway(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "examples", "gateway", "gateway.go"))
	if err != nil {
		t.Fatal(err)
	}
	mut := strings.Replace(string(src), "semconv.SpanAgentSessionExec)", `"agent.session.exec_v2")`, 1)
	if mut == string(src) {
		t.Fatal("mutation did not apply")
	}
	fs := lintTree(t, map[string]string{"gateway.go": mut})
	var unknown int
	for _, f := range fs {
		if f.Rule == RuleUnknownTelemetry {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatalf("want 1 unknown-telemetry, got %v", fs)
	}
}

// Enum member constants are references the linter must accept as names, while
// their values ("cgroup") must not turn a bare literal into a valid span name.
func TestRegistryEnumValueConstantsAreNamesNotTelemetry(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, map[string]string{"s.go": "package semconv\nconst (\n\tSpanA = \"a.b\"\n\tAttrX = \"x.y\"\n\tValXOne = \"one\"\n)\n"}, dir)
	r, err := LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Names["ValXOne"] || r.Values["one"] || r.ByValue["one"] != "" {
		t.Fatalf("enum value constant misclassified: %+v", r)
	}
	if !r.Values["a.b"] || !r.Values["x.y"] {
		t.Fatalf("names and keys lost: %+v", r)
	}
}
