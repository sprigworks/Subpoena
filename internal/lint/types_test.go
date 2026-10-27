//subpoena:impl_derived

package lint

import (
	"bytes"
	"strings"
	"testing"
)

// typedModule is a module that type-checks: its own harness and witness
// packages (matched by path suffix, like a vendored copy), and a metrics
// package whose methods share their names.
var typedModule = map[string]string{
	"go.mod": "module example.com/svc\n\ngo 1.24\n",
	"pkg/harness/harness.go": "package harness\n\ntype Harness struct{}\ntype Trace struct{}\n\n" +
		"func (*Harness) Collect() *Trace { return &Trace{} }\nfunc (*Trace) Absent(q string) bool { return true }\n",
	"pkg/witness/witness.go": "package witness\n\ntype Witness interface{ Spawned(traceID string) []string }\n",
	"metrics/metrics.go": "package metrics\n\ntype M struct{}\n\n" +
		"func (M) Collect()                  {}\nfunc (M) Absent(q string) bool       { return true }\nfunc (M) Spawned(id string) []string { return nil }\n",
	"svc.go": "package svc\n\n//subpoena:enforcement_point\nfunc Run() {}\n",
}

func lintTyped(t *testing.T, test string) ([]Finding, string) {
	t.Helper()
	files := map[string]string{"svc_test.go": test}
	for k, v := range typedModule {
		files[k] = v
	}
	dir := writeTree(t, files, t.TempDir())
	var warn bytes.Buffer
	fs, err := RunWith([]string{dir}, registry(t), Options{Warn: &warn})
	if err != nil {
		t.Fatal(err)
	}
	return fs, warn.String()
}

func byRule(fs []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestTypedCallsFromTheHarnessAndWitnessCount(t *testing.T) {
	fs, warn := lintTyped(t, `//subpoena:impl_derived
package svc

import (
	"testing"

	h "example.com/svc/pkg/harness"
	wit "example.com/svc/pkg/witness"
)

func TestRun(t *testing.T) {
	var hh h.Harness
	tr := hh.Collect()
	var w wit.Witness
	_ = w.Spawned("x")
	q := ""
	_ = tr.Absent(q)
}
`)
	if len(fs) != 0 {
		t.Fatalf("renamed harness and witness imports must count; got %v", fs)
	}
	if warn != "" {
		t.Fatalf("every file type-checks, so nothing should fall back to names; got %q", warn)
	}
}

// The gap name matching left: with the harness and witness imported, any
// method called Collect or Spawned counted, whatever package declared it.
func TestSameNamedMethodsElsewhereDoNotCount(t *testing.T) {
	fs, _ := lintTyped(t, `//subpoena:impl_derived
package svc

import (
	"testing"

	"example.com/svc/metrics"
	"example.com/svc/pkg/harness"
	"example.com/svc/pkg/witness"
)

var _ witness.Witness
var _ harness.Harness

func TestRun(t *testing.T) {
	var m metrics.M
	m.Collect()
	_ = m.Spawned("x")
	q := ""
	_ = m.Absent(q)
}
`)
	if got := byRule(fs, RuleNoTraceAssertion); len(got) != 1 {
		t.Errorf("metrics Collect is not the harness Collect; want 1 %s, got %v", RuleNoTraceAssertion, fs)
	}
	if got := byRule(fs, RuleUnwitnessedEnforcement); len(got) != 1 {
		t.Errorf("metrics Spawned is not a witness; want 1 %s, got %v", RuleUnwitnessedEnforcement, fs)
	}
	if got := byRule(fs, RuleUnguardedAbsence); len(got) != 0 {
		t.Errorf("metrics Absent is not a harness absence check; got %v", got)
	}
}

func TestOtherCollectDoesNotGuardAbsence(t *testing.T) {
	fs, _ := lintTyped(t, `//subpoena:impl_derived
package svc

import (
	"testing"

	"example.com/svc/metrics"
	"example.com/svc/pkg/harness"
	"example.com/svc/pkg/witness"
)

func TestRun(t *testing.T) {
	var m metrics.M
	m.Collect()
	var tr *harness.Trace
	q := ""
	_ = tr.Absent(q)
	var hh harness.Harness
	_ = hh.Collect()
	var w witness.Witness
	_ = w.Spawned("x")
}
`)
	got := byRule(fs, RuleUnguardedAbsence)
	if len(got) != 1 || len(fs) != 1 {
		t.Fatalf("only the harness Collect guards an absence check; want 1 %s, got %v", RuleUnguardedAbsence, fs)
	}
}

func TestUntypedFilesAreReported(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a_test.go": "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\")\nfunc TestA(t *testing.T) { h.Collect(ctx) }\n",
	}, t.TempDir())
	var warn bytes.Buffer
	if _, err := RunWith([]string{dir}, registry(t), Options{Warn: &warn}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warn.String(), "1 file(s)") || !strings.Contains(warn.String(), "not type-checked") {
		t.Fatalf("a tree outside any module must say it fell back to names; got %q", warn.String())
	}
}
