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

// realHarness has the real Collect signature, (*Trace, error), and another
// harness function that returns a trace without collecting.
const realHarness = "package harness\n\ntype Harness struct{}\ntype Trace struct{}\n\n" +
	"func (*Harness) Collect() (*Trace, error) { return &Trace{}, nil }\n" +
	"func (*Harness) Snapshot() *Trace        { return &Trace{} }\n" +
	"func (*Trace) Absent(q string) bool       { return true }\n"

// lintTypedFiles is lintTyped with the real harness and several files.
func lintTypedFiles(t *testing.T, files map[string]string) []Finding {
	t.Helper()
	all := map[string]string{}
	for k, v := range typedModule {
		all[k] = v
	}
	all["pkg/harness/harness.go"] = realHarness
	all["fake/fake.go"] = "package fake\n\nimport \"example.com/svc/pkg/harness\"\n\nfunc Collect() (*harness.Trace, error) { return &harness.Trace{}, nil }\n"
	for k, v := range files {
		all[k] = v
	}
	dir := writeTree(t, all, t.TempDir())
	fs, err := RunWith([]string{dir}, registry(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// wrapperUser calls rig.Collect, then asserts an absence on what it returned.
const wrapperUser = `//subpoena:impl_derived
package svc

import (
	"testing"

	"example.com/svc/pkg/witness"
)

func TestRun(t *testing.T) {
	r := &rig{}
	tr := r.Collect(t)
	q := ""
	_ = tr.Absent(q)
	var w witness.Witness
	_ = w.Spawned("x")
}
`

func helperFile(body string) string {
	return `//subpoena:impl_derived
package svc

import (
	"example.com/svc/fake"
	"example.com/svc/metrics"
	"example.com/svc/pkg/harness"
)

var (
	_ metrics.M
	_ = fake.Collect
)

type rig struct {
	h harness.Harness
	m metrics.M
	o *harness.Trace
}

func (r *rig) stop() {}

` + body + "\n"
}

// A lifecycle helper in one file stops the system, then calls the harness
// Collect and returns its trace; tests in another file call only the helper.
// Both shapes of return count, and so does a helper that wraps a wrapper.
func TestCollectWrapperCounts(t *testing.T) {
	cases := map[string]string{
		"variable": `func (r *rig) Collect(t interface{ Helper() }) *harness.Trace {
	t.Helper()
	r.stop()
	tr, err := r.h.Collect()
	if err != nil {
		panic(err)
	}
	return tr
}`,
		"direct return": `func (r *rig) Collect(t interface{ Helper() }) (*harness.Trace, error) {
	r.stop()
	return r.h.Collect()
}`,
		// Declared before the wrapper it calls, so finding it takes a second pass.
		"wrapper of a wrapper": `func (r *rig) Collect(t interface{ Helper() }) *harness.Trace {
	var tr = r.inner()
	return tr
}

func (r *rig) inner() *harness.Trace {
	tr, _ := r.h.Collect()
	return tr
}`,
	}
	// The helper may also sit in a non-test file of the package, which
	// go/packages loads in both the package and its test variant.
	for _, helperName := range []string{"helpers_test.go", "helpers.go"} {
		for name, helper := range cases {
			t.Run(helperName+"/"+name, func(t *testing.T) {
				user := wrapperUser
				if name == "direct return" {
					user = strings.Replace(user, "tr := r.Collect(t)", "tr, _ := r.Collect(t)", 1)
				}
				fs := lintTypedFiles(t, map[string]string{helperName: helperFile(helper), "svc_test.go": user})
				if len(fs) != 0 {
					t.Fatalf("calls to a verified Collect wrapper must count as Collect; got %v", fs)
				}
			})
		}
	}
}

// Lookalikes are not wrappers, whatever they are called.
func TestCollectWrapperLookalikesDoNotCount(t *testing.T) {
	cases := map[string]string{
		"metrics Collect":             `func (r *rig) Collect(t any) *harness.Trace { r.m.Collect(); return &harness.Trace{} }`,
		"other package's Collect":     `func (r *rig) Collect(t any) *harness.Trace { tr, _ := fake.Collect(); return tr }`,
		"other harness function":      `func (r *rig) Collect(t any) *harness.Trace { tr := r.h.Snapshot(); return tr }`,
		"no call":                     `func (r *rig) Collect(t any) *harness.Trace { return &harness.Trace{} }`,
		"collects but returns nil":    `func (r *rig) Collect(t any) *harness.Trace { r.h.Collect(); return nil }`,
		"returns another trace":       `func (r *rig) Collect(t any) *harness.Trace { _, _ = r.h.Collect(); return r.o }`,
		"one return is not collected": `func (r *rig) Collect(t any) *harness.Trace { tr, err := r.h.Collect(); if err != nil { return r.o }; return tr }`,
		"func literal": `func (r *rig) Collect(t any) *harness.Trace {
	f := func() *harness.Trace { tr, _ := r.h.Collect(); return tr }
	_ = f
	return r.o
}`,
		"returns a package variable": `var other *harness.Trace

func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); _ = tr; return other }`,
		"never returns": `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); _ = tr; panic("unreachable") }`,
		"assigned in a func literal": `func (r *rig) Collect(t any) *harness.Trace {
	var tr *harness.Trace
	f := func() { tr, _ = r.h.Collect() }
	_ = f
	return tr
}`,
		"defer": `func (r *rig) Collect(t any) *harness.Trace {
	defer r.h.Collect()
	return r.o
}`,
		"go statement": `func (r *rig) Collect(t any) *harness.Trace {
	go r.h.Collect()
	return r.o
}`,
		"no trace returned": `func (r *rig) Collect(t any) { _, _ = r.h.Collect() }`,
		// A collected variable written again could hand back another trace.
		"reassigned after collect":    `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); tr = r.o; return tr }`,
		"reassigned by another call":  `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); tr, _ = fake.Collect(); return tr }`,
		"swapped":                     `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); o := r.o; tr, o = o, tr; _ = o; return tr }`,
		"reassigned in a switch":      `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); switch { default: tr = r.o }; return tr }`,
		"range reassigns":             `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); for _, tr = range []*harness.Trace{r.o} {}; return tr }`,
		"var then nil":                `func (r *rig) Collect(t any) *harness.Trace { var tr, _ = r.h.Collect(); tr = nil; return tr }`,
		"named result reassigned":     `func (r *rig) Collect(t any) (tr *harness.Trace) { tr, _ = r.h.Collect(); tr = r.o; return tr }`,
		"named result set in a defer": `func (r *rig) Collect(t any) (tr *harness.Trace) { defer func() { tr = r.o }(); tr, _ = r.h.Collect(); return tr }`,
		"closure reassigns":           `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); func() { tr = r.o }(); return tr }`,
		"pointer alias":               `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); p := &tr; *p = r.o; return tr }`,
		"address passed on": `func set(p **harness.Trace, v *harness.Trace) { *p = v }

func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); set(&tr, r.o); return tr }`,
		"parameter returned first": `func (r *rig) Collect(t any) *harness.Trace { return r.c(r.o, t != nil) }

func (r *rig) c(tr *harness.Trace, early bool) *harness.Trace { if early { return tr }; tr, _ = r.h.Collect(); return tr }`,
		"local returned first": `func (r *rig) Collect(t any) *harness.Trace { tr := r.o; if t != nil { return tr }; tr, _ = r.h.Collect(); return tr }`,
		"deref overwrite":      `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); *tr = *r.o; return tr }`,
	}
	for name, helper := range cases {
		t.Run(name, func(t *testing.T) {
			fs := lintTypedFiles(t, map[string]string{"helpers_test.go": helperFile(helper), "svc_test.go": wrapperUser})
			if name == "no trace returned" {
				// tr := r.Collect(t) does not compile, so the file falls back
				// to names; only no-trace-assertion is certain.
				if got := byRule(fs, RuleNoTraceAssertion); len(got) != 1 {
					t.Errorf("want 1 %s, got %v", RuleNoTraceAssertion, fs)
				}
				return
			}
			if got := byRule(fs, RuleUnguardedAbsence); len(got) != 1 {
				t.Errorf("want 1 %s, got %v", RuleUnguardedAbsence, fs)
			}
			// helpers_test.go defines no tests, so only svc_test.go can be flagged.
			if got := byRule(fs, RuleNoTraceAssertion); len(got) != 1 || !strings.Contains(got[0].Msg, "svc_test.go") {
				t.Errorf("want 1 %s on svc_test.go, got %v", RuleNoTraceAssertion, fs)
			}
		})
	}
}

// A file left out of type-checking (here by a build constraint) that calls a
// wrapper is matched by name as before (it imports the harness, so Collect
// counts by name), and must not crash the wrapper check.
func TestWrapperCallFromUntypedFile(t *testing.T) {
	fs := lintTypedFiles(t, map[string]string{
		"helpers_test.go": helperFile(`func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); return tr }`),
		"svc_test.go":     wrapperUser,
		"ignored_test.go": "//go:build ignore\n\n//subpoena:impl_derived\npackage svc\n\nimport (\n\t\"testing\"\n\n\t\"example.com/svc/pkg/harness\"\n)\n\nvar _ harness.Trace\n\nfunc TestIgnored(t *testing.T) {\n\tr := &rig{}\n\ttr := r.Collect(t)\n\tq := \"\"\n\t_ = tr.Absent(q)\n}\n",
	})
	if len(fs) != 0 {
		t.Fatalf("got %v", fs)
	}
}

// Second review of the wrapper check: writes and aliases the single-write
// count missed, and a Collect that may not run.
func TestCollectWrapperLookalikesDoNotCount2(t *testing.T) {
	cases := map[string]string{
		"parenthesised write": `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); (tr) = r.o; return tr }`,
		"parenthesised deref": `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); *(tr) = *r.o; return tr }`,
		"collect under an if": `func (r *rig) Collect(t any) *harness.Trace { var tr *harness.Trace; if t == nil { tr, _ = r.h.Collect() }; return tr }`,
		"goto past the collect": `func (r *rig) Collect(t any) *harness.Trace {
	var tr *harness.Trace
	goto end
	tr, _ = r.h.Collect()
end:
	return tr
}`,
		"collect in a loop": `func (r *rig) Collect(t any) *harness.Trace { var tr *harness.Trace; for i := 0; i < 0; i++ { tr, _ = r.h.Collect() }; return tr }`,
		"alias overwritten": `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); p := tr; *p = *r.o; return tr }`,
		"alias zeroed":      `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); p := tr; *p = harness.Trace{}; return tr }`,
		"var alias":         `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); var p = tr; *p = *r.o; return tr }`,
		"package alias": `var pp *harness.Trace

func clobber(o *harness.Trace) { *pp = *o }

func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); pp = tr; clobber(r.o); return tr }`,
		"method value":                    `func (r *rig) Collect(t any) *harness.Trace { tr, _ := r.h.Collect(); f := tr.Absent; _ = f; return tr }`,
		"named result swapped in a defer": `func (r *rig) Collect(t any) (out *harness.Trace) { tr, _ := r.h.Collect(); defer func() { out = r.o }(); return tr }`,
		"defer recovers before the collect": `func (r *rig) boom() { panic("x") }

func (r *rig) Collect(t any) *harness.Trace { defer func() { recover() }(); r.boom(); tr, _ := r.h.Collect(); return tr }`,
	}
	for name, helper := range cases {
		t.Run(name, func(t *testing.T) {
			fs := lintTypedFiles(t, map[string]string{"helpers_test.go": helperFile(helper), "svc_test.go": wrapperUser})
			if got := byRule(fs, RuleUnguardedAbsence); len(got) != 1 {
				t.Errorf("want 1 %s, got %v", RuleUnguardedAbsence, fs)
			}
		})
	}
}

// Honest shapes still count after the stricter check.
func TestCollectWrapperHonestShapesCount(t *testing.T) {
	cases := map[string]string{
		"check err, then return": `func (r *rig) Collect(t interface{ Fatal(...any) }) *harness.Trace {
	tr, err := r.h.Collect()
	if err != nil {
		t.Fatal(err)
	}
	return tr
}`,
		"declared, then collected": `func (r *rig) Collect(t any) *harness.Trace { var tr *harness.Trace; tr, _ = r.h.Collect(); return tr }`,
		"nil check and a method call": `func (r *rig) Collect(t any) *harness.Trace {
	tr, _ := r.h.Collect()
	if tr == nil {
		panic("no trace")
	}
	q := ""
	_ = tr.Absent(q)
	return (tr)
}`,
	}
	for name, helper := range cases {
		t.Run(name, func(t *testing.T) {
			fs := lintTypedFiles(t, map[string]string{"helpers_test.go": helperFile(helper), "svc_test.go": wrapperUser})
			if len(fs) != 0 {
				t.Fatalf("an honest wrapper must count: %v", fs)
			}
		})
	}
}
