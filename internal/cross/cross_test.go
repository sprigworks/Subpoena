//subpoena:impl_derived

package cross

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goMod = "module mini\n\ngo 1.24\n"

const authOK = `package mini

import "errors"

var ErrDenied = errors.New("denied")

// Allow decides.
//
//subpoena:enforcement_point
func Allow(admin bool) error {
	if !admin {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

const strongTest = `package mini

import "testing"

func TestDeny(t *testing.T) {
	if Allow(false) == nil {
		t.Fatal("non-admin must be denied")
	}
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

const weakTest = `package mini

import "testing"

func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

func module(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = goMod
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

func run(t *testing.T, dir string) (*Report, error) {
	t.Helper()
	return Run(context.Background(), Options{Target: dir})
}

func TestFindMutants(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	ms, err := FindMutants(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Func != "Allow" || ms[0].Line != 12 || ms[0].Removed != "return ErrDenied" {
		t.Fatalf("unexpected mutants: %+v", ms)
	}
}

func TestStrongSuiteKillsMutant(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Killed || rep.Failed() {
		t.Fatalf("want killed, got %+v", rep.Results)
	}
	if got := rep.Results[0].Failing; len(got) != 1 || got[0] != "TestDeny" {
		t.Fatalf("failing tests: %v", got)
	}
	// The original tree must be untouched.
	b, _ := os.ReadFile(filepath.Join(dir, "auth.go"))
	if string(b) != authOK {
		t.Fatal("cross-examination modified the original tree")
	}
}

func TestWeakSuiteLetsMutantSurvive(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": weakTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Survived || !rep.Failed() {
		t.Fatalf("want survived, got %+v", rep.Results)
	}
	if rep.Results[0].Outcome != "enforcement-mutant-survived" || rep.Results[0].Mutant.Func != "Allow" {
		t.Fatalf("report wording changed: %+v", rep.Results[0])
	}
}

func TestNonCompilingMutantIsInvalidNotKilled(t *testing.T) {
	// The removed statement declares a variable used later, so the mutant
	// cannot build whatever cross-examination does.
	src := strings.Replace(authOK, `	if !admin {
		return ErrDenied //subpoena:enforcement
	}`, `	err := ErrDenied //subpoena:enforcement
	if !admin {
		return err
	}`, 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Invalid || !rep.Failed() {
		t.Fatalf("a compile failure must not count as a kill: %+v", rep.Results[0])
	}
}

func TestImportOnlyUsedByTheRemovedStatementIsPruned(t *testing.T) {
	// errors is imported only for the removed line: without pruning the
	// mutant would not build and would prove nothing.
	src := strings.Replace(authOK, "var ErrDenied = errors.New(\"denied\")\n", "var ErrDenied error\n", 1)
	src = strings.Replace(src, "return ErrDenied //subpoena:enforcement", "return errors.New(\"denied\") //subpoena:enforcement", 1)
	test := strings.Replace(strongTest, "Allow(false) == nil", "Allow(false) == nil && ErrDenied == nil", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Killed {
		t.Fatalf("want killed after pruning the unused import, got %+v", rep.Results[0])
	}
}

func TestRelativeReplaceStillResolvesInTheCopy(t *testing.T) {
	// mini depends on a sibling module through `replace ... => ../lib`, as a
	// service developed against a local checkout does.
	root := t.TempDir()
	write := func(p, src string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "lib", "go.mod"), "module example.com/lib\n\ngo 1.24\n")
	write(filepath.Join(root, "lib", "lib.go"), "package lib\n\nfunc Admin(name string) bool { return name == \"root\" }\n")
	write(filepath.Join(root, "mini", "go.mod"), "module mini\n\ngo 1.24\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => ../lib\n")
	write(filepath.Join(root, "mini", "auth.go"), authOK)
	write(filepath.Join(root, "mini", "auth_test.go"), strings.Replace(strongTest, `import "testing"`, "import (\n\t\"testing\"\n\n\t\"example.com/lib\"\n)", 1)+
		"\nfunc TestLib(t *testing.T) {\n\tif !lib.Admin(\"root\") {\n\t\tt.Fatal(\"lib\")\n\t}\n}\n")
	rep, err := run(t, filepath.Join(root, "mini"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Killed {
		t.Fatalf("want killed, got %+v", rep.Results[0])
	}
}

func TestRedBaselineIsAnError(t *testing.T) {
	failing := strongTest + "\nfunc TestBroken(t *testing.T) { t.Fatal(\"red\") }\n"
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": failing})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("want baseline error, got %v", err)
	}
}

func TestNoMarkerIsAnError(t *testing.T) {
	src := strings.Replace(authOK, " //subpoena:enforcement", "", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "vacuous") {
		t.Fatalf("want vacuous cross-examination error, got %v", err)
	}
}

func TestMarkerOnCompoundStatementIsRejected(t *testing.T) {
	src := strings.Replace(authOK, "if !admin {", "if !admin { //subpoena:enforcement", 1)
	src = strings.Replace(src, " //subpoena:enforcement\n\t}", "\n\t}", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	if _, err := FindMutants(dir, dir); err == nil {
		t.Fatal("a marker on an if line must be rejected rather than remove the whole if")
	}
}

func TestMarkersOutsideEnforcementPointsAreIgnored(t *testing.T) {
	src := strings.Replace(authOK, "//\n//subpoena:enforcement_point\n", "", 1)
	dir := module(t, map[string]string{"auth.go": src})
	ms, err := FindMutants(dir, dir)
	if err != nil || len(ms) != 0 {
		t.Fatalf("want none, got %v %v", ms, err)
	}
}

func TestMarkerRegexDoesNotMatchEnforcementPoint(t *testing.T) {
	if isEnforcementComment("//subpoena:enforcement_point") {
		t.Fatal("enforcement_point must not be treated as the statement marker")
	}
	if !isEnforcementComment("//subpoena:enforcement") || !isEnforcementComment("// subpoena:enforcement because") {
		t.Fatal("statement marker not recognised")
	}
}
