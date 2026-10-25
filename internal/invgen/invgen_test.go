//subpoena:impl_derived

package invgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdent(t *testing.T) {
	good := map[string]string{
		"no_exec_after_deny": "NoExecAfterDeny",
		"a":                  "A",
		"deny-then-exec2":    "DenyThenExec2",
	}
	for in, want := range good {
		if got, err := Ident(in); err != nil || got != want {
			t.Errorf("Ident(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "Upper", "1st", "has space", "dot.name"} {
		if _, err := Ident(bad); err == nil {
			t.Errorf("Ident(%q) should fail", bad)
		}
	}
}

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"b_two.traceql", "a_one.traceql", "ignored.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	src, err := Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{`AOne = "a_one"`, `BTwo = "b_two"`, `"a_one",`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "ignored") {
		t.Error("non-.traceql file leaked into output")
	}
	if strings.Index(s, "AOne") > strings.Index(s, "BTwo") {
		t.Error("constants not sorted")
	}
}

func TestGenerateRejectsCollisions(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a_b.traceql", "a-b.traceql"} {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o644)
	}
	if _, err := Generate(dir); err == nil || !strings.Contains(err.Error(), "both map") {
		t.Fatalf("want collision error, got %v", err)
	}
}
