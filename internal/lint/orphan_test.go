//subpoena:impl_derived

package lint

import (
	"path/filepath"
	"strings"
	"testing"
)

const invA = `{ name = "a" } >> { name = "b" }`

func TestOrphanInvariant(t *testing.T) {
	head := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; \"x/pkg/witness\")\nfunc TestA(t *testing.T) {\n\th.Collect(ctx)\n"
	cases := []struct {
		name string
		call string
		want int
	}{
		{"exact match", "harness.RequireAbsent(t, tr, `" + invA + "`)", 0},
		{"surrounding whitespace is trimmed", "harness.RequireAbsent(t, tr, \"  \\n" + `{ name = \"a\" } >> { name = \"b\" }` + "\\n\")", 0},
		{"interpreted literal equal to the file", "harness.RequireExists(t, tr, \"" + `{ name = \"a\" } >> { name = \"b\" }` + "\")", 0},
		{"one byte off", "harness.RequireAbsent(t, tr, `{ name = \"a\" }  >> { name = \"b\" }`)", 1},
		{"unknown query via Require", "harness.RequireExists(t, tr, `{ name = \"zzz\" }`)", 1},
		{"method Absent", "tr.Absent(`{ name = \"zzz\" }`)", 1},
		{"method Exists", "tr.Exists(`{ name = \"zzz\" }`)", 1},
		{"method Query", "tr.Query(`{ name = \"zzz\" }`)", 1},
		{"matching method literal", "tr.Query(`" + invA + "`)", 0},
		{"variable is not a literal", "q := invariants.MustLoad(invariants.A); harness.RequireAbsent(t, tr, q)", 0},
		{"Sprintf is not a literal", "harness.RequireAbsent(t, tr, fmt.Sprintf(`{ name = %q }`, n))", 0},
		{"literal in a non-query position", "harness.RequireAbsent(t, tr, q, `{ name = \"zzz\" }`)", 0},
		{"Query with no args (url.Query)", "u.Query()", 0},
		{"two bad calls", "tr.Query(`{}`); tr.Absent(`{ }`)", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := lintTree(t, map[string]string{
				"invariants/a.traceql": invA + "\n",
				"a_test.go":            head + "\t" + c.call + "\n}\n",
			})
			var n int
			for _, f := range fs {
				if f.Rule == RuleOrphanInvariant {
					n++
				} else {
					t.Errorf("unexpected finding %v", f)
				}
			}
			if n != c.want {
				t.Fatalf("want %d orphan-invariant, got %d: %v", c.want, n, fs)
			}
		})
	}
}

func TestOrphanInvariantReportsFileAndLine(t *testing.T) {
	src := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; \"x/pkg/witness\")\nfunc TestA(t *testing.T) {\n\th.Collect(ctx)\n\n\ttr.Absent(`{ name = \"zzz\" }`)\n}\n"
	fs := lintTree(t, map[string]string{"invariants/a.traceql": invA, "a_test.go": src})
	only(t, fs, RuleOrphanInvariant, 1)
	if filepath.Base(fs[0].Pos.Filename) != "a_test.go" || fs[0].Pos.Line != 7 {
		t.Fatalf("want a_test.go:7, got %s:%d", fs[0].Pos.Filename, fs[0].Pos.Line)
	}
	if !strings.Contains(fs[0].String(), "a_test.go:7:") || !strings.Contains(fs[0].Msg, "MustLoad") {
		t.Fatalf("message should point at the fix: %s", fs[0])
	}
}

func TestOrphanInvariantNonTestFilesAreIgnored(t *testing.T) {
	fs := lintTree(t, map[string]string{
		"invariants/a.traceql": invA,
		"a.go":                 "package p\nfunc f() { tr.Absent(`{ name = \"zzz\" }`) }\n",
	})
	if len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestOrphanInvariantWithoutInvariantsDir(t *testing.T) {
	src := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; \"x/pkg/witness\")\nfunc TestA(t *testing.T) { h.Collect(ctx); tr.Query(`{}`) }\n"
	fs := lintTree(t, map[string]string{"a_test.go": src})
	only(t, fs, RuleOrphanInvariant, 1)
	if !strings.Contains(fs[0].Msg, "no invariants/") {
		t.Fatalf("should explain the missing directory: %s", fs[0].Msg)
	}
}

func TestOrphanInvariantExplicitDir(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "elsewhere")
	src := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; \"x/pkg/witness\")\nfunc TestA(t *testing.T) { h.Collect(ctx); tr.Query(`" + invA + "`) }\n"
	tree := writeTree(t, map[string]string{"elsewhere/x.traceql": invA, "pkg/a_test.go": src}, dir)
	fs, err := RunWith([]string{filepath.Join(tree, "pkg")}, registry(t), Options{InvariantsDir: inv})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

// Linting a subdirectory finds invariants/ in an ancestor, like the registry.
func TestOrphanInvariantFoundInAncestor(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"invariants/x.traceql": invA,
		"pkg/a_test.go":        "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; \"x/pkg/witness\")\nfunc TestA(t *testing.T) { h.Collect(ctx); tr.Query(`" + invA + "`); tr.Query(`{}`) }\n",
	}, t.TempDir())
	fs, err := Run([]string{filepath.Join(dir, "pkg")}, registry(t))
	if err != nil {
		t.Fatal(err)
	}
	only(t, fs, RuleOrphanInvariant, 1)
}
