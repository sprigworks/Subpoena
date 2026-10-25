//subpoena:impl_derived

package lint

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const driftAttrsV1 = `groups:
  - id: registry.x
    type: attribute_group
    brief: x
    attributes:
      - id: x.alpha
        type: string
        stability: stable
        brief: first
        annotations:
          tier: all
      - id: x.beta
        type: int
        stability: stable
        brief: second
`

const driftSpansV1 = `groups:
  - id: span.x.work
    type: span
    name: x.work
    span_kind: internal
    stability: stable
    brief: work
    attributes:
      - ref: x.alpha
        requirement_level: required
  - id: span.x.rest
    type: span
    name: x.rest
    span_kind: internal
    stability: stable
    brief: rest
`

const driftSemconvV1 = `package semconv

const (
	SpanXRest = "x.rest"
	SpanXWork = "x.work"
)

const (
	AttrXAlpha = "x.alpha"
	AttrXBeta  = "x.beta"
)
`

// V2: x.gamma is new; x.beta changes type; x.work gains an attribute ref.
const driftAttrsV2 = driftAttrsV1 + `      - id: x.gamma
        type: boolean
        stability: stable
        brief: third
`
const driftSemconvV2 = `package semconv

const (
	SpanXRest = "x.rest"
	SpanXWork = "x.work"
)

const (
	AttrXAlpha = "x.alpha"
	AttrXBeta  = "x.beta"
	AttrXGamma = "x.gamma"
)
`

func testFile(body string) string {
	return "//subpoena:impl_derived\npackage p\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/generated/go/semconv\"\n)\n\nfunc TestA(t *testing.T) {\n" + body + "\n}\n"
}

type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	r := &repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.write(map[string]string{
		"registry/manifest.yaml":          "name: m\n",
		"registry/model/attributes.yaml":  driftAttrsV1,
		"registry/model/spans.yaml":       driftSpansV1,
		"generated/go/semconv/semconv.go": driftSemconvV1,
		"a_test.go":                       testFile("_ = semconv.SpanXWork; _ = semconv.AttrXAlpha"),
	})
	r.commit("base")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (r *repo) write(files map[string]string) {
	r.t.Helper()
	writeTree(r.t, files, r.dir)
}

func (r *repo) commit(msg string) {
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
}

func (r *repo) drift(base string) []Finding {
	r.t.Helper()
	fs, err := CheckRegistryDrift(DriftOptions{Repo: r.dir, Base: base})
	if err != nil {
		r.t.Fatal(err)
	}
	return fs
}

func msgs(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.String() + "\n")
	}
	return b.String()
}

func TestDriftCleanTree(t *testing.T) {
	if fs := newRepo(t).drift(""); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestDriftNewAttributeReferencedByChangedTest(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{
		"registry/model/attributes.yaml":  driftAttrsV2,
		"generated/go/semconv/semconv.go": driftSemconvV2,
		"a_test.go":                       testFile("_ = semconv.SpanXWork; _ = semconv.AttrXGamma"),
	})
	fs := r.drift("")
	only(t, fs, RuleRegistryDrift, 1)
	f := fs[0]
	if filepath.Base(f.Pos.Filename) != "a_test.go" || f.Pos.Line != 11 {
		t.Fatalf("want a_test.go:11, got %s", f)
	}
	for _, want := range []string{"semconv.AttrXGamma", `"x.gamma"`, "new", "HEAD"} {
		if !strings.Contains(f.Msg, want) {
			t.Errorf("message lacks %q: %s", want, f.Msg)
		}
	}
}

func TestDriftRegistryChangeWithoutTestChangeIsQuiet(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"registry/model/attributes.yaml": driftAttrsV2, "generated/go/semconv/semconv.go": driftSemconvV2})
	if fs := r.drift(""); len(fs) != 0 {
		t.Fatalf("no test changed, nothing to report: %v", fs)
	}
}

func TestDriftTestChangeWithoutRegistryChangeIsQuiet(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{"a_test.go": testFile("_ = semconv.SpanXWork; _ = semconv.AttrXAlpha; _ = 1")})
	if fs := r.drift(""); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestDriftChangedTestReferencingOnlyUnchangedIdentifiersIsQuiet(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{
		"registry/model/attributes.yaml":  driftAttrsV2,
		"generated/go/semconv/semconv.go": driftSemconvV2,
		"a_test.go":                       testFile("_ = semconv.SpanXRest; _ = semconv.AttrXAlpha"),
	})
	if fs := r.drift(""); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestDriftChangedAttributeAndChangedSpan(t *testing.T) {
	r := newRepo(t)
	attrs := strings.Replace(driftAttrsV1, "type: int", "type: string", 1) // x.beta changes type
	spans := driftSpansV1 + ""
	spans = strings.Replace(spans, "      - ref: x.alpha\n        requirement_level: required\n",
		"      - ref: x.alpha\n        requirement_level: required\n      - ref: x.beta\n        requirement_level: recommended\n", 1)
	r.write(map[string]string{
		"registry/model/attributes.yaml": attrs,
		"registry/model/spans.yaml":      spans,
		"a_test.go":                      testFile("_ = semconv.SpanXWork\n_ = semconv.AttrXBeta\n_ = semconv.SpanXRest"),
	})
	fs := r.drift("")
	only(t, fs, RuleRegistryDrift, 2)
	all := msgs(fs)
	for _, want := range []string{`span "x.work"`, `attribute "x.beta"`, "changed"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "x.rest") {
		t.Errorf("unchanged span reported:\n%s", all)
	}
	if fs[0].Pos.Line > fs[1].Pos.Line {
		t.Error("findings not ordered by position")
	}
}

func TestDriftIgnoresProseOnlyChanges(t *testing.T) {
	r := newRepo(t)
	attrs := strings.Replace(driftAttrsV1, "brief: first", "brief: a much better description", 1)
	r.write(map[string]string{
		"registry/model/attributes.yaml": attrs,
		"a_test.go":                      testFile("_ = semconv.AttrXAlpha; _ = 1"),
	})
	if fs := r.drift(""); len(fs) != 0 {
		t.Fatalf("brief-only change must not count: %v", fs)
	}
}

func TestDriftTierAnnotationChangeCounts(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{
		"registry/model/attributes.yaml": strings.Replace(driftAttrsV1, "tier: all", "tier: test", 1),
		"a_test.go":                      testFile("_ = semconv.AttrXAlpha; _ = 1"),
	})
	only(t, r.drift(""), RuleRegistryDrift, 1)
}

func TestDriftUntrackedFiles(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{
		"registry/model/more.yaml":        "groups:\n  - id: registry.y\n    type: attribute_group\n    brief: y\n    attributes:\n      - id: x.delta\n        type: string\n        stability: stable\n        brief: d\n",
		"generated/go/semconv/semconv.go": strings.Replace(driftSemconvV1, "AttrXBeta  = \"x.beta\"\n", "AttrXBeta  = \"x.beta\"\n\tAttrXDelta = \"x.delta\"\n", 1),
		"new_test.go":                     testFile("_ = semconv.AttrXDelta"), // untracked
	})
	fs := r.drift("")
	only(t, fs, RuleRegistryDrift, 1)
	if filepath.Base(fs[0].Pos.Filename) != "new_test.go" || !strings.Contains(fs[0].Msg, `"x.delta"`) {
		t.Fatalf("got %s", fs[0])
	}
}

// Literals are not scanned: unknown-telemetry steers tests to constants, and
// fixture strings in unrelated tests would make this rule noisy.
func TestDriftIgnoresStringLiterals(t *testing.T) {
	r := newRepo(t)
	r.write(map[string]string{
		"registry/model/attributes.yaml":  driftAttrsV2,
		"generated/go/semconv/semconv.go": driftSemconvV2,
		"a_test.go":                       "//subpoena:impl_derived\npackage p\n\nvar _ = \"x.gamma\"\n",
	})
	if fs := r.drift(""); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

func TestDriftImportAlias(t *testing.T) {
	r := newRepo(t)
	src := strings.Replace(testFile("_ = sc.AttrXGamma; _ = semconv.AttrXGamma"), `"example.com/m/generated/go/semconv"`, `sc "example.com/m/generated/go/semconv"`, 1)
	r.write(map[string]string{
		"registry/model/attributes.yaml":  driftAttrsV2,
		"generated/go/semconv/semconv.go": driftSemconvV2,
		"a_test.go":                       src,
	})
	// sc.AttrXGamma is reported; semconv.AttrXGamma is not the semconv package here.
	only(t, r.drift(""), RuleRegistryDrift, 1)
}

func TestDriftBaseRefUsesMergeBase(t *testing.T) {
	r := newRepo(t)
	r.git("checkout", "-q", "-b", "feature")
	r.write(map[string]string{
		"registry/model/attributes.yaml":  driftAttrsV2,
		"generated/go/semconv/semconv.go": driftSemconvV2,
		"a_test.go":                       testFile("_ = semconv.AttrXGamma"),
	})
	r.commit("feature work: registry and test together")

	// Working tree against HEAD: nothing is uncommitted.
	if fs := r.drift(""); len(fs) != 0 {
		t.Fatalf("HEAD..working tree is clean, got %v", fs)
	}
	// Against main: the whole branch is one range.
	fs := r.drift("main")
	only(t, fs, RuleRegistryDrift, 1)
	if !strings.Contains(fs[0].Msg, "against main") {
		t.Fatalf("message should name the base: %s", fs[0].Msg)
	}

	// main moves on with an unrelated registry change; the merge-base keeps the
	// range to the feature branch's own work.
	r.git("checkout", "-q", "main")
	r.write(map[string]string{"registry/model/other.yaml": "groups:\n  - id: registry.z\n    type: attribute_group\n    brief: z\n    attributes:\n      - id: x.zeta\n        type: string\n        stability: stable\n        brief: z\n"})
	r.commit("main moves")
	r.git("checkout", "-q", "feature")
	only(t, r.drift("main"), RuleRegistryDrift, 1)
}

func TestDriftErrors(t *testing.T) {
	if _, err := CheckRegistryDrift(DriftOptions{Repo: t.TempDir()}); err == nil {
		t.Error("a non-repository must be an error, not a clean result")
	}
	r := newRepo(t)
	if _, err := CheckRegistryDrift(DriftOptions{Repo: r.dir, Base: "no-such-ref"}); err == nil {
		t.Error("an unknown base must be an error")
	}
	r.write(map[string]string{"registry/model/attributes.yaml": "groups: [\n"})
	if _, err := CheckRegistryDrift(DriftOptions{Repo: r.dir}); err == nil {
		t.Error("unparseable registry yaml must be an error")
	}
}

func TestDiffRegistryOnlyReportsNewAndChanged(t *testing.T) {
	mk := func(attrs, spans map[string]string) *regModel { return &regModel{attrs: attrs, spans: spans} }
	base := mk(map[string]string{"a": "1", "b": "1", "gone": "1"}, map[string]string{"s": "1"})
	head := mk(map[string]string{"a": "1", "b": "2", "c": "1"}, map[string]string{"s": "1", "t": "1"})
	got := DiffRegistry(base, head)
	want := []DriftChange{{"attribute", "b", false}, {"attribute", "c", true}, {"span", "t", true}}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// The real repository's registry parses with the production parser.
func TestRegistryYAMLParsesRealRegistry(t *testing.T) {
	m := &regModel{attrs: map[string]string{}, spans: map[string]string{}}
	for _, f := range []string{"attributes.yaml", "spans.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "registry", "model", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := parseRegistryYAML(m, f, b); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []string{"session.id", "authorization.allowed", "authorization.policy_id"} {
		if m.attrs[a] == "" {
			t.Errorf("attribute %s not parsed", a)
		}
	}
	if len(m.spans) != 3 || m.spans["agent.session.exec"] == "" {
		t.Errorf("spans not parsed: %v", m.spans)
	}
}
