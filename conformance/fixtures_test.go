//subpoena:impl_derived

// These tests need no Tempo. They verify the fixtures themselves: that they are
// well-formed OTLP/JSON, and that pkg/traceql produces exactly the results in
// expected.yaml (derived by hand from docs/traceql-subset.md). They do not
// assert on captured telemetry, so the harness Collect() rule does not apply.
package conformance

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

const (
	fixturesDir   = "fixtures"
	queriesDir    = "queries"
	invariantsDir = "../invariants"
)

var (
	hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

func loadAll(t *testing.T) ([]*Fixture, []Query) {
	t.Helper()
	fx, err := LoadFixtures(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	qs, err := LoadQueries(invariantsDir, queriesDir)
	if err != nil {
		t.Fatal(err)
	}
	return fx, qs
}

func loadExpected(t *testing.T) Expected {
	t.Helper()
	e, err := LoadExpected("expected.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The scenarios the suite promises to cover; each must be a fixture.
var requiredFixtures = []string{
	"deny_then_exec_violation",
	"deny_without_exec",
	"allow_then_exec",
	"nested_descendant_vs_direct_child",
	"attribute_type_mismatch",
	"multiple_traces_one_push",
}

func TestFixturesWellFormed(t *testing.T) {
	fx, _ := loadAll(t)
	have := map[string]bool{}
	for _, f := range fx {
		have[f.Name] = true
	}
	for _, want := range requiredFixtures {
		if !have[want] {
			t.Errorf("missing required fixture %s", want)
		}
	}
	if len(fx) < 6 {
		t.Fatalf("want at least 6 fixtures, have %d", len(fx))
	}
	seenTrace := map[string]string{}
	seenSpan := map[string]string{}
	for _, f := range fx {
		trs, err := f.Traces()
		if err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		if len(trs) == 0 {
			t.Errorf("%s: no traces", f.Name)
		}
		for _, tr := range trs {
			if !hex32.MatchString(tr.ID) {
				t.Errorf("%s: trace ID %q is not 32 lower-case hex digits", f.Name, tr.ID)
			}
			if tr.ID[0] == '0' {
				t.Errorf("%s: trace ID %s starts with 0; Tempo may trim leading zeros", f.Name, tr.ID)
			}
			if prev := seenTrace[tr.ID]; prev != "" {
				t.Errorf("%s: trace ID %s also in %s", f.Name, tr.ID, prev)
			}
			seenTrace[tr.ID] = f.Name
			for _, sp := range tr.Spans {
				if !hex16.MatchString(sp.ID) || (sp.ParentID != "" && !hex16.MatchString(sp.ParentID)) {
					t.Errorf("%s: bad span or parent ID %q/%q", f.Name, sp.ID, sp.ParentID)
				}
				if prev := seenSpan[sp.ID]; prev != "" {
					t.Errorf("%s: span ID %s also in %s", f.Name, sp.ID, prev)
				}
				seenSpan[sp.ID] = f.Name
			}
		}
	}
}

// Only the orphan fixture may reference a parent that is not in its trace.
func TestOnlyTheOrphanFixtureHasOrphans(t *testing.T) {
	fx, _ := loadAll(t)
	for _, f := range fx {
		trs, _ := f.Traces()
		orphans := 0
		for _, tr := range trs {
			ids := map[string]bool{}
			for _, sp := range tr.Spans {
				ids[sp.ID] = true
			}
			for _, sp := range tr.Spans {
				if sp.ParentID != "" && !ids[sp.ParentID] {
					orphans++
				}
			}
		}
		if want := f.Name == "missing_attribute_and_orphan"; (orphans > 0) != want {
			t.Errorf("%s: %d orphan span(s), want orphans=%v", f.Name, orphans, want)
		}
	}
}

func TestEveryQueryParsesInTheSubset(t *testing.T) {
	_, qs := loadAll(t)
	if len(qs) < 10 {
		t.Fatalf("expected the invariants plus the construct queries, got %d", len(qs))
	}
	for _, q := range qs {
		if _, err := traceql.Parse(q.Text); err != nil {
			t.Errorf("%s: %v", q.Name, err)
		}
		if strings.Contains(q.Text, "\n") {
			t.Errorf("%s: multi-line query; keep it on one line so it can be pasted into OATS and alerts", q.Name)
		}
	}
}

func TestExpectedTableIsConsistent(t *testing.T) {
	fx, qs := loadAll(t)
	exp := loadExpected(t)
	traceIDs := map[string]map[string]bool{}
	for _, f := range fx {
		ids, _ := f.TraceIDs()
		traceIDs[f.Name] = map[string]bool{}
		for _, id := range ids {
			traceIDs[f.Name][id] = true
		}
	}
	queryNames := map[string]bool{}
	for _, q := range qs {
		queryNames[q.Name] = true
		if _, ok := exp.Queries[q.Name]; !ok {
			t.Errorf("expected.yaml has no entry for %s", q.Name)
		}
	}
	for qn, fixtures := range exp.Unsupported {
		if !queryNames[qn] {
			t.Errorf("unsupported names unknown query %s", qn)
		}
		for _, fn := range fixtures {
			if traceIDs[fn] == nil {
				t.Errorf("unsupported %s: unknown fixture %s", qn, fn)
			}
			if len(exp.Queries[qn][fn]) > 0 {
				t.Errorf("%s over %s is both refused and expected to match", qn, fn)
			}
		}
	}
	for qn, byFixture := range exp.Queries {
		if !queryNames[qn] {
			t.Errorf("expected.yaml names unknown query %s", qn)
		}
		for fn, ids := range byFixture {
			if traceIDs[fn] == nil {
				t.Errorf("%s: unknown fixture %s", qn, fn)
				continue
			}
			for _, id := range ids {
				if !traceIDs[fn][id] {
					t.Errorf("%s/%s: trace %s is not in that fixture", qn, fn, id)
				}
			}
		}
	}
}

// TestSubsetMatchesExpected is the half of the conformance suite that runs
// everywhere: every query over every fixture, checked against expected.yaml.
func TestSubsetMatchesExpected(t *testing.T) {
	fx, qs := loadAll(t)
	exp := loadExpected(t)
	matches, nonMatches := 0, 0
	for _, q := range qs {
		parsed, err := traceql.Parse(q.Text)
		if err != nil {
			t.Fatalf("%s: %v", q.Name, err)
		}
		for _, f := range fx {
			trs, err := f.Traces()
			if err != nil {
				t.Fatal(err)
			}
			ms, err := parsed.Eval(trs)
			var ue *traceql.UnsupportedValueError
			if exp.Refused(q.Name, f.Name) {
				if !errors.As(err, &ue) {
					t.Errorf("%s over %s: must be refused (array value), got %v, %v", q.Name, f.Name, ms, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s over %s: %v", q.Name, f.Name, err)
				continue
			}
			var got []string
			for _, m := range ms {
				got = append(got, m.TraceID)
			}
			want := append([]string(nil), exp.Queries[q.Name][f.Name]...)
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s over %s:\n  query: %s\n  got  %v\n  want %v", q.Name, f.Name, q.Text, got, want)
			}
			matches += len(got)
			nonMatches += len(trs) - len(got)
		}
	}
	// Guard against a degenerate pair (evaluator and table both "match nothing"
	// or "match everything"): the table must exercise both outcomes.
	if matches == 0 || nonMatches == 0 {
		t.Fatalf("expected.yaml is degenerate: %d matches, %d non-matches", matches, nonMatches)
	}
}

// The invariants directory is part of the corpus: every file in it is a query.
func TestInvariantsAreInTheCorpus(t *testing.T) {
	_, qs := loadAll(t)
	n := 0
	paths, _ := filepath.Glob(filepath.Join(invariantsDir, "*.traceql"))
	for _, q := range qs {
		if strings.HasPrefix(q.Name, "invariants/") {
			n++
		}
	}
	if n == 0 || n != len(paths) {
		t.Fatalf("corpus has %d invariants, directory has %d", n, len(paths))
	}
}

// The compose file and Tempo config cannot be run here, but they can be kept
// consistent with the client's defaults.
func TestComposeAndTempoConfigMatchClientDefaults(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Image string   `yaml:"image"`
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
	}
	b, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &compose); err != nil {
		t.Fatal(err)
	}
	if len(compose.Services) != 1 {
		t.Fatalf("compose must run only Tempo, has %d services", len(compose.Services))
	}
	tempo := compose.Services["tempo"]
	if !strings.HasPrefix(tempo.Image, "grafana/tempo:") || strings.HasSuffix(tempo.Image, ":latest") {
		t.Errorf("image must be a pinned grafana/tempo tag, got %q", tempo.Image)
	}
	ports := strings.Join(tempo.Ports, " ")
	// Ephemeral loopback host ports: make conformance reads them back with
	// `docker compose port tempo <port>`, so only the container ports are fixed.
	for _, want := range []string{"127.0.0.1::3200", "127.0.0.1::4318"} {
		if !strings.Contains(ports, want) {
			t.Errorf("compose does not publish %s (%v)", want, tempo.Ports)
		}
	}
	var cfg map[string]any
	b, err = os.ReadFile("tempo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "0.0.0.0:4318") {
		t.Error("tempo.yaml must enable the OTLP/HTTP receiver on 4318")
	}
}
