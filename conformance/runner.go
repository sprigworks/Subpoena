package conformance

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Corpus is everything an evaluator is checked against: the queries (the
// invariants and the construct queries), the fixtures, the expected matches
// and the queries outside the subset.
type Corpus struct {
	Queries  []Query
	Fixtures []*Fixture
	Expected Expected
	Rejected []string

	fixturePaths map[string]string
}

// LoadCorpus reads the corpus of the repository at root.
func LoadCorpus(root string) (*Corpus, error) {
	dir := filepath.Join(root, "conformance")
	qs, err := LoadQueries(filepath.Join(root, "invariants"), filepath.Join(dir, "queries"))
	if err != nil {
		return nil, err
	}
	fx, err := LoadFixtures(filepath.Join(dir, "fixtures"))
	if err != nil {
		return nil, err
	}
	c := &Corpus{Queries: qs, Fixtures: fx, fixturePaths: map[string]string{}}
	for _, f := range fx {
		c.fixturePaths[f.Name] = filepath.Join(dir, "fixtures", f.Name+".json")
	}
	if c.Expected, err = LoadExpected(filepath.Join(dir, "expected.yaml")); err != nil {
		return nil, err
	}
	if c.Rejected, err = LoadRejected(filepath.Join(dir, "rejected.traceql")); err != nil {
		return nil, err
	}
	return c, nil
}

// Expected is expected.yaml.
type Expected struct {
	// Queries maps query name -> fixture name -> matching trace IDs.
	Queries map[string]map[string][]string `yaml:"queries"`
	// Unsupported maps query name -> the fixtures it must be refused over,
	// because it reads an array or map value in them.
	Unsupported map[string][]string `yaml:"unsupported"`
}

// Refused reports whether query must be refused over fixture.
func (e Expected) Refused(query, fixture string) bool {
	for _, f := range e.Unsupported[query] {
		if f == fixture {
			return true
		}
	}
	return false
}

// LoadExpected reads expected.yaml.
func LoadExpected(path string) (Expected, error) {
	var e Expected
	b, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := yaml.Unmarshal(b, &e); err != nil {
		return e, fmt.Errorf("conformance: %s: %w", path, err)
	}
	return e, nil
}

// LoadRejected reads rejected.traceql: one query per line, # comments.
func LoadRejected(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

// Mismatch is one case where the evaluator disagreed with the corpus. Fixture
// is empty for a rejected query the evaluator accepted.
type Mismatch struct {
	Query, Text, Fixture string
	Got, Want            []string
	Problem              string // set when the evaluator failed or was wrong in kind
}

func (m Mismatch) String() string {
	if m.Fixture == "" {
		return fmt.Sprintf("%s: outside the subset, must exit 2: %s", m.Text, m.Problem)
	}
	if m.Problem != "" {
		return fmt.Sprintf("%s over %s: %s\n  query: %s", m.Query, m.Fixture, m.Problem, m.Text)
	}
	return fmt.Sprintf("%s over %s:\n  query: %s\n  got  %v\n  want %v", m.Query, m.Fixture, m.Text, m.Got, m.Want)
}

// Report is the outcome of RunEvaluator.
type Report struct {
	Runs       int
	Mismatches []Mismatch
}

// RunEvaluator runs argv + [QUERY_FILE, TRACES_FILE] for every query over
// every fixture and for every rejected query, and compares each answer with
// the corpus (the protocol in docs/ports.md). The error is for failures of
// the runner itself; an evaluator's failures are mismatches.
func RunEvaluator(ctx context.Context, c *Corpus, argv []string) (*Report, error) {
	if len(argv) == 0 {
		return nil, errors.New("conformance: no evaluator command")
	}
	tmp, err := os.MkdirTemp("", "subpoena-conform-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	write := func(name, text string) (string, error) {
		p := filepath.Join(tmp, strings.ReplaceAll(name, "/", "_")+".traceql")
		return p, os.WriteFile(p, []byte(text+"\n"), 0o644)
	}
	r := &Report{}
	for _, q := range c.Queries {
		qf, err := write(q.Name, q.Text)
		if err != nil {
			return nil, err
		}
		for _, f := range c.Fixtures {
			r.Runs++
			want := append([]string{}, c.Expected.Queries[q.Name][f.Name]...)
			sort.Strings(want)
			m := Mismatch{Query: q.Name, Text: q.Text, Fixture: f.Name, Want: want}
			out, code, stderr, err := evaluate(ctx, argv, qf, c.fixturePaths[f.Name])
			refuse := c.Expected.Refused(q.Name, f.Name)
			switch {
			case err != nil:
				return nil, err
			case refuse && code == 3:
				continue
			case refuse:
				m.Problem = fmt.Sprintf("reads an array value here, must exit 3; exit %d: %s", code, stderr)
			case code != 0:
				m.Problem = fmt.Sprintf("exit %d: %s", code, stderr)
			default:
				m.Got = out
				if strings.Join(m.Got, ",") == strings.Join(want, ",") {
					continue
				}
			}
			r.Mismatches = append(r.Mismatches, m)
		}
	}
	// A rejected query is checked over one fixture: the evaluator must not
	// get as far as evaluating it.
	anyFixture := c.fixturePaths[c.Fixtures[0].Name]
	for i, q := range c.Rejected {
		qf, err := write(fmt.Sprintf("rejected_%02d", i), q)
		if err != nil {
			return nil, err
		}
		r.Runs++
		_, code, _, err := evaluate(ctx, argv, qf, anyFixture)
		if err != nil {
			return nil, err
		}
		if code != 2 {
			r.Mismatches = append(r.Mismatches, Mismatch{Text: q, Problem: fmt.Sprintf("exit %d", code)})
		}
	}
	return r, nil
}

// evaluate runs one case. It returns the normalised, sorted IDs printed, the
// exit code and stderr; err only if the command could not be started.
func evaluate(ctx context.Context, argv []string, queryFile, tracesFile string) ([]string, int, string, error) {
	cmd := exec.CommandContext(ctx, argv[0], append(append([]string{}, argv[1:]...), queryFile, tracesFile)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil, exit.ExitCode(), strings.TrimSpace(stderr.String()), nil
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("conformance: run %s: %w", argv[0], err)
	}
	ids := []string{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			ids = append(ids, NormID(l))
		}
	}
	sort.Strings(ids)
	return ids, 0, "", nil
}
