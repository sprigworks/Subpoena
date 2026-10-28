package cross

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Test selection (Options.Select). After the green baseline each test runs
// alone with a coverage profile of the mutants' packages; a mutant then runs
// only the tests that executed its line. A test that never runs the mutated
// line cannot change its result, unless it reaches it where coverage cannot
// see (a subprocess), so every mutant selection did not kill runs again on
// the whole suite, and group runs always use the whole suite. A kill needs
// the selected tests to be green without the mutant: a test that fails alone,
// and a selected subset that fails together, are errors. A mutant no test was
// seen to execute runs the whole suite.

var moduleRE = regexp.MustCompile(`(?m)^module\s+(\S+)`)

// selectTests maps each mutant's Name to the tests that executed its line.
// A test that fails alone, green in the full baseline, depends on the tests
// before it: run in a subset it could fail with or without the mutant, and
// that would be a kill, so it is an error.
//
//subpoena:enforcement_point
func selectTests(ctx context.Context, o Options, sb sandbox, pkgs string, mutants []Mutant) (map[string][]string, error) {
	gomod, err := os.ReadFile(filepath.Join(sb.dir, "go.mod"))
	if err != nil {
		return nil, err
	}
	m := moduleRE.FindSubmatch(gomod)
	if m == nil {
		return nil, fmt.Errorf("cross: select: no module line in go.mod")
	}
	modPath := string(m[1])
	// The packages the mutants live in, as coverage reports their files.
	coverPkgs := map[string]bool{}
	for _, mu := range mutants {
		coverPkgs[importPath(modPath, mu.File)] = true
	}
	var cp []string
	for p := range coverPkgs {
		cp = append(cp, p)
	}
	sort.Strings(cp)

	out, err := goIn(ctx, o.Timeout, sb, "list", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles", pkgs)
	if err != nil {
		return nil, fmt.Errorf("cross: select: go list: %w\n%s", err, tail(out, 20))
	}
	type pkg struct {
		ImportPath, Dir           string
		TestGoFiles, XTestGoFiles []string
	}
	bins, err := os.MkdirTemp("", "subpoena-cross-select-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(bins)
	sel := map[string]map[string]bool{}
	dec := json.NewDecoder(strings.NewReader(out))
	for n := 0; dec.More(); n++ {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("cross: select: go list output: %w", err)
		}
		if len(p.TestGoFiles)+len(p.XTestGoFiles) == 0 {
			continue
		}
		bin := filepath.Join(bins, strconv.Itoa(n)+".test")
		if out, err := goIn(ctx, o.Timeout, sb, "test", "-c", "-cover", "-covermode=set", "-coverpkg="+strings.Join(cp, ","), "-o", bin, p.ImportPath); err != nil {
			return nil, fmt.Errorf("cross: select: build %s: %w\n%s", p.ImportPath, err, tail(out, 20))
		}
		list, err := runBin(ctx, o.Timeout, bin, p.Dir, "-test.list", ".")
		if err != nil {
			return nil, fmt.Errorf("cross: select: list %s: %w\n%s", p.ImportPath, err, tail(list, 20))
		}
		for _, name := range strings.Fields(list) {
			if strings.HasPrefix(name, "ok") || !isTestName(name) {
				continue
			}
			prof := filepath.Join(bins, strconv.Itoa(n)+"-"+name+".cov")
			out, err := runBin(ctx, o.Timeout, bin, p.Dir, "-test.run", "^"+name+"$", "-test.count=1", "-test.coverprofile="+prof)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// The verdict is kept apart from the return so that removing the
			// return (make cross-self) still compiles.
			var aloneErr error
			if err != nil {
				aloneErr = fmt.Errorf("cross: select: %s %s fails when run alone, so a subset of the suite could fail without the mutant; fix the test or drop -select:\n%s", p.ImportPath, name, tail(out, 20))
			}
			if aloneErr != nil {
				return nil, aloneErr //subpoena:enforcement
			}
			hit, err := executedLines(prof)
			if err != nil {
				continue // no profile: the test selects nothing, so it is never left out by mistake below
			}
			for _, mu := range mutants {
				if hit(importPath(modPath, mu.File)+"/"+path.Base(mu.File), mu.Line) {
					if sel[mu.Name()] == nil {
						sel[mu.Name()] = map[string]bool{}
					}
					sel[mu.Name()][name] = true
				}
			}
		}
	}
	res := map[string][]string{}
	for k, set := range sel {
		for name := range set {
			res[k] = append(res[k], name)
		}
		sort.Strings(res[k])
	}
	return res, nil
}

func isTestName(s string) bool {
	for _, p := range []string{"Test", "Example", "Fuzz"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// importPath is the import path of the package holding file (relative to the
// module root, slash-separated).
func importPath(modPath, file string) string {
	if d := path.Dir(file); d != "." {
		return modPath + "/" + d
	}
	return modPath
}

// executedLines reads a coverage profile and reports whether a block that
// ran spans the given line of the given file (import path + "/" + name).
func executedLines(profile string) (func(file string, line int) bool, error) {
	f, err := os.Open(profile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type span struct{ from, to int }
	ran := map[string][]span{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		if strings.HasPrefix(ln, "mode:") {
			continue
		}
		// file.go:l1.c1,l2.c2 statements count
		colon := strings.LastIndex(ln, ":")
		fields := strings.Fields(ln[colon+1:])
		if colon < 0 || len(fields) != 3 || fields[2] == "0" {
			continue
		}
		var l1, c1, l2, c2 int
		if _, err := fmt.Sscanf(fields[0], "%d.%d,%d.%d", &l1, &c1, &l2, &c2); err != nil {
			continue
		}
		ran[ln[:colon]] = append(ran[ln[:colon]], span{l1, l2})
	}
	return func(file string, line int) bool {
		for _, s := range ran[file] {
			if s.from <= line && line <= s.to {
				return true
			}
		}
		return false
	}, sc.Err()
}

// runBin runs a compiled test binary in dir, killing its group on timeout.
func runBin(ctx context.Context, timeout time.Duration, bin, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	killGroupOnCancel(cmd)
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runFilter is the go test -run pattern for ms, or "" to run every test: one
// mutant with no selected test means the whole suite.
func runFilter(sel map[string][]string, ms []Mutant) string {
	if sel == nil {
		return ""
	}
	set := map[string]bool{}
	for _, m := range ms {
		names := sel[m.Name()]
		if len(names) == 0 {
			return ""
		}
		for _, n := range names {
			set[n] = true
		}
	}
	var names []string
	for n := range set {
		names = append(names, regexp.QuoteMeta(n))
	}
	sort.Strings(names)
	return "^(" + strings.Join(names, "|") + ")$"
}

// checkSubsets runs each distinct selected subset once on the unmutated
// copy. A subset can fail where the full suite and each test alone pass (one
// test leaves state another trips on, and the test that resets it was left
// out); a mutant run on it would be red without the mutant, a kill, so a red
// subset is an error.
//
//subpoena:enforcement_point
func checkSubsets(ctx context.Context, o Options, sb sandbox, pkgs string, mutants []Mutant) error {
	seen := map[string]bool{}
	for _, m := range mutants {
		f := runFilter(o.selected, []Mutant{m})
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out, err := goIn(ctx, o.Timeout, sb, "test", "-count=1", "-run", f, pkgs)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var redErr error
		if err != nil {
			redErr = fmt.Errorf("cross: select: the tests %s fail together without any mutant, so they depend on tests left out; fix the tests or drop -select:\n%s", f, tail(out, 20))
		}
		if redErr != nil {
			return redErr //subpoena:enforcement
		}
	}
	return nil
}

// confirmOnWholeSuite runs again, on the whole suite, every single mutant
// that selection did not kill, and returns the results with those replaced.
//
//subpoena:enforcement_point
func confirmOnWholeSuite(ctx context.Context, o Options, workers []sandbox, pkgs string, mutants []Mutant, results []Result) ([]Result, error) {
	var again []Mutant
	var at []int
	for i, r := range results {
		if r.Outcome != Killed && runFilter(o.selected, []Mutant{mutants[i]}) != "" {
			again = append(again, mutants[i])
			at = append(at, i)
		}
	}
	if len(again) == 0 {
		return results, nil
	}
	fmt.Fprintf(o.Log, "select: %d mutant(s) not killed by their selected tests; running them on the whole suite\n", len(again))
	o.selected = nil
	redo, err := runSingles(ctx, o, workers, pkgs, again)
	if err != nil {
		return nil, err
	}
	out := results
	fmt.Fprintf(o.Log, "select: %d mutant(s) judged again on the whole suite\n", len(redo))
	out = merged(results, at, redo) //subpoena:enforcement
	return out, nil
}

// merged returns rs with rs[at[j]] replaced by redo[j].
func merged(rs []Result, at []int, redo []Result) []Result {
	out := append([]Result(nil), rs...)
	for j, i := range at {
		out[i] = redo[j]
	}
	return out
}
