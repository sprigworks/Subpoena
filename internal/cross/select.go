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
// line cannot change its result, so leaving it out can only turn a kill into
// a survivor, which fails the run, never the reverse. A mutant no test was
// seen to execute runs the whole suite.

var moduleRE = regexp.MustCompile(`(?m)^module\s+(\S+)`)

// selectTests maps each mutant's Name to the tests that executed its line.
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
			// A test that fails alone still reports what it executed.
			if _, err := runBin(ctx, o.Timeout, bin, p.Dir, "-test.run", "^"+name+"$", "-test.count=1", "-test.coverprofile="+prof); err != nil && ctx.Err() != nil {
				return nil, ctx.Err()
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
