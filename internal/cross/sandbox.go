// The sandboxes mutants run in, and running go inside them.

package cross

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

func moduleRoot(dir string) (string, error) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("cross: no go.mod above %s", dir)
		}
	}
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

// sandbox is one copy of the module that mutants are run in, the GOWORK its go
// commands use ("" to inherit the environment's), the discovery copy it is made
// from, the run's directory for trees it could not remove, and the run's key.
type sandbox struct {
	dir, work, template, stale string
	key                        string // handed to test binaries, to sign witness failures
}

// fresh replaces the copy with the discovery copy, so a run sees nothing an
// earlier run left. The path stays: the go build cache keys on it.
func (sb sandbox) fresh() error {
	if err := removeTree(sb.dir); err != nil {
		// A detached child can still be writing there. Move the tree aside, into
		// the run's own directory, and the child writes on unseen until the run
		// ends and removeLeftovers takes it.
		aside, terr := os.MkdirTemp(sb.stale, "copy-")
		if terr != nil {
			return fmt.Errorf("cross: reset copy: %w", err)
		}
		if rerr := os.Rename(sb.dir, filepath.Join(aside, "copy")); rerr != nil {
			return fmt.Errorf("cross: reset copy: %w", err)
		}
	}
	if err := copyTree(sb.template, sb.dir); err != nil {
		return fmt.Errorf("cross: copy tree: %w", err)
	}
	return nil
}

// freshMutant is fresh with the mutated files written back.
func (sb sandbox) freshMutant(mutated map[string][]byte) error {
	if err := sb.fresh(); err != nil {
		return err
	}
	for file, b := range mutated {
		if err := os.WriteFile(filepath.Join(sb.dir, filepath.FromSlash(file)), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// removeLeftovers removes a tree of the run as it ends. A detached child can be
// writing there, and each try can lose to it, but a tree that goes once is gone:
// the child's directory went with it. The tree holds mutated source, so one that
// will not go is named.
func removeLeftovers(log io.Writer, dir string) {
	for range removeTries {
		if removeTree(dir) == nil {
			return
		}
		time.Sleep(removeWait)
	}
	fmt.Fprintf(log, "cross: could not remove %s, which holds mutated source: a process a test started may still be writing there\n", dir)
}

// removeTries and removeWait bound removeLeftovers.
const (
	removeTries = 50
	removeWait  = 100 * time.Millisecond
)

// runSingles runs each mutant alone, on as many copies as there are workers,
// and returns the results in mutants' order. The first error stops the rest.
//
//subpoena:enforcement_point
func runSingles(ctx context.Context, o Options, workers []sandbox, pkgs string, mutants []Mutant) ([]Result, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	results := make([]Result, len(mutants))
	next := make(chan int)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	for _, sb := range workers {
		wg.Add(1)
		go func(sb sandbox) {
			defer wg.Done()
			for i := range next {
				if ctx.Err() != nil {
					continue
				}
				res, err := runCase(ctx, o, sb, pkgs, []Mutant{mutants[i]})
				if err != nil {
					once.Do(func() { firstErr = err; cancel(err) })
					continue
				}
				results[i] = res
			}
		}(sb)
	}
feed:
	for i := range mutants {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	// A cancel can stop the feed between two runs, with no run left to
	// report it: unrun mutants must not come back as zero results.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cross: run stopped: %w", err) //subpoena:enforcement
	}
	return results, nil
}

// goIn runs go in a sandbox copy.
func goIn(ctx context.Context, timeout time.Duration, sb sandbox, args ...string) (string, error) {
	env := append(os.Environ(), crossmark.Env+"="+sb.key)
	if sb.work != "" {
		env = append(env, "GOWORK="+sb.work)
	}
	return goCmdEnv(ctx, timeout, sb.dir, env, args...)
}

// lockedWriter serializes progress lines from parallel mutants.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// errTimeout is returned by goCmd when the command ran past its timeout.
var errTimeout = errors.New("timed out")

func goCmd(ctx context.Context, timeout time.Duration, dir string, args ...string) (string, error) {
	return goCmdEnv(ctx, timeout, dir, nil, args...)
}

// goCmdEnv is goCmd with an environment; nil inherits this process's.
func goCmdEnv(ctx context.Context, timeout time.Duration, dir string, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = env
	killGroupOnCancel(cmd)
	// A process left holding the output pipe must not hold up the verdict.
	cmd.WaitDelay = 5 * time.Second
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("go %s: %w after %v", args[0], errTimeout, timeout)
	}
	return buf.String(), err
}

// testTimeoutRE matches the test binary's own -timeout panic.
var testTimeoutRE = regexp.MustCompile(`(?m)^panic: test timed out after `)

// timedOut reports whether a failed go test run ended by a timeout, either
// goCmd's or the test binary's own, rather than by a failing test.
func timedOut(out string, err error) bool {
	return errors.Is(err, errTimeout) || testTimeoutRE.MatchString(out)
}

// buildRE matches go test's own line. The text alone can be anything a test or a
// panic printed.
var buildRE = regexp.MustCompile(`(?m)^FAIL\s+\S+\s+\[(build|setup) failed\]$`)

func buildFailed(out string) bool { return buildRE.MatchString(out) }

// failingTests names the tests that failed in raw, from their fail events.
func failingTests(raw string) []string {
	var names []string
	for _, e := range failEvents(raw) {
		if !slices.Contains(names, e.Test) {
			names = append(names, e.Test)
		}
	}
	if len(names) == 0 {
		names = []string{"(package failed without a named test failure)"}
	}
	return names
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
