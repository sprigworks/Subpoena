package cross

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// runner is how every go test of a run starts its test binaries: the baseline,
// a selected subset, a mutant run and its reruns alike. A test red only under
// the way it was started is then red on all of them, and no kill.
//
// go test -json gives no exit code, so the test binaries run under -exec with a
// small wrapper that records it. The wrapper is Go, built here with the go
// command cross needs anyway: a shell would filter the environment (dash drops
// a variable named app.mode) and may not be there. A project's own -exec, from
// GOFLAGS, or go_$GOOS_$GOARCH_exec for another platform, runs under the wrapper,
// so it stays in place. Cross cannot run without the wrapper: there is no mode
// that reads the output alone.
type runner struct {
	dir  string // holds the wrapper and each run's record
	exec string // the -exec value, less the record's path: wrapper, then user
	user string // the project's own runner, "" if none
	n    atomic.Int64
}

// wrapperSource is the wrapper: wrapper <record> <command...>. It adds nothing
// to the environment. It asks the test binary for a heap profile, which package
// testing writes only when m.Run ends, so a binary that exits 1 in the middle
// of a test (os.Exit in the code under test) leaves none, whatever it printed:
// the profile is the one sign of a finished run that printed text cannot give.
var wrapperSource = `package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	record, argv := os.Args[1], os.Args[2:]
	done := record + ".done." + strconv.Itoa(os.Getpid())
	if at := slices.IndexFunc(argv, func(a string) bool { return strings.HasPrefix(a, "-test.") }); at >= 0 {
		argv = slices.Insert(argv, at, "-test.memprofile="+done)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-cross wrapper:", err)
		os.Exit(127)
	}
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	label := strconv.Itoa(code)
	_, err := os.Stat(done)
	os.Remove(done)
	if code == 1 && err != nil {
		label = "1-before-testing-ended"
	}
	dir, _ := os.Getwd()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	if f, err := os.OpenFile(record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintln(f, label, dir)
		f.Close()
	}
	if code < 0 {
		code = 2
	}
	os.Exit(code)
}
`

// newRunner builds the wrapper. A failure here stops the run: without it no exit
// code can be read, and a death beside a failure message would pass as a kill.
//
//subpoena:enforcement_point
func newRunner(ctx context.Context, root string) (*runner, error) {
	out, err := goCmd(ctx, time.Minute, root, "env", "-json", "GOFLAGS", "GOOS", "GOARCH", "GOHOSTOS", "GOHOSTARCH")
	if err != nil {
		return nil, fmt.Errorf("cross: go env: %w\n%s", err, tail(out, 20))
	}
	var env struct{ GOFLAGS, GOOS, GOARCH, GOHOSTOS, GOHOSTARCH string }
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		return nil, fmt.Errorf("cross: go env output: %w", err)
	}
	dir, err := os.MkdirTemp("", "subpoena-cross-run-")
	if err != nil {
		return nil, err
	}
	r := &runner{dir: dir, user: userExec(env.GOFLAGS)}
	if r.user == "" && (env.GOOS != env.GOHOSTOS || env.GOARCH != env.GOHOSTARCH) {
		name := "go_" + env.GOOS + "_" + env.GOARCH + "_exec"
		if p, err := exec.LookPath(name); err == nil {
			r.user = p
		}
	}
	src := filepath.Join(dir, "wrapper.go")
	bin := filepath.Join(dir, "wrapper")
	if env.GOHOSTOS == "windows" {
		bin += ".exe"
	}
	if err := os.WriteFile(src, []byte(wrapperSource), 0o644); err != nil {
		r.remove()
		return nil, err
	}
	// The wrapper runs here, whatever the project builds for or with.
	build := append(os.Environ(), "GOFLAGS=", "GOWORK=off", "CGO_ENABLED=0", "GOOS="+env.GOHOSTOS, "GOARCH="+env.GOHOSTARCH)
	if out, err := goCmdEnv(ctx, 2*time.Minute, dir, build, "build", "-buildvcs=false", "-o", bin, src); err != nil {
		r.remove()
		return nil, fmt.Errorf("cross: build the exit-code wrapper: %w\n%s", err, tail(out, 20)) //subpoena:enforcement
	}
	if r.exec, err = quoteField(bin); err != nil {
		r.remove()
		return nil, err
	}
	return r, nil
}

func (r *runner) remove() { removeTree(r.dir) }

// userExec is the -exec a project set in GOFLAGS, "" if none. The last one wins,
// as it does for go.
func userExec(goflags string) string {
	found := ""
	for _, f := range splitQuoted(goflags) {
		f = strings.TrimPrefix(f, "-")
		if v, ok := strings.CutPrefix(strings.TrimPrefix(f, "-"), "exec="); ok {
			found = v
		}
	}
	return found
}

// splitQuoted splits as go splits GOFLAGS: on space, with a field that starts
// with a quote running to the matching quote.
func splitQuoted(s string) []string {
	var out []string
	for {
		s = strings.TrimLeft(s, " \t\n\r")
		if s == "" {
			return out
		}
		if q := s[0]; q == '\'' || q == '"' {
			if end := strings.IndexByte(s[1:], q); end >= 0 {
				out = append(out, s[1:1+end])
				s = s[end+2:]
				continue
			}
		}
		end := strings.IndexAny(s, " \t\n\r")
		if end < 0 {
			return append(out, s)
		}
		out = append(out, s[:end])
		s = s[end:]
	}
}

// quoteField quotes s for go's -exec, which splits as GOFLAGS does. A field
// cannot hold both kinds of quote.
func quoteField(s string) (string, error) {
	switch {
	case !strings.Contains(s, "'"):
		return "'" + s + "'", nil
	case !strings.Contains(s, `"`):
		return `"` + s + `"`, nil
	}
	return "", fmt.Errorf("cross: %s holds both kinds of quote, which go test -exec cannot carry; set TMPDIR to another directory", s)
}

// test runs go test in sb under the wrapper, and adds to its output an exit
// event for each package that failed.
func (r *runner) test(ctx context.Context, o Options, sb sandbox, args ...string) (string, error) {
	record := filepath.Join(r.dir, "codes-"+strconv.FormatInt(r.n.Add(1), 10))
	field, err := quoteField(record)
	if err != nil {
		return "", err
	}
	value := r.exec + " " + field
	if r.user != "" {
		value += " " + r.user
	}
	raw, err := goIn(ctx, o.Timeout, sb, append([]string{"test", "-exec", value}, args...)...)
	return raw + exitEvents(record, raw, sb.dir, o.modPath), err
}

// exitEvents gives an exit event for each package that failed in raw, a run in
// the module copy at root. go test runs a binary in its package's directory,
// which names the package. A failed package with no record is exitUnknown, and
// counts as dead.
func exitEvents(record, raw, root, modPath string) string {
	codes := map[string]string{}
	base, err := filepath.EvalSymlinks(root)
	if b, rerr := os.ReadFile(record); err == nil && rerr == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if code, dir, ok := strings.Cut(line, " "); ok {
				if rel, err := filepath.Rel(base, dir); err == nil {
					codes[filepath.ToSlash(rel)] = code
				}
			}
		}
	}
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Action, Package, Test string }
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil || e.Action != "fail" || e.Test != "" {
			continue
		}
		code, ok := codes[strings.TrimPrefix(strings.TrimPrefix(e.Package, modPath), "/")]
		if e.Package == modPath {
			code, ok = codes["."]
		}
		if !ok {
			code = exitUnknown
		}
		b.WriteString(exitEvent(e.Package, code) + "\n")
	}
	return b.String()
}

// modulePath is the module's path as go reads it: go.mod may quote it or put it
// in a block.
func modulePath(ctx context.Context, root string) (string, error) {
	out, err := goCmd(ctx, time.Minute, root, "mod", "edit", "-json")
	if err != nil {
		return "", fmt.Errorf("cross: go mod edit -json: %w\n%s", err, tail(out, 20))
	}
	var m struct{ Module struct{ Path string } }
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return "", fmt.Errorf("cross: go mod edit -json output: %w", err)
	}
	if m.Module.Path == "" {
		return "", fmt.Errorf("cross: no module line in %s/go.mod", root)
	}
	return m.Module.Path, nil
}

// removeTree is os.RemoveAll for a tree a test wrote: a directory left read-only
// cannot be emptied until it is writable again.
func removeTree(dir string) error {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o755)
		}
		return nil
	})
	return os.RemoveAll(dir)
}
