//subpoena:impl_derived

package cross

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

const gate3 = `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

func outcome(t *testing.T, o Options) (Outcome, Result) {
	t.Helper()
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %+v", rep.Results)
	}
	return rep.Results[0].Outcome, rep.Results[0]
}

// dash drops a variable whose name is no shell identifier, so a wrapper in sh
// turned a green test red on the mutant run alone: a kill with no part played by
// the mutant (repro g01).
func TestARunnerThatDropsEnvIsNoKill(t *testing.T) {
	t.Setenv("app.mode", "ci")
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("os"; "testing")

func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
func TestConfig(t *testing.T) {
	if os.Getenv("app.mode") != "ci" { t.Fatalf("app.mode not set") }
}
`})
	if got, _ := outcome(t, Options{Target: dir}); got != Survived {
		t.Fatalf("got %s, want survived", got)
	}
}

// A project's own -exec runner stays in place on every run (repro g02).
func TestAProjectsExecRunnerRunsEveryTime(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "myexec")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nRUNNER=1 exec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOFLAGS", strings.TrimSpace(os.Getenv("GOFLAGS")+" -exec="+bin))
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("os"; "testing")

func TestAllowed(t *testing.T) { if Check("ann") != nil { t.Fatal("ann refused") } }
func TestRunner(t *testing.T) { if os.Getenv("RUNNER") != "1" { t.Fatal("not under the runner") } }
`})
	if got, _ := outcome(t, Options{Target: dir}); got != Survived {
		t.Fatalf("got %s, want survived", got)
	}
}

// With no sh on PATH the exit code must still be read (repro g13).
func TestNoShStillSeesTheDeath(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip(err)
	}
	p := t.TempDir()
	if err := os.Symlink(goBin, filepath.Join(p, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", p)
	dir := module(t, map[string]string{"gate.go": `package mini

import ("errors"; "fmt")

var ErrDenied = errors.New("denied")

type loud struct{}

func (loud) Error() string { fmt.Print("...."); return "nil pointer dereference" }

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	panic(loud{})
}
`, "gate_test.go": `package mini

import "testing"

func TestA(t *testing.T) { t.Log("about to call"); Check("mallory") }
`})
	if got, _ := outcome(t, Options{Target: dir}); got != Crashed {
		t.Fatalf("got %s, want crashed", got)
	}
}

// go accepts both spellings; a kill must stay a kill (repro g08).
func TestAQuotedOrBlockModuleLineKeepsItsKill(t *testing.T) {
	for name, line := range map[string]string{
		"quoted": `module "example.com/mini"`,
		"block":  "module (\n\texample.com/mini\n)",
	} {
		t.Run(name, func(t *testing.T) {
			dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import "testing"

func TestDenied(t *testing.T) { if Check("mallory") == nil { t.Fatal("not refused") } }
`})
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(line+"\n\ngo 1.25.0\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if got, _ := outcome(t, Options{Target: dir}); got != Killed {
				t.Fatalf("got %s, want killed", got)
			}
		})
	}
}

// The app prints go test's own framing byte and a failure, then exits 1: the
// output is a failed test, the exit code a failed test's. The binary never
// finished testing (repro g03 marker).
func TestPrintedFramingThenExit1IsNoKill(t *testing.T) {
	dir := module(t, map[string]string{"gate.go": `package mini

import ("errors"; "fmt"; "os")

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func Check(u string) error {
	if u == "mallory" {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}

func Handle(u string) {
	if Check(u) == nil && u == "mallory" {
		fmt.Print("\x16--- FAIL: TestHandle (0.00s)\n    gate_test.go:5: refusal was not honoured\n")
		os.Exit(1)
	}
}
`, "gate_test.go": `package mini

import "testing"

func TestHandle(t *testing.T) { Handle("mallory") }
`})
	if got, _ := outcome(t, Options{Target: dir}); got != Crashed {
		t.Fatalf("got %s, want crashed", got)
	}
}

// A test seen failing without the mutant stays unconfirmed under -select: the
// whole-suite run must not replace it with a kill (repro g05).
func TestSelectKeepsUnconfirmed(t *testing.T) {
	count := filepath.Join(t.TempDir(), "count")
	t.Setenv("R3_COUNT", count)
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("os"; "strings"; "testing")

// Green on the baseline, the coverage pass and the subset check, then red.
func TestAllowed(t *testing.T) {
	p := os.Getenv("R3_COUNT")
	b, _ := os.ReadFile(p)
	n := len(b) + 1
	os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o644)
	_ = Check("mallory")
	if n >= 4 && n <= 6 { t.Fatal("flake") }
	if Check("ann") != nil { t.Fatal("ann refused") }
}
`})
	if got, res := outcome(t, Options{Target: dir, Select: true}); got != Unconfirmed {
		t.Fatalf("got %s (%s), want unconfirmed", got, res.FirstFailure)
	}
}

// A test can leave a directory it cannot delete, as a GOMODCACHE in the tree
// does (repro g09).
func TestAReadOnlyDirLeftByATestStopsNothing(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import ("os"; "testing")

func TestDenied(t *testing.T) {
	os.MkdirAll("cache/mod", 0o755)
	os.WriteFile("cache/mod/f", []byte("x"), 0o444)
	os.Chmod("cache/mod", 0o555)
	if Check("mallory") == nil { t.Fatal("not refused") }
}
`})
	if got, _ := outcome(t, Options{Target: dir}); got != Killed {
		t.Fatalf("got %s, want killed", got)
	}
	left, _ := filepath.Glob(filepath.Join(scratch, "subpoena-cross-*"))
	if len(left) != 0 {
		t.Fatalf("left behind: %q", left)
	}
}

// A quote in TMPDIR must not break the runner (repro g07).
func TestAQuoteInTMPDIRKeepsItsKill(t *testing.T) {
	scratch := filepath.Join(t.TempDir(), "r3'q")
	if err := os.Mkdir(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", scratch)
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import "testing"

func TestDenied(t *testing.T) { if Check("mallory") == nil { t.Fatal("not refused") } }
`})
	if got, res := outcome(t, Options{Target: dir}); got != Killed {
		t.Fatalf("got %s: %s", got, res.Output)
	}
}

// go test -json cuts a long line into several events, and the mark is at its
// end (repro g14).
func TestALongSignedLineKeepsItsMark(t *testing.T) {
	full := "    a_test.go:5: " + crossmark.Sign(testKey, "witness: "+strings.Repeat("x", 3000)) + "\n"
	var raw strings.Builder
	for len(full) > 0 {
		n := min(1024, len(full))
		b, _ := json.Marshal(struct{ Action, Package, Test, Output string }{"output", "p", "TestA", full[:n]})
		raw.Write(append(b, '\n'))
		full = full[n:]
	}
	raw.WriteString(`{"Action":"fail","Package":"p","Test":"TestA"}` + "\n")
	ev, _, crashed := firstFailure(raw.String(), testKey)
	if crashed || ev != EvidenceWitness {
		t.Fatalf("ev=%q crashed=%v", ev, crashed)
	}
}

// Cross's own exit event is no text of go test's (seen in repro g05's output).
func TestExitEventsAreNotPrintedText(t *testing.T) {
	raw := `{"Action":"output","Package":"p","Output":"FAIL\n"}` + "\n" + exitEvent("p", "1") + "\n"
	if got := testText(raw); got != "FAIL\n" {
		t.Fatalf("got %q", got)
	}
}

// With no wrapper no exit code can be read, so there is no run: the old wrapper
// turned itself off in silence (repro g13).
func TestNoWrapperIsNoRun(t *testing.T) {
	src := wrapperSource
	defer func() { wrapperSource = src }()
	wrapperSource = "package main\n\nfunc main() { this does not compile }\n"
	dir := module(t, map[string]string{"gate.go": gate3, "gate_test.go": `package mini

import "testing"

func TestDenied(t *testing.T) { if Check("mallory") == nil { t.Fatal("not refused") } }
`})
	if _, err := Run(context.Background(), Options{Target: dir}); err == nil || !strings.Contains(err.Error(), "exit-code wrapper") {
		t.Fatalf("got %v, want the wrapper's build error", err)
	}
}
