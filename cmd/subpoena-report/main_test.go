//subpoena:impl_derived
//subpoena:pure_logic

// The exit status and what reaches the page, driven through run as the command
// line would, written after reading the implementation. No telemetry.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/report"
)

const (
	passing = `{"run_id":"20261104T010000Z-aaaaaaaa","capture_complete":true,
	  "assertions":{"results":[{"id":"a","kind":"exists","verdict":"pass"}]}}`
	failing = `{"run_id":"20261104T010100Z-bbbbbbbb","capture_complete":true,
	  "assertions":{"results":[{"id":"a","kind":"exists","verdict":"fail"}]}}`
	inconclusive = `{"run_id":"20261104T010200Z-cccccccc","capture_complete":true,
	  "assertions":{"results":[{"id":"a","kind":"absent","verdict":"inconclusive"}]}}`
	cutOff = `{"run_id":"20261104T010300Z-dddddddd","assertions":{"results":[{"id":"a","verd`
)

func dirWith(t *testing.T, bodies ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, body := range bodies {
		name := filepath.Join(dir, string(rune('a'+i))+".json")
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestExitStatus(t *testing.T) {
	for _, c := range []struct {
		name   string
		bodies []string
		failOn string
		want   int
	}{
		{"all passed", []string{passing}, "any", 0},
		{"a failure", []string{passing, failing}, "any", 1},
		{"an inconclusive", []string{passing, inconclusive}, "any", 1},
		{"an unreadable input", []string{passing, cutOff}, "any", 1},
		{"fail ignores inconclusive", []string{passing, inconclusive}, "fail", 0},
		{"fail sees a failure", []string{passing, failing}, "fail", 1},
		{"fail sees an unreadable input", []string{passing, cutOff}, "fail", 1},
		{"inconclusive ignores a failure", []string{passing, failing}, "inconclusive", 0},
		{"inconclusive sees an inconclusive", []string{passing, inconclusive}, "inconclusive", 1},
		{"inconclusive sees an unreadable input", []string{passing, cutOff}, "inconclusive", 1},
		{"none", []string{failing, cutOff}, "none", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "p.md")
			args := []string{"-from", "run-results", "-fail-on", c.failOn, "-md", out, dirWith(t, c.bodies...)}
			if got := run(args); got != c.want {
				t.Errorf("exit = %d; want %d", got, c.want)
			}
		})
	}
}

func TestUnreadableInputReachesThePage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.md")
	if got := run([]string{"-from", "run-results", "-md", out, dirWith(t, passing, cutOff)}); got != 1 {
		t.Fatalf("exit = %d; want 1", got)
	}
	page, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "Unreadable input") || !strings.Contains(string(page), "could not be read") {
		t.Errorf("page does not report the input:\n%s", page)
	}
}

func TestExitForTreatsNoneAsNoGate(t *testing.T) {
	if exitFor("none", report.Totals{Failed: 1, Inconclusive: 1, Unreadable: 1}) {
		t.Error("exitFor(none) = true; want false")
	}
}
