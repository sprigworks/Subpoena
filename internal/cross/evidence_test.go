//subpoena:impl_derived

package cross

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tagTest fails TestDeny with a message tagged as the harness tags witness
// failures, after a skipped test logs an untagged line first.
const tagTest = `package mini

import "testing"

func TestASkip(t *testing.T) { t.Skip("no cgroup here") }

func TestDeny(t *testing.T) {
	if Allow(false) == nil {
		t.Fatal("witness: a process ran after the denial")
	}
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

// The first failure's tag says which evidence killed the mutant; a skipped
// test's log line is not a failure. The full -json output is kept.
func TestKillRecordsItsFirstEvidence(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": tagTest})
	evDir := filepath.Join(t.TempDir(), "evidence")
	rep, err := Run(context.Background(), Options{Target: dir, EvidenceDir: evDir})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Outcome != Killed || r.Evidence != EvidenceWitness || !strings.HasPrefix(r.FirstFailure, "witness: a process ran") {
		t.Fatalf("want a witness kill, got %+v", r)
	}
	b, err := os.ReadFile(r.EvidenceFile)
	if err != nil || !strings.Contains(string(b), `"Action":"fail"`) || filepath.Dir(r.EvidenceFile) != evDir {
		t.Fatalf("full go test -json output not kept at %q: %v", r.EvidenceFile, err)
	}
}

// An untagged failure (an error return, an exit code) is Other: not
// independent proof.
func TestUntaggedKillIsOther(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Killed || r.Evidence != EvidenceOther || r.FirstFailure != "non-admin must be denied" {
		t.Fatalf("want an untagged kill, got %+v", r)
	}
}

// crashTest only goes red because the mutant's nil error is dereferenced: no
// assertion catches the bypass, so it is not a kill.
const crashTest = `package mini

import "testing"

func TestDeny(t *testing.T) {
	err := Allow(false)
	_ = err.Error()
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

func TestPanicBeforeAnyAssertionIsACrashNotAKill(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": crashTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Crashed || !rep.Failed() || !strings.Contains(r.Output, "nil pointer") {
		t.Fatalf("want crashed, failing the run; got %+v", r)
	}
}

func TestFirstFailureReadsOnlyFailedTests(t *testing.T) {
	raw := strings.Join([]string{
		`{"Action":"output","Package":"p","Test":"TestSkip","Output":"    a_test.go:3: setup unavailable\n"}`,
		`{"Action":"skip","Package":"p","Test":"TestSkip"}`,
		`{"Action":"output","Package":"p","Test":"TestPass","Output":"    a_test.go:5: witness: just a log line\n"}`,
		`{"Action":"pass","Package":"p","Test":"TestPass"}`,
		`{"Action":"output","Package":"p","Test":"TestDeny","Output":"    a_test.go:9: testimony: denial span missing\n"}`,
		`{"Action":"output","Package":"p","Test":"TestDeny","Output":"    a_test.go:10: witness: later\n"}`,
		`{"Action":"fail","Package":"p","Test":"TestDeny"}`,
		`not json: a go command message`,
	}, "\n")
	ev, msg, crashed := firstFailure(raw)
	if ev != EvidenceTestimony || msg != "testimony: denial span missing" || crashed {
		t.Fatalf("got %q %q crashed=%v", ev, msg, crashed)
	}
	if got := testText(raw); !strings.Contains(got, "testimony: denial span missing\n") || !strings.Contains(got, "not json: a go command message\n") {
		t.Fatalf("testText lost lines: %q", got)
	}
}
