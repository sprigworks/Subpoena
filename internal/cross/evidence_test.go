//subpoena:impl_derived

package cross

import (
	"context"
	"encoding/json"
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

// A log line ahead of a witness failure stays the first failure, so the kill is
// not upgraded; the witness message is kept beside it for the reader.
func TestWitnessFailureAfterALogLine(t *testing.T) {
	raw := strings.Join([]string{
		`{"Action":"output","Package":"p","Test":"TestOK","Output":"    a_test.go:1: witness: passing test\n"}`,
		`{"Action":"pass","Package":"p","Test":"TestOK"}`,
		`{"Action":"output","Package":"p","Test":"TestDeny","Output":"    a_test.go:3: client error: EOF\n"}`,
		`{"Action":"output","Package":"p","Test":"TestDeny","Output":"    a_test.go:4: witness: saw a dial\n"}`,
		`{"Action":"fail","Package":"p","Test":"TestDeny"}`,
	}, "\n")
	ev, msg, crashed := firstFailure(raw)
	if ev != EvidenceOther || msg != "client error: EOF" || crashed {
		t.Fatalf("got %q %q crashed=%v", ev, msg, crashed)
	}
	if got := witnessFailure(raw); got != "witness: saw a dial" {
		t.Fatalf("witnessFailure = %q", got)
	}
}

const logThenWitnessTest = `package mini

import "testing"

func TestDeny(t *testing.T) {
	err := Allow(false)
	t.Logf("got: %v", err)
	if err == nil {
		t.Fatal("witness: a process ran after the denial")
	}
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

func TestRequireWitnessStaysStrictButNamesTheLaterWitness(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": logThenWitnessTest})
	rep, err := Run(context.Background(), Options{Target: dir, RequireWitness: true})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Outcome != KilledBySelfReport || !rep.Failed() || !strings.HasPrefix(r.LaterWitness, "witness: a process ran") {
		t.Fatalf("want a rejected kill naming the witness, got %+v", r)
	}
}

func TestFirstFailureCrashes(t *testing.T) {
	j := func(lines ...string) string { return strings.Join(lines, "\n") }
	cases := []struct {
		name    string
		raw     string
		crashed bool
		msg     string
	}{
		{"log then panic", j(
			`{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:3: witness: hello\n"}`,
			`{"Action":"output","Package":"p","Test":"TestA","Output":"panic: runtime error: invalid memory address or nil pointer dereference\n"}`,
			`{"Action":"fail","Package":"p","Test":"TestA"}`,
			`{"Action":"fail","Package":"p"}`), true, ""},
		{"os.Exit", j(
			`{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:4: x\n"}`,
			`{"Action":"output","Package":"p","Output":"FAIL\tp\t0.006s\n"}`,
			`{"Action":"fail","Package":"p"}`), true, ""},
		{"fatal error in an unfinished test", j(
			`{"Action":"output","Package":"p","Test":"TestA","Output":"fatal error: concurrent map writes\n"}`,
			`{"Action":"fail","Package":"p"}`), true, ""},
		{"failed with no message", j(
			`{"Action":"fail","Package":"p","Test":"TestA"}`,
			`{"Action":"fail","Package":"p"}`), true, ""},
		{"passing test prints panic, another fails", j(
			`{"Action":"output","Package":"p","Test":"TestP","Output":"panic: recovered and expected\n"}`,
			`{"Action":"pass","Package":"p","Test":"TestP"}`,
			`{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:9: witness: spawned\n"}`,
			`{"Action":"fail","Package":"p","Test":"TestA"}`), false, "witness: spawned"},
		{"one package crashes, another kills", j(
			`{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:3: setup\n"}`,
			`{"Action":"output","Package":"p","Test":"TestA","Output":"panic: boom\n"}`,
			`{"Action":"fail","Package":"p","Test":"TestA"}`,
			`{"Action":"output","Package":"q","Test":"TestB","Output":"    b_test.go:7: testimony: no span\n"}`,
			`{"Action":"fail","Package":"q","Test":"TestB"}`), false, "testimony: no span"},
	}
	for _, c := range cases {
		_, msg, crashed := firstFailure(c.raw)
		if crashed != c.crashed || msg != c.msg {
			t.Errorf("%s: got %q crashed=%v", c.name, msg, crashed)
		}
	}
}

func TestRunSinglesRefusesACancelledRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := runSingles(ctx, Options{}, []sandbox{{}, {}}, "./...", []Mutant{{}, {}, {}})
	if err == nil {
		t.Fatalf("want an error for unrun mutants, got %d results", len(res))
	}
}

// jsonLines turns (test, output) pairs into go test -json output lines.
func jsonLines(pairs ...[2]string) string {
	var b strings.Builder
	for _, p := range pairs {
		line, err := json.Marshal(struct{ Action, Package, Test, Output string }{"output", "p", p[0], p[1] + "\n"})
		if err != nil {
			panic(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// A testify failure and a multi-line t.Errorf both leave the head line blank;
// the text is under it. Shapes are from real suites (echo, oauth2-proxy,
// traefik, webdav), including a log line from the code under test in between.
func TestFirstFailureReadsTheTextUnderABlankHead(t *testing.T) {
	failed := `{"Action":"fail","Package":"p","Test":"TestA"}` + "\n"
	cases := []struct {
		name string
		out  [][2]string
		want string
	}{
		{"testify", [][2]string{
			{"TestA", "    a_test.go:161: "},
			{"TestA", "        \tError Trace:\t/tmp/x/a_test.go:161"},
			{"TestA", "        \tError:      \tNot equal: "},
			{"TestA", "        \t            \texpected: 200"},
			{"TestA", "        \t            \tactual  : 418"},
			{"TestA", "        \tTest:       \tTestA"},
			{"TestA", "        \tMessages:   \tnot this"},
		}, "Not equal: expected: 200 actual  : 418"},
		{"log line from the code in between", [][2]string{
			{"TestA", "    a_test.go:9: "},
			{"TestA", `{"level":"debug","message":"proxy_set_header"}`},
			{"TestA", "        \tError Trace:\t/tmp/x/a_test.go:9"},
			{"TestA", "        \tError:      \tAn error is expected but got nil."},
		}, "An error is expected but got nil."},
		{"multi-line t.Errorf", [][2]string{
			{"TestA", "    a_test.go:439: "},
			{"TestA", "        Expected"},
			{"TestA", "            <bool>: true"},
			{"TestA", "        to be false"},
		}, "Expected <bool>: true to be false"},
		{"blank head and nothing under it", [][2]string{
			{"TestA", "    a_test.go:2: "},
		}, emptyFailure},
	}
	for _, c := range cases {
		_, msg, crashed := firstFailure(jsonLines(c.out...) + failed)
		if crashed || msg != c.want {
			t.Errorf("%s: got %q crashed=%v, want %q", c.name, msg, crashed, c.want)
		}
	}
}

// The text under a blank head is for the reader. A tag is read from the head
// line alone, so reading further cannot upgrade a kill.
func TestTextUnderABlankHeadIsNeverATag(t *testing.T) {
	raw := jsonLines(
		[2]string{"TestA", "    a_test.go:161: "},
		[2]string{"TestA", "        \tError Trace:\t/tmp/x/a_test.go:161"},
		[2]string{"TestA", "        \tError:      \twitness: saw a dial"},
	) + `{"Action":"fail","Package":"p","Test":"TestA"}`
	if ev, _, _ := firstFailure(raw); ev != EvidenceOther {
		t.Fatalf("evidence = %q, want other", ev)
	}
	if got := witnessFailure(raw); got != "" {
		t.Fatalf("witnessFailure = %q, want none", got)
	}
}

func TestLongFailureTextIsCut(t *testing.T) {
	var pairs [][2]string
	pairs = append(pairs, [2]string{"TestA", "    a_test.go:2: "})
	for range 100 {
		pairs = append(pairs, [2]string{"TestA", "        " + strings.Repeat("x", 20)})
	}
	_, msg, _ := firstFailure(jsonLines(pairs...) + `{"Action":"fail","Package":"p","Test":"TestA"}`)
	if len(msg) > maxFailureText+21 {
		t.Fatalf("text is %d bytes", len(msg))
	}
}
