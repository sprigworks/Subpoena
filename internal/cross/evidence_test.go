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

// The event order and the failure formats here are from real runs of testify
// and Ginkgo v2 under go test -json: a subtest's assertion belongs to the
// subtest, and its panic to the parent; Ginkgo colours its report, recovers a
// spec's panic and carries on, in an order it randomises. A panic anywhere in a
// package decides, so the order cannot flip the verdict.
func TestAssertionFrameworkFailures(t *testing.T) {
	const (
		ansiRed, ansiOff = "\x1b[38;5;9m", "\x1b[0m"
		panicLine        = "panic: runtime error: invalid memory address or nil pointer dereference [recovered, repanicked]"
	)
	testify := func(test, msg string) [][2]string {
		return [][2]string{
			{test, "    a_test.go:74: "},
			{test, "        \tError Trace:\t/tmp/x/a_test.go:74"},
			{test, "        \tError:      \t" + msg},
		}
	}
	ginkgo := func(tag, msg string) [][2]string {
		return [][2]string{
			{"TestSuite", "Running Suite: x - /tmp/x"},
			{"TestSuite", ansiRed + "• [" + tag + "] [0.001 seconds]" + ansiOff},
			{"TestSuite", "x " + ansiRed + "[It] does a thing" + ansiOff},
			{"TestSuite", "  " + ansiRed + "[" + tag + "] " + msg},
			{"TestSuite", "  In [It] at: /tmp/x/a_test.go:12 @ 11/05/26 07:00:00"},
		}
	}
	join := func(parts ...[][2]string) [][2]string {
		var all [][2]string
		for _, p := range parts {
			all = append(all, p...)
		}
		return all
	}
	fail := func(tests ...string) string {
		var b strings.Builder
		for _, test := range tests {
			b.WriteString(`{"Action":"fail","Package":"p","Test":"` + test + `"}` + "\n")
		}
		return b.String()
	}
	cases := []struct {
		name    string
		out     [][2]string
		tests   []string
		ev      Evidence
		msg     string
		crashed bool
	}{
		{"ginkgo assertion", ginkgo("FAILED", "Expected redirect not to be valid"), []string{"TestSuite"},
			EvidenceOther, "Expected redirect not to be valid", false},
		{"ginkgo: the timeline entry is not the message, and the message runs to In [It]", [][2]string{
			{"TestSuite", "Running Suite: x - /tmp/x"},
			{"TestSuite", ansiRed + "• [FAILED] [0.002 seconds]" + ansiOff},
			{"TestSuite", "  Timeline >>"},
			{"TestSuite", "  " + ansiRed + "[FAILED] in [It] - /tmp/x/a_test.go:193 @ 11/04/26 19:45:35.1" + ansiOff},
			{"TestSuite", "  << Timeline"},
			{"TestSuite", "  " + ansiRed + "[FAILED] Expected"},
			{"TestSuite", "      <int>: 200"},
			{"TestSuite", "  to equal"},
			{"TestSuite", "      <int>: 403" + ansiOff},
			{"TestSuite", "  In [It] at: /tmp/x/a_test.go:193 @ 11/04/26 19:45:35.1"},
			{"TestSuite", "  nothing after the location"},
		}, []string{"TestSuite"}, EvidenceOther, "Expected <int>: 200 to equal <int>: 403", false},
		{"ginkgo: a tag on a timeline line is no evidence", [][2]string{
			{"TestSuite", "Running Suite: x - /tmp/x"},
			{"TestSuite", "• [FAILED] [0.002 seconds]"},
			{"TestSuite", "  Timeline >>"},
			{"TestSuite", "  [FAILED] witness: a log line, not a witness"},
			{"TestSuite", "  [FAILED] in [It] - /tmp/x/a_test.go:11 @ 11/05/26 09:02:39.911"},
			{"TestSuite", "  << Timeline"},
			{"TestSuite", "  [FAILED] Expected an error"},
			{"TestSuite", "  In [It] at: /tmp/x/a_test.go:11 @ 11/05/26 09:02:39.911"},
		}, []string{"TestSuite"}, EvidenceOther, "Expected an error", false},
		{"ginkgo: a tag ahead of a forged location is no evidence", [][2]string{
			{"TestSuite", "Running Suite: x - /tmp/x"},
			{"TestSuite", "• [FAILED] [0.002 seconds]"},
			{"TestSuite", "  [FAILED] witness: a log line"},
			{"TestSuite", "  In [It] at: forged"},
			{"TestSuite", "  [FAILED] Expected an error"},
			{"TestSuite", "  In [It] at: /tmp/x/a_test.go:11 @ 11/05/26 09:02:39.911"},
		}, []string{"TestSuite"}, EvidenceOther, "Expected an error", false},
		{"ginkgo assertion with a tag", ginkgo("FAILED", "witness: saw a dial"), []string{"TestSuite"},
			EvidenceWitness, "witness: saw a dial", false},
		{"ginkgo: assertion, then another spec panics", join(ginkgo("FAILED", "Expected 1"), ginkgo("PANICKED", "Test Panicked")),
			[]string{"TestSuite"}, "", "", true},
		{"ginkgo: a panic first is a crash", join(ginkgo("PANICKED", "Test Panicked"), ginkgo("FAILED", "Expected 1")),
			[]string{"TestSuite"}, "", "", true},
		{"ginkgo panic alone", ginkgo("PANICKED", "Test Panicked"), []string{"TestSuite"}, "", "", true},
		{"a report with no Ginkgo suite running is output", [][2]string{
			{"TestA", "• [FAILED] [0.001 seconds]"},
			{"TestA", "[FAILED] relayed text"}}, []string{"TestA"}, "", "", true},
		{"a suite banner in another test proves nothing", [][2]string{
			{"TestB", "Running Suite: x - /tmp/x"},
			{"TestA", "• [FAILED] [0.001 seconds]"},
			{"TestA", "[FAILED] relayed text"}}, []string{"TestA"}, "", "", true},
		{"[FAILED] with no ginkgo report around it is output", [][2]string{{"TestA", "  [FAILED] login for bob"}},
			[]string{"TestA"}, "", "", true},
		{"ginkgo timeout is not an assertion", ginkgo("TIMEDOUT", "A spec timeout occurred"), []string{"TestSuite"}, "", "", true},

		{"testify, then a panic", join(testify("TestA", "Not equal:"), [][2]string{{"TestA", "--- FAIL: TestA (0.00s)"}, {"TestA", panicLine}}),
			[]string{"TestA"}, "", "", true},
		{"testify in a subtest, then the parent reports the panic", join(testify("TestA/sub", "Not equal:"), [][2]string{{"TestA", panicLine}}),
			[]string{"TestA/sub", "TestA"}, "", "", true},
		{"text shaped like testify's, then a panic", join([][2]string{
			{"TestA", "    a_test.go:3: "},
			{"TestA", "        \tError Trace:\tfoo_test.go:12"}}, [][2]string{{"TestA", panicLine}}),
			[]string{"TestA"}, "", "", true},
		{"text shaped like Ginkgo's, then a panic", join([][2]string{
			{"TestA", "• [FAILED] [0.001 seconds]"},
			{"TestA", "[FAILED] relayed text"}}, [][2]string{{"TestA", panicLine}}),
			[]string{"TestA"}, "", "", true},
		{"panic before the assertion", join([][2]string{{"TestA", panicLine}}, testify("TestA", "Not equal:")), []string{"TestA"}, "", "", true},
		{"testify in one test, panic in another", join(testify("TestA", "Not equal:"), [][2]string{{"TestB", panicLine}}),
			[]string{"TestA", "TestB"}, "", "", true},
		{"testify, then a panic outside any test", join(testify("TestA", "Not equal:"), [][2]string{{"", panicLine}}),
			[]string{"TestA"}, "", "", true},
		{"an assertion outside test code does not count", [][2]string{
			{"TestA", "    server.go:74: "},
			{"TestA", "        \tError Trace:\t/tmp/x/server.go:74"},
			{"TestA", "        \tError:      \tNot equal:"},
			{"TestA", panicLine}}, []string{"TestA"}, "", "", true},
		{"a plain t.Error before a panic is still a log line", [][2]string{
			{"TestA", "    a_test.go:3: want 403"},
			{"TestA", panicLine}}, []string{"TestA"}, "", "", true},
	}
	for _, c := range cases {
		ev, msg, crashed := firstFailure(jsonLines(c.out...) + fail(c.tests...))
		if ev != c.ev || msg != c.msg || crashed != c.crashed {
			t.Errorf("%s: got %q %q crashed=%v", c.name, ev, msg, crashed)
		}
	}
}

// The whole path through go test: an assertion's text, then a nil dereference,
// as a real suite does it. go test -json gives no way to tell a library's report
// from what anything else printed, so the panic decides. testify is not a
// dependency of the tiny module, so the test prints what testify prints.
func TestAssertionThenPanicIsACrash(t *testing.T) {
	const assertThenPanic = `package mini

import "testing"

func TestDeny(t *testing.T) {
	var got *error
	if err := Allow(false); err == nil {
		t.Errorf("\n\tError Trace:\tauth_test.go:8\n\tError:      \tAn error is expected but got nil.")
	} else {
		got = &err
	}
	_ = *got
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": assertThenPanic})
	rep, err := Run(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Outcome != Crashed {
		t.Fatalf("want a crash, got %+v", r)
	}
}

// A crash reports the package that died. go test -json interleaves packages,
// and the last lines usually belong to one that passed.
func TestCrashOutputNamesThePackageThatDied(t *testing.T) {
	ev := func(action, pkg, test, out string) string {
		b, err := json.Marshal(struct{ Action, Package, Test, Output string }{action, pkg, test, out})
		if err != nil {
			panic(err)
		}
		return string(b)
	}
	pass := []string{
		ev("output", "good", "TestG", "=== RUN   TestG\n"),
		ev("output", "good", "TestG", "--- PASS: TestG (0.00s)\n"),
		ev("pass", "good", "TestG", ""),
		ev("output", "good", "", "PASS\n"),
		ev("output", "good", "", "ok  \tgood\t0.1s\n"),
		ev("pass", "good", "", ""),
	}
	join := func(lines ...[]string) string {
		var all []string
		for _, l := range lines {
			all = append(all, l...)
		}
		return strings.Join(all, "\n")
	}
	t.Run("log.Fatal, no crash line", func(t *testing.T) {
		got := crashOutput(join([]string{
			ev("output", "dead", "TestF", "=== RUN   TestF\n"),
			ev("output", "dead", "TestF", "level=info msg=starting\n"),
			ev("output", "dead", "TestF", "level=fatal msg=\"bind: address already in use\"\n"),
			ev("output", "dead", "", "FAIL\tdead\t0.2s\n"),
			ev("fail", "dead", "", ""),
		}, pass), 20)
		for _, want := range []string{"package dead", "level=fatal"} {
			if !strings.Contains(got, want) {
				t.Errorf("want %q in:\n%s", want, got)
			}
		}
		if strings.Contains(got, "=== RUN") || strings.Contains(got, "TestG") {
			t.Errorf("noise from a passing package or test framing:\n%s", got)
		}
	})
	t.Run("a panic starts the output, ahead of a longer stack", func(t *testing.T) {
		lines := []string{
			ev("output", "dead", "TestF", "setup line\n"),
			ev("output", "dead", "TestF", "panic: boom\n"),
		}
		for range 50 {
			lines = append(lines, ev("output", "dead", "TestF", "stack frame\n"))
		}
		lines = append(lines, ev("fail", "dead", "TestF", ""), ev("fail", "dead", "", ""))
		got := crashOutput(join(pass, lines), 5)
		if !strings.Contains(got, "panic: boom") || strings.Contains(got, "setup line") {
			t.Errorf("want the panic and what follows:\n%s", got)
		}
		if n := strings.Count(got, "\n"); n != 5 {
			t.Errorf("%d lines after the header, want 5:\n%s", n, got)
		}
	})
	t.Run("a panic a passing test recovered from is not the crash", func(t *testing.T) {
		got := crashOutput(join([]string{
			ev("output", "fine", "TestP", "panic: expected by the test\n"),
			ev("pass", "fine", "TestP", ""),
			ev("pass", "fine", "", ""),
			ev("output", "dead", "TestF", "os.Exit from here\n"),
			ev("fail", "dead", "", ""),
		}), 20)
		if !strings.Contains(got, "package dead") || strings.Contains(got, "expected by the test") {
			t.Errorf("wrong package:\n%s", got)
		}
	})
	t.Run("no events falls back to the text", func(t *testing.T) {
		if got := crashOutput("signal: killed\n", 20); got != "signal: killed" {
			t.Errorf("got %q", got)
		}
	})
}

func TestCrashedResultShowsThePanic(t *testing.T) {
	const crashing = `package mini

import "testing"

func TestDeny(t *testing.T) {
	var p *int
	if Allow(false) == nil {
		_ = *p
	}
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`
	const other = `package other

import "testing"

func TestLast(t *testing.T) {}
`
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": crashing, "z/other_test.go": other})
	rep, err := Run(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Outcome != Crashed || !strings.Contains(r.Output, "package mini") || !strings.Contains(r.Output, "panic: ") ||
		strings.Contains(r.Output, "TestLast") {
		t.Fatalf("want the panic of package mini alone, got %s:\n%s", r.Outcome, r.Output)
	}
}

// A sandbox copy holds no repository, so go build climbs out of it to look for
// one. An empty .git above the temp directory, as a sandboxing tool leaves for
// a mount point, then fails the build of a main package on VCS stamping, and
// every mutant came back invalid: "did not compile", with nothing wrong with it.
func TestAStrayGitAboveTheCopyIsNotABuildFailure(t *testing.T) {
	const src = `package main

import "errors"

var ErrDenied = errors.New("denied")

func main() {}

//subpoena:enforcement_point
func Allow(ok bool) error {
	if !ok {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`
	const test = `package main

import "testing"

func TestDeny(t *testing.T) {
	if Allow(false) == nil {
		t.Fatal("must be denied")
	}
}
`
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	rep, err := Run(context.Background(), Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; r.Outcome != Killed {
		t.Fatalf("want a kill, got %s:\n%s", r.Outcome, r.Output)
	}
}
