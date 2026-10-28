//subpoena:impl_derived

package cross

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const goMod = "module mini\n\ngo 1.24\n"

const authOK = `package mini

import "errors"

var ErrDenied = errors.New("denied")

// Allow decides.
//
//subpoena:enforcement_point
func Allow(admin bool) error {
	if !admin {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

const strongTest = `package mini

import "testing"

func TestDeny(t *testing.T) {
	if Allow(false) == nil {
		t.Fatal("non-admin must be denied")
	}
}
func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

const weakTest = `package mini

import "testing"

func TestAllow(t *testing.T) {
	if Allow(true) != nil {
		t.Fatal("admin must be allowed")
	}
}
`

func module(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = goMod
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func run(t *testing.T, dir string) (*Report, error) {
	t.Helper()
	return Run(context.Background(), Options{Target: dir})
}

func TestFindMutants(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	ms, err := FindMutants(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Func != "Allow" || ms[0].Line != 12 || ms[0].Removed != "return ErrDenied" {
		t.Fatalf("unexpected mutants: %+v", ms)
	}
}

func TestStrongSuiteKillsMutant(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Killed || rep.Failed() {
		t.Fatalf("want killed, got %+v", rep.Results)
	}
	if rep.EnforcementPoints != 1 {
		t.Fatalf("enforcement points = %d, want 1", rep.EnforcementPoints)
	}
	if got := rep.Results[0].Failing; len(got) != 1 || got[0] != "TestDeny" {
		t.Fatalf("failing tests: %v", got)
	}
	// The original tree must be untouched.
	b, _ := os.ReadFile(filepath.Join(dir, "auth.go"))
	if string(b) != authOK {
		t.Fatal("cross-examination modified the original tree")
	}
}

func TestWeakSuiteLetsMutantSurvive(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": weakTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Survived || !rep.Failed() {
		t.Fatalf("want survived, got %+v", rep.Results)
	}
	if rep.Results[0].Outcome != "enforcement-mutant-survived" || rep.Results[0].Mutant.Func != "Allow" {
		t.Fatalf("report wording changed: %+v", rep.Results[0])
	}
}

func TestNonCompilingMutantIsInvalidNotKilled(t *testing.T) {
	// The removed statement declares a variable used later, so the mutant
	// cannot build whatever cross-examination does.
	src := strings.Replace(authOK, `	if !admin {
		return ErrDenied //subpoena:enforcement
	}`, `	err := ErrDenied //subpoena:enforcement
	if !admin {
		return err
	}`, 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Invalid || !rep.Failed() {
		t.Fatalf("a compile failure must not count as a kill: %+v", rep.Results[0])
	}
}

func TestImportOnlyUsedByTheRemovedStatementIsPruned(t *testing.T) {
	// errors is imported only for the removed line: without pruning the
	// mutant would not build and would prove nothing.
	src := strings.Replace(authOK, "var ErrDenied = errors.New(\"denied\")\n", "var ErrDenied error\n", 1)
	src = strings.Replace(src, "return ErrDenied //subpoena:enforcement", "return errors.New(\"denied\") //subpoena:enforcement", 1)
	test := strings.Replace(strongTest, "Allow(false) == nil", "Allow(false) == nil && ErrDenied == nil", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Killed {
		t.Fatalf("want killed after pruning the unused import, got %+v", rep.Results[0])
	}
}

func TestRelativeReplaceStillResolvesInTheCopy(t *testing.T) {
	// mini depends on a sibling module through `replace ... => ../lib`, as a
	// service developed against a local checkout does.
	root := t.TempDir()
	write := func(p, src string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "lib", "go.mod"), "module example.com/lib\n\ngo 1.24\n")
	write(filepath.Join(root, "lib", "lib.go"), "package lib\n\nfunc Admin(name string) bool { return name == \"root\" }\n")
	write(filepath.Join(root, "mini", "go.mod"), "module mini\n\ngo 1.24\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => ../lib\n")
	write(filepath.Join(root, "mini", "auth.go"), authOK)
	write(filepath.Join(root, "mini", "auth_test.go"), strings.Replace(strongTest, `import "testing"`, "import (\n\t\"testing\"\n\n\t\"example.com/lib\"\n)", 1)+
		"\nfunc TestLib(t *testing.T) {\n\tif !lib.Admin(\"root\") {\n\t\tt.Fatal(\"lib\")\n\t}\n}\n")
	rep, err := run(t, filepath.Join(root, "mini"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Killed {
		t.Fatalf("want killed, got %+v", rep.Results[0])
	}
}

func TestRedBaselineIsAnError(t *testing.T) {
	failing := strongTest + "\nfunc TestBroken(t *testing.T) { t.Fatal(\"red\") }\n"
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": failing})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("want baseline error, got %v", err)
	}
}

func TestNoMarkerIsAnError(t *testing.T) {
	src := strings.Replace(authOK, " //subpoena:enforcement", "", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "Allow is marked //subpoena:enforcement_point but has no //subpoena:enforcement statement") {
		t.Fatalf("want an error naming Allow, got %v", err)
	}
}

// One covered enforcement point must not hide another that has no statement
// marker: the run fails and names the forgotten function.
func TestEveryEnforcementPointNeedsAStatementMarker(t *testing.T) {
	forgotten := authOK + `
// Forgotten also decides.
//
//subpoena:enforcement_point
func Forgotten(admin bool) error {
	if !admin {
		return ErrDenied
	}
	return nil
}
`
	dir := module(t, map[string]string{"auth.go": forgotten, "auth_test.go": strongTest})
	if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), "Forgotten") {
		t.Fatalf("want an error naming Forgotten, got %v", err)
	}
	if _, err := run(t, dir); err == nil {
		t.Fatal("cross-examination must fail when an enforcement point has no statement marker")
	}
}

func TestNoEnforcementPointIsVacuous(t *testing.T) {
	src := strings.Replace(authOK, "//\n//subpoena:enforcement_point\n", "", 1)
	src = strings.Replace(src, " //subpoena:enforcement", "", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "vacuous") {
		t.Fatalf("want vacuous cross-examination error, got %v", err)
	}
}

func TestMarkerOnCompoundStatementIsRejected(t *testing.T) {
	src := strings.Replace(authOK, "if !admin {", "if !admin { //subpoena:enforcement", 1)
	src = strings.Replace(src, " //subpoena:enforcement\n\t}", "\n\t}", 1)
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": strongTest})
	// The rejection must be for the misplaced marker itself, not a later check.
	if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), "not on a simple statement line") {
		t.Fatalf("a marker on an if line must be rejected rather than remove the whole if; got %v", err)
	}
}

// A statement marker outside an enforcement point, or a misspelt marker,
// would leave its statement unexamined while the run stays green.
func TestStrayAndMisspeltMarkersAreRefused(t *testing.T) {
	for name, src := range map[string]string{
		"outside a point":             strings.Replace(authOK, "//\n//subpoena:enforcement_point\n", "", 1),
		"misspelt in a point":         strings.Replace(authOK, "\treturn nil\n}", "\treturn nil //subpoena:enforcement_gaurd true\n}", 1),
		"point marker off a function": authOK + "\n//subpoena:enforcement_point\nvar X = 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := module(t, map[string]string{"auth.go": src})
			if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), "is not a marker cross applies") {
				t.Fatalf("want a stray-marker error, got %v", err)
			}
		})
	}
	// Prose that mentions a marker mid-comment is not a marker.
	dir := module(t, map[string]string{"auth.go": authOK + "\n// Mark it //subpoena:enforcement on the line.\n"})
	if ms, err := FindMutants(dir, dir); err != nil || len(ms) != 1 {
		t.Fatalf("prose must not count as a marker: %v %v", ms, err)
	}
}

// A run whose context is canceled is an error, not a kill: the go command it
// stopped proves nothing about the mutant.
func TestCanceledRunIsAnErrorNotAKill(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rep, err := Run(ctx, Options{Target: dir, beforeMutate: func(string) { cancel() }})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want a canceled error, got %v %+v", err, rep)
	}
}

// runCase itself refuses a canceled run, whoever called it: a group run has
// no runSingles around it.
func TestRunCaseRefusesACanceledRun(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	ms, err := FindMutants(dir, dir)
	if err != nil || len(ms) != 1 {
		t.Fatalf("FindMutants: %v %v", ms, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := runCase(ctx, Options{Log: io.Discard}, sandbox{dir: dir}, "./...", ms)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want a canceled error, got %v %+v", err, res)
	}
}

func TestMarkerRegexDoesNotMatchEnforcementPoint(t *testing.T) {
	if isEnforcementComment("//subpoena:enforcement_point") {
		t.Fatal("enforcement_point must not be treated as the statement marker")
	}
	if !isEnforcementComment("//subpoena:enforcement") || !isEnforcementComment("// subpoena:enforcement because") {
		t.Fatal("statement marker not recognised")
	}
}

// The doc marker is matched as subpoena-lint matches it, so a function lint
// treats as an enforcement point cannot slip past cross-examination.
func TestPointMarkerMatchesLikeLint(t *testing.T) {
	for _, doc := range []string{"//subpoena:enforcement_points", "// see subpoena:enforcement_point", "/* subpoena:enforcement_point */"} {
		src := strings.Replace(authOK, "//subpoena:enforcement_point", doc, 1)
		src = strings.Replace(src, " //subpoena:enforcement", "", 1)
		dir := module(t, map[string]string{"auth.go": src})
		if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), "Allow") {
			t.Fatalf("%s: want an error naming Allow, got %v", doc, err)
		}
	}
}

// Methods share a name across receivers; each is its own enforcement point.
func TestMethodsWithTheSameNameCountSeparately(t *testing.T) {
	src := `package mini

import "errors"

var ErrDenied = errors.New("denied")

type A struct{}
type B struct{}

//subpoena:enforcement_point
func (A) Allow(admin bool) error {
	if !admin {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}

//subpoena:enforcement_point
func (B) Allow(admin bool) error {
	if !admin {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`
	test := `package mini

import "testing"

func TestDeny(t *testing.T) {
	if (A{}).Allow(false) == nil || (B{}).Allow(false) == nil {
		t.Fatal("non-admin allowed")
	}
}
`
	dir := module(t, map[string]string{"auth.go": src, "auth_test.go": test})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.EnforcementPoints != 2 || len(rep.Results) != 2 || rep.Failed() {
		t.Fatalf("want 2 points, 2 killed; got %d points, %+v", rep.EnforcementPoints, rep.Results)
	}
}

func TestChangedSourceAfterDiscoveryIsNotSliced(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	ms, err := FindMutants(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || len(ms[0].src) == 0 {
		t.Fatalf("discovery did not keep snapshot bytes: %+v", ms)
	}
	drifted := append([]byte("// edited during the run\n"), ms[0].src...)
	if err := os.WriteFile(filepath.Join(dir, "auth.go"), drifted, 0o644); err != nil {
		t.Fatal(err)
	}
	mutated, err := applyMutant(ms[0].src, ms[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "auth.go", mutated, 0); err != nil {
		t.Fatalf("snapshot mutant does not parse: %v", err)
	}
	if _, err := applyMutant(drifted, ms[0]); err == nil || !strings.Contains(err.Error(), "source drift") {
		t.Fatalf("changed bytes were accepted, err=%v", err)
	}
	// The live file is not what a later reread would have to slice.
	live, err := os.ReadFile(filepath.Join(dir, "auth.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(live[ms[0].start:ms[0].end]) == ms[0].Removed {
		t.Fatal("prepend did not shift the discovered statement")
	}
	// The previous reread applied those offsets to the changed bytes.
	sliced := append(append(append([]byte{}, drifted[:ms[0].start]...), []byte("/* removed by subpoena-cross */")...), drifted[ms[0].end:]...)
	if _, err := parser.ParseFile(token.NewFileSet(), "auth.go", sliced, 0); err == nil {
		t.Fatal("stale-offset slice of the changed file still parsed; reproduction no longer shows an invalid mutant")
	}
}

func TestRunUsesSnapshotWhenLiveSourceChangesAfterDiscovery(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	orig, err := os.ReadFile(filepath.Join(dir, "auth.go"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(orig)
	want := hex.EncodeToString(sum[:])
	rep, err := Run(context.Background(), Options{
		Target: dir,
		afterDiscover: func(liveRoot string) {
			b, err := os.ReadFile(filepath.Join(liveRoot, "auth.go"))
			if err != nil {
				t.Fatal(err)
			}
			drifted := append([]byte("// edited during baseline\n"), b...)
			if err := os.WriteFile(filepath.Join(liveRoot, "auth.go"), drifted, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Killed || rep.Failed() {
		t.Fatalf("live edit changed the mutant result: %+v err=%v", rep.Results, err)
	}
	var got string
	for _, file := range rep.Snapshot {
		if file.Path == "auth.go" {
			got = file.SHA256
		}
	}
	if got != want {
		t.Fatalf("snapshot hash = %s, want pre-edit %s", got, want)
	}
	live, err := os.ReadFile(filepath.Join(dir, "auth.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(live) == string(orig) {
		t.Fatal("baseline hook did not change the live file")
	}
}

func TestRunRefusesCopyDriftBeforeMutation(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest})
	_, err := Run(context.Background(), Options{
		Target: dir,
		beforeMutate: func(tmpRoot string) {
			p := filepath.Join(tmpRoot, "auth.go")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append([]byte("// copy drifted\n"), b...), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "snapshot drift") {
		t.Fatalf("copy drift was not refused: %v", err)
	}
}

// hangOK sleeps where enforcement used to return, so removing the enforcement
// makes the suite hang rather than fail. Before sleeping it writes its pid to
// PIDFILE, so the test can check the timeout killed it.
const hangOK = `package mini

import (
	"os"
	"strconv"
	"time"
)

// Allow decides.
//
//subpoena:enforcement_point
func Allow(admin bool) bool {
	if !admin {
		return false //subpoena:enforcement
	}
	os.WriteFile("PIDFILE", []byte(strconv.Itoa(os.Getpid())), 0o644)
	time.Sleep(time.Hour)
	return true
}
`

const hangTest = `package mini

import "testing"

func TestDeny(t *testing.T) {
	if Allow(false) {
		t.Fatal("non-admin allowed")
	}
}
`

// A mutant whose suite hangs past the timeout is not a kill: the hang may be
// the host's, and nothing asserted the enforcement.
func TestHangingMutantTimesOutNotKilled(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	dir := module(t, map[string]string{"auth.go": strings.Replace(hangOK, "PIDFILE", pidFile, 1), "auth_test.go": hangTest})
	rep, err := Run(context.Background(), Options{Target: dir, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != TimedOut || !rep.Failed() {
		t.Fatalf("want timed out, got %+v", rep.Results)
	}
	if u := rep.Results[0].Unfinished; !slices.Contains(u, "mini TestDeny") {
		t.Fatalf("the report must name the hung test, got %q", u)
	}
	// The timeout kills the test binary too, not only the go command. A
	// killed process may linger unreaped as a zombie, which is not running.
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the mutant never reached the hang: %v", err)
	}
	if stat, err := os.ReadFile("/proc/" + string(pid) + "/stat"); err == nil {
		if f := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:])); len(f) > 0 && f[0] != "Z" {
			t.Fatalf("hung test binary %s outlived the timeout (state %s)", pid, f[0])
		}
	}
}

// The test binary's own -timeout panic counts as a timeout too.
func TestTestBinaryTimeoutPanicIsATimeout(t *testing.T) {
	out := "panic: test timed out after 10m0s\n\trunning tests:\n\t\tTestDeny (10m0s)\n"
	if !timedOut(out, errors.New("exit status 2")) {
		t.Fatal("the test binary's timeout panic must be a timeout")
	}
	if timedOut("--- FAIL: TestDeny (0.00s)\n", errors.New("exit status 1")) {
		t.Fatal("a failing test is not a timeout")
	}
}

const guardSrc = `package mini

var Ran bool

// Exec runs only when not revoked.
//
//subpoena:enforcement_point
func Exec(revoked bool) {
	if !revoked { //subpoena:enforcement_guard true
		Ran = true
	}
}
`

const guardStrongTest = `package mini

import "testing"

func TestRevokedDoesNotRun(t *testing.T) {
	Ran = false
	Exec(true)
	if Ran {
		t.Fatal("revoked session ran")
	}
}
`

const guardWeakTest = `package mini

import "testing"

func TestRuns(t *testing.T) {
	Exec(false)
	if !Ran {
		t.Fatal("did not run")
	}
}
`

func TestGuardMarkerFindsTheCondition(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": guardSrc, "exec_test.go": guardStrongTest})
	ms, err := FindMutants(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Removed != "!revoked" || ms[0].Bypass != "true" || ms[0].Line != 9 {
		t.Fatalf("unexpected mutants: %+v", ms)
	}
	got, err := applyMutant(ms[0].src, ms[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "if (!revoked) || true /* forced by subpoena-cross */ {") {
		t.Fatalf("condition not forced:\n%s", got)
	}
}

func TestForcedGuardIsKilledByAStrongSuite(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": guardSrc, "exec_test.go": guardStrongTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Killed || rep.Failed() {
		t.Fatalf("want killed, got %+v", rep.Results)
	}
}

func TestForcedGuardSurvivesAWeakSuite(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": guardSrc, "exec_test.go": guardWeakTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Outcome != Survived || !rep.Failed() {
		t.Fatalf("want survived, got %+v", rep.Results)
	}
}

func TestBadMarkersAreRefused(t *testing.T) {
	for name, tc := range map[string]struct{ line, want string }{
		"guard without value":             {"if !revoked { //subpoena:enforcement_guard", "needs the bypass value"},
		"guard bad value":                 {"if !revoked { //subpoena:enforcement_guard yes", "needs the bypass value"},
		"unknown argument":                {"if !revoked { //subpoena:enforcement_guard true grop=x", "want at most one group"},
		"two groups":                      {"if !revoked { //subpoena:enforcement_guard true group=a group=b", "want at most one group"},
		"guard not on an if":              {"if !revoked {\n\t\tRan = true //subpoena:enforcement_guard true\n\t\t_ = 0", "is not on an if line"},
		"guard on an inline closure's if": {"f := func() { if revoked { Ran = true } } //subpoena:enforcement_guard true\n\tf()\n\tif !revoked {", "is not on an if line"},
	} {
		t.Run(name, func(t *testing.T) {
			src := strings.Replace(guardSrc, "if !revoked { //subpoena:enforcement_guard true", tc.line, 1)
			dir := module(t, map[string]string{"exec.go": src})
			if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	dir := module(t, map[string]string{"auth.go": strings.Replace(authOK, "ErrDenied //subpoena:enforcement", "ErrDenied //subpoena:enforcement because", 1)})
	if _, err := FindMutants(dir, dir); err == nil || !strings.Contains(err.Error(), "want at most one group") {
		t.Fatalf("statement marker with a stray argument: %v", err)
	}
}

// Two layers of one guarantee: an early refusal, and a guard in the runner.
// Either alone stops the run, so each single mutant survives.
const layeredSrc = `package mini

import "errors"

var ErrRevoked = errors.New("revoked")

var Ran int

// Exec refuses a revoked session.
//
//subpoena:enforcement_point
func Exec(revoked bool) error {
	if revoked {
		return ErrRevoked //subpoena:enforcement group=revoke
	}
	run(revoked)
	return nil
}

// run checks again before running.
//
//subpoena:enforcement_point
func run(revoked bool) {
	if !revoked { //subpoena:enforcement_guard true group=revoke
		Ran++
	}
}
`

const layeredTest = `package mini

import "testing"

func TestRevokedNeverRuns(t *testing.T) {
	Ran = 0
	Exec(true)
	if Ran != 0 {
		t.Fatal("revoked session ran")
	}
}
`

func TestMaskedLayersNameEachOther(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": layeredTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("want 2 layers and 1 group run, got %+v", rep.Results)
	}
	ret, guard, group := rep.Results[0], rep.Results[1], rep.Results[2]
	if ret.Outcome != Masked || len(ret.MaskedBy) != 1 || ret.MaskedBy[0] != guard.Mutant.Name() {
		t.Fatalf("return layer: %+v", ret)
	}
	if guard.Outcome != Masked || len(guard.MaskedBy) != 1 || guard.MaskedBy[0] != ret.Mutant.Name() {
		t.Fatalf("guard layer: %+v", guard)
	}
	if group.Group != "revoke" || group.Outcome != Killed || len(group.With) != 1 {
		t.Fatalf("group run: %+v", group)
	}
	if !rep.Failed() {
		t.Fatal("a masked layer not listed in cross-masked.txt must fail the run")
	}
}

const maskedList = `# accepted masked layers
exec.go | Exec | group=revoke | return ErrRevoked | the runner re-checks; tested together
exec.go | run | group=revoke | !revoked | the early refusal covers this; tested together
`

func TestListedMaskedLayersAreAccepted(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": layeredTest, MaskedFile: maskedList})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() || len(rep.StaleAccepted) != 0 {
		t.Fatalf("listed masked layers must pass: %+v stale=%v", rep.Results, rep.StaleAccepted)
	}
	if rep.Results[0].Accepted != "the runner re-checks; tested together" {
		t.Fatalf("reason not recorded: %+v", rep.Results[0])
	}
	// One layer listed, the other not: still fails.
	one := strings.Join(strings.Split(maskedList, "\n")[:2], "\n") + "\n"
	dir = module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": layeredTest, MaskedFile: one})
	if rep, err = run(t, dir); err != nil || !rep.Failed() {
		t.Fatalf("an unlisted masked layer must fail: %v %+v", err, rep)
	}
}

func TestStaleMaskedEntryFails(t *testing.T) {
	list := maskedList + "exec.go | Exec | group=revoke | return nil | no such masked layer\n"
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": layeredTest, MaskedFile: list})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.StaleAccepted) != 1 || !rep.Failed() {
		t.Fatalf("want one stale entry failing the run, got %v", rep.StaleAccepted)
	}
}

// The entry names the layer's group: a layer moved to another group is
// masked by other layers, so its acceptance does not carry over.
func TestMaskedEntryNamesTheGroup(t *testing.T) {
	layer := Mutant{File: "exec.go", Func: "Exec", Group: "moved", Removed: "return ErrNo"}
	rep := &Report{Results: []Result{{Mutant: layer, Outcome: Masked}}}
	path := filepath.Join(t.TempDir(), MaskedFile)
	if err := os.WriteFile(path, []byte("exec.go | Exec | group=g | return ErrNo | covered together\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := acceptMasked(rep, path); err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Accepted != "" || len(rep.StaleAccepted) != 1 || !rep.Failed() {
		t.Fatalf("an entry for another group must not accept the layer: %+v stale=%v", rep.Results, rep.StaleAccepted)
	}
	if err := os.WriteFile(path, []byte("exec.go | Exec | return ErrNo | no group\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := acceptMasked(rep, path); err == nil || !strings.Contains(err.Error(), "group=<group>") {
		t.Fatalf("an entry without its group must be refused, got %v", err)
	}
}

func TestMalformedMaskedFileIsAnError(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": layeredTest, MaskedFile: "exec.go | Exec | group=revoke | return ErrRevoked |\n"})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "want <file>") {
		t.Fatalf("missing reason: %v", err)
	}
}

// A layer killed on its own makes every run that includes it red. That must
// not excuse a sibling nothing tests.
func TestKilledLayerDoesNotMaskAnUntestedSibling(t *testing.T) {
	onlyErr := strings.Replace(layeredTest, "if Ran != 0 {", "if Exec(true) == nil {", 1)
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": onlyErr})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Outcome != Killed || rep.Results[1].Outcome != Survived || !rep.Failed() {
		t.Fatalf("want return killed, guard survived, run failed: %+v", rep.Results)
	}
}

func TestSurvivingGroupFailsAndLayersStaySurvived(t *testing.T) {
	weak := strings.Replace(layeredTest, "if Ran != 0 {", "if false {", 1)
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": weak})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.Outcome != Survived {
			t.Fatalf("want every run survived, got %+v", rep.Results)
		}
	}
	if !rep.Failed() {
		t.Fatal("a surviving group must fail")
	}
}

func TestGroupSizeIsChecked(t *testing.T) {
	one := strings.Replace(layeredSrc, " group=revoke\n\t\tRan++", "\n\t\tRan++", 1)
	dir := module(t, map[string]string{"exec.go": one, "exec_test.go": layeredTest})
	if _, err := run(t, dir); err == nil || !strings.Contains(err.Error(), "needs at least two") {
		t.Fatalf("group of one: %v", err)
	}
	ms := make([]Mutant, maxGroup+1)
	for i := range ms {
		ms[i] = Mutant{Func: "F", File: "f.go", Line: i + 1, Group: "big"}
	}
	if _, err := groupsOf(ms); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("group of %d: %v", len(ms), err)
	}
	if g, err := groupsOf(ms[:maxGroup]); err != nil || len(g["big"]) != maxGroup {
		t.Fatalf("group of %d: %v %v", maxGroup, g, err)
	}
}

func TestOverlappingMutantsAreRefused(t *testing.T) {
	src := []byte("abcdef")
	a := Mutant{Removed: "bcd", start: 1, end: 4, src: src}
	b := Mutant{Removed: "de", start: 3, end: 5, src: src}
	if _, err := applyMutants(src, []Mutant{a, b}); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("want overlap error, got %v", err)
	}
}

// A cancel in a watcher goroutine is an ordinary statement mutant.
const watcherSrc = `package mini

import "context"

// Watch cancels the session's context when it is revoked.
//
//subpoena:enforcement_point
func Watch(cancel context.CancelFunc, revoked <-chan struct{}) {
	go func() {
		<-revoked
		cancel() //subpoena:enforcement
	}()
}
`

const watcherTest = `package mini

import (
	"context"
	"testing"
	"time"
)

func TestRevokeCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	revoked := make(chan struct{})
	Watch(cancel, revoked)
	close(revoked)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not cancel the session")
	}
}
`

func TestCancelInAWatcherGoroutineIsAMutant(t *testing.T) {
	dir := module(t, map[string]string{"watch.go": watcherSrc, "watch_test.go": watcherTest})
	rep, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Mutant.Removed != "cancel()" || rep.Results[0].Outcome != Killed {
		t.Fatalf("want cancel() killed, got %+v", rep.Results)
	}
}

// One cross-masked.txt entry accepts one layer: an entry matching two masked
// layers (the same text twice in one function) is refused, and so is an
// entry listed twice.
func TestMaskedEntryAcceptsOneLayer(t *testing.T) {
	layer := Mutant{File: "exec.go", Func: "Exec", Group: "g", Removed: "return ErrNo"}
	twoLayers := &Report{Results: []Result{{Mutant: layer, Outcome: Masked}, {Mutant: layer, Outcome: Masked}}}
	path := filepath.Join(t.TempDir(), MaskedFile)
	if err := os.WriteFile(path, []byte("exec.go | Exec | group=g | return ErrNo | covered together\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := acceptMasked(twoLayers, path); err == nil || !strings.Contains(err.Error(), "matches 2 masked layers") {
		t.Fatalf("want an ambiguous-entry error, got %v", err)
	}
	for _, r := range twoLayers.Results {
		if r.Accepted != "" {
			t.Fatalf("an ambiguous entry must accept nothing: %+v", twoLayers.Results)
		}
	}
	oneLayer := &Report{Results: []Result{{Mutant: layer, Outcome: Masked}}}
	if err := os.WriteFile(path, []byte("exec.go | Exec | group=g | return ErrNo | one\nexec.go | Exec | group=g | return ErrNo | two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := acceptMasked(oneLayer, path); err == nil || !strings.Contains(err.Error(), "each layer listed once") {
		t.Fatalf("want a duplicate-entry error, got %v", err)
	}
}

const threePoints = `package mini

import "errors"

var ErrDenied = errors.New("denied")

//subpoena:enforcement_point
func A(ok bool) error {
	if !ok {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}

//subpoena:enforcement_point
func B(ok bool) error {
	if !ok {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}

//subpoena:enforcement_point
func C(ok bool) error {
	if !ok {
		return ErrDenied //subpoena:enforcement
	}
	return nil
}
`

// A and C are tested; B is not, so it survives.
const threeTests = `package mini

import "testing"

func TestA(t *testing.T) {
	if A(false) == nil {
		t.Fatal("A must deny")
	}
}
func TestC(t *testing.T) {
	if C(false) == nil {
		t.Fatal("C must deny")
	}
}
`

// Parallel workers give the same verdicts, in the same order, as one.
func TestParallelJobsGiveTheSameVerdicts(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": threePoints, "auth_test.go": threeTests})
	outcomes := func(jobs int) []string {
		rep, err := Run(context.Background(), Options{Target: dir, Jobs: jobs})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rep.Results {
			out = append(out, r.Mutant.Func+" "+string(r.Outcome))
		}
		return out
	}
	one, three := outcomes(1), outcomes(3)
	want := []string{"A " + string(Killed), "B " + string(Survived), "C " + string(Killed)}
	if strings.Join(one, ",") != strings.Join(want, ",") || strings.Join(three, ",") != strings.Join(want, ",") {
		t.Fatalf("jobs=1 %v, jobs=3 %v, want %v", one, three, want)
	}
}

// With selection each mutant runs only the tests that executed its line, and
// the verdicts match a full run. B has no test, so it runs the whole suite and
// survives as before.
func TestSelectionRunsOnlyCoveringTests(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": threePoints, "auth_test.go": threeTests})
	var log bytes.Buffer
	rep, err := Run(context.Background(), Options{Target: dir, Select: true, Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rep.Results {
		got = append(got, r.Mutant.Func+" "+string(r.Outcome))
	}
	want := []string{"A " + string(Killed), "B " + string(Survived), "C " + string(Killed)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, line := range []string{"selected tests: ^(TestA)$", "selected tests: ^(TestC)$"} {
		if !strings.Contains(log.String(), line) {
			t.Fatalf("log lacks %q:\n%s", line, log.String())
		}
	}
	if strings.Count(log.String(), "selected tests:") != 2 {
		t.Fatalf("B has no covering test and must run the whole suite:\n%s", log.String())
	}
}

// TestB passes in the full suite only because TestA ran first. Alone it fails,
// so any subset run holding it would be a kill without the mutant: refused.
func TestSelectionRefusesATestThatFailsAlone(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": `//subpoena:impl_derived

package mini

import "testing"

var ready bool

func TestA(t *testing.T) {
	ready = true
	if Allow(false) == nil {
		t.Fatal("denied caller allowed")
	}
}

func TestB(t *testing.T) {
	if !ready {
		t.Fatal("needs TestA first")
	}
}
`})
	_, err := Run(context.Background(), Options{Target: dir, Select: true})
	if err == nil || !strings.Contains(err.Error(), "TestB fails when run alone") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

// From review: each test passes alone and the full suite stays green with
// the mutant, but the selected subset {TestA, TestC} fails without TestReset,
// mutant or not. Selection must refuse it, not report a kill.
const orderDependentTest = `package mini

import "testing"

var dirty bool

func TestA(t *testing.T) {
	_ = Allow(false)
	dirty = true
}

func TestReset(t *testing.T) { dirty = false }

func TestC(t *testing.T) {
	_ = Allow(false)
	if dirty {
		t.Fatal("state left by TestA")
	}
}
`

func TestSelectionRefusesASubsetThatFailsWithoutTheMutant(t *testing.T) {
	_, err := Run(context.Background(), Options{Target: module(t, map[string]string{"auth.go": authOK, "auth_test.go": orderDependentTest}), Select: true})
	if err == nil || !strings.Contains(err.Error(), "fail together without any mutant") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

// From review: the return layer is caught alone only by a test that checks in
// a re-exec'd child, whose coverage the parent's profile lacks. Selection
// leaves that test out; the layer must still be judged on the whole suite,
// not come back as a masked layer that cross-masked.txt accepts.
const subprocessTest = `package mini

import (
	"os"
	"os/exec"
	"testing"
)

func TestRevokedNeverRuns(t *testing.T) {
	Ran = 0
	Exec(true)
	if Ran != 0 {
		t.Fatal("revoked session ran")
	}
}

func TestChild(t *testing.T) {
	if os.Getenv("PROBE_CHILD") != "1" {
		return
	}
	if Exec(true) != ErrRevoked {
		os.Exit(3)
	}
}

func TestRevokedErrorInChild(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "PROBE_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
`

func TestSelectionConfirmsSurvivorsOnTheWholeSuite(t *testing.T) {
	files := func() map[string]string {
		return map[string]string{"exec.go": layeredSrc, "exec_test.go": subprocessTest, MaskedFile: maskedList}
	}
	verdicts := func(sel bool) (string, bool) {
		rep, err := Run(context.Background(), Options{Target: module(t, files()), Select: sel})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rep.Results {
			out = append(out, r.Mutant.Name()+" "+string(r.Outcome)+" "+r.Accepted)
		}
		return strings.Join(out, ", "), rep.Failed()
	}
	full, fullFailed := verdicts(false)
	sel, selFailed := verdicts(true)
	if sel != full || !selFailed || !fullFailed {
		t.Fatalf("selection changed the verdicts:\n full:   %s (failed=%v)\n select: %s (failed=%v)", full, fullFailed, sel, selFailed)
	}
}
