package harness

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/internal/crossmark"
	"github.com/sprigworks/subpoena/pkg/witness"
)

// Failure messages from the harness start with a tag saying what kind of
// evidence failed, so a reader, or cross-examination attributing a killed
// mutant, can tell the witness from the system's own report.
const (
	// TagWitness marks a failure the independent witness found.
	TagWitness = "witness"
	// TagTestimony marks a failure in the system's own telemetry.
	TagTestimony = "testimony"
	// TagInconclusive marks a check the witness could not answer: the capture
	// failed, or says nothing of its health. It fails the test, as any
	// Inconclusive does, but it is about the witness and not about the effect,
	// and the code under test can cause it. It is never witness evidence.
	TagInconclusive = "inconclusive"
)

// crossKey is the key subpoena-cross hands a test binary to sign witness
// failures with. It leaves the environment here, so that child processes of the
// code under test do not inherit it. That is all this does: /proc/<pid>/environ
// keeps the value for the life of the process, so in-process code, and any
// process of the same user, a child included, can read it there. Outside cross
// it is empty and nothing is signed. See internal/crossmark.
var crossKey = func() string {
	key := os.Getenv(crossmark.Env)
	os.Unsetenv(crossmark.Env)
	return key
}()

// signable reports whether tb is one of package testing's own types. Only those
// get the mark. The harness is public, so production code could otherwise pass
// a stand-in TB, read the signed message and print it. A wrapper (GinkgoTB, a
// struct embedding *testing.T) is a stand-in too: its failures read as other.
var signable = func(tb testing.TB) bool {
	switch tb.(type) {
	case *testing.T, *testing.B, *testing.F:
		return true
	}
	return false
}

// witnessText signs msg for cross, and leaves it alone outside it.
func witnessText(tb testing.TB, msg string) string {
	if crossKey == "" || !signable(tb) {
		return msg
	}
	return crossmark.Sign(crossKey, msg)
}

// WitnessErrorf fails tb with a message tagged "witness:". A test that asks a
// witness itself reports what it saw through this, not by writing the tag:
// cross counts a tag as witness evidence only if the harness wrote it, since the
// code under test can print any text. Under cross the message's first line ends
// with a mark that says so, if tb is a *testing.T, B or F; elsewhere the message
// is just the text.
func WitnessErrorf(tb testing.TB, format string, args ...any) {
	tb.Helper()
	tb.Errorf("%s", witnessText(tb, TagWitness+": "+fmt.Sprintf(format, args...)))
}

// SpawnRule says which commands a WatchSpawns check accepts. Entries match
// the witness's command line (ProcessEvent.Command), and the two lists match
// differently, each in the direction that fails closed.
//
// Never matches loosely, so it still fires through a wrapper such as timeout
// or env. Allowed matches exactly, so a command line that merely ends with an
// allowed command (`sh -c "x; sleep 0.6"`) is not allowed; list the wrapped
// form ("timeout 5 sleep 0.6") if the test runs one.
//
// A process that exits before its arguments are read is seen by name only
// (ProcessEvent.NameOnly). Such a sighting fails when its name is the program
// of a Never entry, because it may have been that command. Otherwise, with an
// Allowed list, it fails as unidentified unless ExcuseNameOnly is set and the
// name is the program of an Allowed entry. A program is an entry's first
// word, without its directory, cut to the kernel's 15-byte task name.
type SpawnRule struct {
	// Allowed lists the exact command lines the test may run. Nil allows any
	// command not in Never; an empty, non-nil slice allows none.
	Allowed []string
	// Never lists commands that must not run in this test, whatever Allowed
	// says. An entry matches a command line whose words end with its words;
	// the entry's program matches with or without a directory on either
	// side ("sleep 1" refuses "/usr/bin/sleep 1", and the reverse).
	Never []string
	// ExcuseNameOnly logs, instead of failing, a name-only sighting whose name
	// is the program of an Allowed entry. Set it only when the test runs
	// commands too short-lived to be read, and keep every refused probe
	// long-lived, so a refused one is always seen with its arguments.
	ExcuseNameOnly bool
}

// WatchSpawns registers a witness check that runs when the test ends, even
// after an earlier Fatal. A test that fails on an exit status or an audit row
// otherwise stops before anyone asks the witness what ran, and the evidence
// that matters most is never read. Call it right after the witness starts.
//
// At cleanup it stops w (if w has a Stop method), then fails the test, with
// messages tagged "witness:", for every process seen for traceID that the rule
// refuses, and with "inconclusive:" for missing or bad capture health. If the test has already
// failed, every process the witness saw is logged as well.
//
// Cleanups run last-registered first, so this runs before a Stop registered
// earlier; stopping here ends the observation window before it is read.
func WatchSpawns(tb testing.TB, w witness.Witness, traceID string, rule SpawnRule) {
	tb.Helper()
	tb.Cleanup(func() { checkSpawns(tb, w, traceID, rule) })
}

// checkSpawns is WatchSpawns' cleanup. It reports whether the check passed.
//
//subpoena:enforcement_point
func checkSpawns(tb testing.TB, w witness.Witness, traceID string, rule SpawnRule) bool {
	failedBefore := tb.Failed()
	stopWitness(w)
	ok := true
	for _, p := range w.Spawned(traceID) {
		switch {
		case p.NameOnly() && slices.Contains(programs(rule.Never), taskName(p.Command)):
			WitnessErrorf(tb, "refused program seen by name only for %s, arguments unknown: pid %d %q (%s)", traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case p.NameOnly() && rule.Allowed != nil && !(rule.ExcuseNameOnly && slices.Contains(programs(rule.Allowed), taskName(p.Command))):
			WitnessErrorf(tb, "process seen by name only for %s, not identified: pid %d %q (%s)", traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case p.NameOnly() && rule.Allowed != nil:
			tb.Logf("%s: excused name-only sighting for %s: pid %d %q (%s)", TagWitness, traceID, p.PID, p.Command, p.Attribution)
		case matchesAny(p.Command, rule.Never):
			WitnessErrorf(tb, "refused command ran for %s: pid %d %q (%s)", traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case rule.Allowed != nil && !slices.Contains(rule.Allowed, p.Command):
			WitnessErrorf(tb, "command not allowed for %s: pid %d %q (%s)", traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case failedBefore:
			tb.Logf("%s: after an earlier failure, saw pid %d %q (%s)", TagWitness, p.PID, p.Command, p.Attribution)
		}
	}
	h, isReporter := w.(witness.HealthReporter)
	if !isReporter {
		tb.Errorf("%s: %s: witness does not report capture health; absence of refused commands is not proven", TagInconclusive, traceID) //subpoena:enforcement
		return false
	}
	if err := h.Health(); err != nil {
		tb.Errorf("%s: %s: capture unhealthy, absence of refused commands is not proven: %v", TagInconclusive, traceID, err) //subpoena:enforcement
		return false
	}
	return ok
}

// stopWitness ends w's observation window if w can be stopped. Stopping twice
// is safe for the witnesses in this module.
func stopWitness(w any) {
	switch s := w.(type) {
	case interface{ Stop() }:
		s.Stop()
	case interface{ Stop() error }:
		_ = s.Stop()
	}
}

// programs returns the task name each rule's program would have: the first
// word, without its directory, cut to 15 bytes.
func programs(rules []string) []string {
	var out []string
	for _, r := range rules {
		f := strings.Fields(r)
		if len(f) == 0 {
			continue
		}
		out = append(out, taskName(path.Base(f[0])))
	}
	return out
}

// taskName cuts s as the kernel cuts a task name, to 15 bytes, and drops a
// character the cut split (and any replacement character it left), so a
// rule's program and a sighting's name compare the same way in every port.
func taskName(s string) string {
	if len(s) > 15 {
		s = s[:15]
	}
	return strings.TrimRight(strings.ToValidUTF8(s, ""), "\uFFFD")
}

// matchesAny reports whether cmd's words end with one of rules' words, the
// rule's program compared without its directory on both sides, so
// "/usr/bin/sleep 1" and "sleep 1" match each other. Used for Never only: for
// an allow list, a suffix match would let any command line that ends with an
// allowed command through.
func matchesAny(cmd string, rules []string) bool {
	words := strings.Fields(cmd)
	for _, r := range rules {
		rw := strings.Fields(r)
		if len(rw) == 0 || len(rw) > len(words) {
			continue
		}
		tail := words[len(words)-len(rw):]
		if path.Base(tail[0]) == path.Base(rw[0]) && slices.Equal(tail[1:], rw[1:]) {
			return true
		}
	}
	return false
}

// CheckNoSpawn is RequireNoSpawn without stopping the test: it reports the
// failure and returns false, so one failing run can show every kind of
// evidence. It reports whether the check passed.
func CheckNoSpawn(tb testing.TB, w witness.Witness, traceID string) bool {
	tb.Helper()
	v, err := NoSpawn(w, traceID)
	if v != Pass {
		tb.Errorf("%s", noSpawnMessage(tb, traceID, v, err))
		return false
	}
	return true
}

// CheckNoDial is RequireNoDial without stopping the test. It reports whether
// the check passed.
func CheckNoDial(tb testing.TB, w witness.NetworkWitness, traceID string, match func(witness.NetworkEvent) bool) bool {
	tb.Helper()
	v, err := NoDial(w, traceID, match)
	if v != Pass {
		tb.Errorf("%s", noDialMessage(tb, traceID, v, err))
		return false
	}
	return true
}

func noSpawnMessage(tb testing.TB, traceID string, v Verdict, err error) string {
	return verdictText(tb, fmt.Sprintf("no spawn for %s: %s: %v", traceID, v, err), v)
}

func noDialMessage(tb testing.TB, traceID string, v Verdict, err error) string {
	return verdictText(tb, fmt.Sprintf("no dial for %s: %s: %v", traceID, v, err), v)
}

// verdictText tags a check's failure. Only a Fail, which is a sighting, is
// witness evidence.
func verdictText(tb testing.TB, msg string, v Verdict) string {
	if v == Fail {
		return witnessText(tb, TagWitness+": "+msg)
	}
	return TagInconclusive + ": " + msg
}
