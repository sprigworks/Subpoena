package harness

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

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
)

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
// refuses, and for missing or bad capture health. If the test has already
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
		case p.NameOnly() && slices.Contains(programs(rule.Never), p.Command):
			tb.Errorf("%s: refused program seen by name only for %s, arguments unknown: pid %d %q (%s)", TagWitness, traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case p.NameOnly() && rule.Allowed != nil && !(rule.ExcuseNameOnly && slices.Contains(programs(rule.Allowed), p.Command)):
			tb.Errorf("%s: process seen by name only for %s, not identified: pid %d %q (%s)", TagWitness, traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case p.NameOnly() && rule.Allowed != nil:
			tb.Logf("%s: excused name-only sighting for %s: pid %d %q (%s)", TagWitness, traceID, p.PID, p.Command, p.Attribution)
		case matchesAny(p.Command, rule.Never):
			tb.Errorf("%s: refused command ran for %s: pid %d %q (%s)", TagWitness, traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case rule.Allowed != nil && !slices.Contains(rule.Allowed, p.Command):
			tb.Errorf("%s: command not allowed for %s: pid %d %q (%s)", TagWitness, traceID, p.PID, p.Command, p.Attribution) //subpoena:enforcement
			ok = false
		case failedBefore:
			tb.Logf("%s: after an earlier failure, saw pid %d %q (%s)", TagWitness, p.PID, p.Command, p.Attribution)
		}
	}
	h, isReporter := w.(witness.HealthReporter)
	if !isReporter {
		tb.Errorf("%s: %s: witness does not report capture health; absence of refused commands is not proven", TagWitness, traceID) //subpoena:enforcement
		return false
	}
	if err := h.Health(); err != nil {
		tb.Errorf("%s: %s: capture unhealthy, absence of refused commands is not proven: %v", TagWitness, traceID, err) //subpoena:enforcement
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
		name := path.Base(f[0])
		if len(name) > 15 {
			name = name[:15]
		}
		out = append(out, name)
	}
	return out
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
		tb.Errorf("%s", noSpawnMessage(traceID, v, err))
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
		tb.Errorf("%s", noDialMessage(traceID, v, err))
		return false
	}
	return true
}

func noSpawnMessage(traceID string, v Verdict, err error) string {
	return fmt.Sprintf("%s: no spawn for %s: %s: %v", TagWitness, traceID, v, err)
}

func noDialMessage(traceID string, v Verdict, err error) string {
	return fmt.Sprintf("%s: no dial for %s: %s: %v", TagWitness, traceID, v, err)
}
