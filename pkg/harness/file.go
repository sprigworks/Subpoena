package harness

import (
	"fmt"
	"slices"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoWrite checks the independent file witness after its observation window has
// ended. paths are absolute paths the claim is about, each with everything
// below it (none: anything under the witness's roots). One event that touches
// them contradicts absence even if capture was unhealthy. With none, missing or
// bad health makes the claim Inconclusive, and so does a path the witness does
// not cover: it could never have been seen.
//
//subpoena:enforcement_point
func NoWrite(w witness.FileWitness, traceID string, paths ...string) (Verdict, error) {
	var hits []witness.FileEvent
	for _, e := range w.Wrote(traceID) {
		if len(paths) == 0 || touchesAny(e, paths) {
			hits = append(hits, e)
		}
	}
	if len(hits) != 0 {
		return Fail, fmt.Errorf("witness saw file changes for %s: %+v", traceID, hits) //subpoena:enforcement
	}
	if err := uncovered(w, paths); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	if err := captureHealth(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	return Pass, nil
}

func touchesAny(e witness.FileEvent, paths []string) bool {
	return slices.ContainsFunc(paths, e.Touches)
}

// uncovered is the fault of a claim about a path w does not cover.
func uncovered(w witness.FileWitness, paths []string) error {
	for _, p := range paths {
		if !w.Covers(p) {
			return fmt.Errorf("witness does not watch %s, so it could not have seen a write there", p)
		}
	}
	return nil
}

// RequireNoWrite fails the test unless a healthy witness saw no change to paths
// (none: to anything it watches).
func RequireNoWrite(tb testing.TB, w witness.FileWitness, traceID string, paths ...string) {
	tb.Helper()
	v, err := NoWrite(w, traceID, paths...)
	if v != Pass {
		tb.Fatalf("%s", noWriteMessage(tb, traceID, v, err))
	}
}

// CheckNoWrite is RequireNoWrite without stopping the test. It reports whether
// the check passed.
func CheckNoWrite(tb testing.TB, w witness.FileWitness, traceID string, paths ...string) bool {
	tb.Helper()
	v, err := NoWrite(w, traceID, paths...)
	if v != Pass {
		tb.Errorf("%s", noWriteMessage(tb, traceID, v, err))
		return false
	}
	return true
}

func noWriteMessage(tb testing.TB, traceID string, v Verdict, err error) string {
	return verdictText(tb, fmt.Sprintf("no write for %s: %s: %v", traceID, v, err), v)
}

// WriteRule says which file changes a WatchWrites check accepts. Entries are
// absolute paths, each covering everything below it, and every one must be
// under a root the witness watches.
type WriteRule struct {
	// Allowed lists where the test may write. Nil allows anything not in
	// Never; an empty, non-nil slice allows nothing.
	Allowed []string
	// Never lists paths that must not change in this test, whatever Allowed
	// says. A rename of a directory above an entry counts: it moved the path.
	Never []string
}

// WatchWrites registers a witness check that runs when the test ends, even
// after an earlier Fatal, as WatchSpawns does for processes. Call it right
// after the witness starts.
//
// At cleanup it stops w (if w has a Stop method), then fails the test, with
// messages tagged "witness:", for every change the rule refuses, and with
// "inconclusive:" for a rule path the witness does not cover or for missing or
// bad capture health. If the test has already failed, every change the witness
// saw is logged as well.
func WatchWrites(tb testing.TB, w witness.FileWitness, traceID string, rule WriteRule) {
	tb.Helper()
	tb.Cleanup(func() { checkWrites(tb, w, traceID, rule) })
}

// checkWrites is WatchWrites' cleanup. It reports whether the check passed.
//
//subpoena:enforcement_point
func checkWrites(tb testing.TB, w witness.FileWitness, traceID string, rule WriteRule) bool {
	failedBefore := tb.Failed()
	stopWitness(w)
	ok := true
	for _, e := range w.Wrote(traceID) {
		switch {
		case touchesAny(e, rule.Never):
			WitnessErrorf(tb, "refused path changed for %s: %s %s (%s)", traceID, e.Op, e.Path, e.Attribution) //subpoena:enforcement
			ok = false
		case rule.Allowed != nil && !slices.ContainsFunc(rule.Allowed, e.Within):
			WitnessErrorf(tb, "change not allowed for %s: %s %s (%s)", traceID, e.Op, e.Path, e.Attribution) //subpoena:enforcement
			ok = false
		case failedBefore:
			tb.Logf("%s: after an earlier failure, saw %s %s (%s)", TagWitness, e.Op, e.Path, e.Attribution)
		}
	}
	if err := uncovered(w, slices.Concat(rule.Never, rule.Allowed)); err != nil {
		tb.Errorf("%s: %s: %v", TagInconclusive, traceID, err) //subpoena:enforcement
		return false
	}
	if err := captureHealth(w); err != nil {
		tb.Errorf("%s: %s: capture unhealthy, absence of refused writes is not proven: %v", TagInconclusive, traceID, err) //subpoena:enforcement
		return false
	}
	return ok
}
