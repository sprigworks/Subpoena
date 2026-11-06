package harness

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoRow checks a database witness after its observation window has ended. A
// committed write that changed rows and counts against table (the empty table:
// any) contradicts absence even if capture was unhealthy. A statement the
// witness could not read counts against every table. With no such write, missing
// or bad health makes the claim Inconclusive, and so does a witness file with no
// row capture in it.
//
//subpoena:enforcement_point
func NoRow(w witness.DBWitness, traceID, table string) (Verdict, error) {
	var hits []witness.RowEvent
	for _, e := range w.Committed(traceID) {
		if e.Effect() && e.Touches(table) {
			hits = append(hits, e)
		}
	}
	if len(hits) != 0 {
		return Fail, fmt.Errorf("witness saw committed writes for %s: %+v", traceID, hits) //subpoena:enforcement
	}
	if err := rowCapture(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	if err := captureHealth(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	return Pass, nil
}

// rowCapture is the fault of a witness file whose start record names no database
// witness: it has no row lines because nothing looked.
//
//subpoena:enforcement_point
func rowCapture(w any) error {
	if c, ok := w.(interface{ CapturedRows() bool }); ok && !c.CapturedRows() {
		return errors.New("the witness file's start record names no row capture, so a write could not have been seen (read the file subpoena-witness db wrote)") //subpoena:enforcement
	}
	return nil
}

// RequireNoRow fails the test unless a healthy witness reports no committed row
// in table. The empty table means any table.
func RequireNoRow(tb testing.TB, w witness.DBWitness, traceID, table string) {
	tb.Helper()
	v, err := NoRow(w, traceID, table)
	if v != Pass {
		tb.Fatalf("%s", noRowMessage(tb, traceID, table, v, err))
	}
}

// CheckNoRow is RequireNoRow without stopping the test. It reports whether the
// check passed.
func CheckNoRow(tb testing.TB, w witness.DBWitness, traceID, table string) bool {
	tb.Helper()
	v, err := NoRow(w, traceID, table)
	if v != Pass {
		tb.Errorf("%s", noRowMessage(tb, traceID, table, v, err))
		return false
	}
	return true
}

func noRowMessage(tb testing.TB, traceID, table string, v Verdict, err error) string {
	return verdictText(tb, fmt.Sprintf("no row in %q for %s: %s: %v", table, traceID, v, err), v)
}

// RowRule says which tables a WatchRows check accepts writes to. An entry
// compares as RowEvent.Touches does: without case, and with or without a schema.
// A write the witness could not read counts against every table: it fails on any
// Never entry and on any Allowed list, because it may have been anything.
type RowRule struct {
	// Allowed lists the tables the test may write. Nil allows any table not in
	// Never; an empty, non-nil slice allows none.
	Allowed []string
	// Never lists tables that must not be written, whatever Allowed says.
	Never []string
}

// WatchRows registers a witness check that runs when the test ends, even after
// an earlier Fatal. Call it right after the witness starts.
//
// At cleanup it stops w (if w has a Stop method), then fails the test, tagged
// "witness:", for every committed write the rule refuses, and with
// "inconclusive:" for missing or bad capture health. If the test has already
// failed, every committed write is logged as well.
func WatchRows(tb testing.TB, w witness.DBWitness, traceID string, rule RowRule) {
	tb.Helper()
	tb.Cleanup(func() { checkRows(tb, w, traceID, rule) })
}

// checkRows is WatchRows' cleanup. It reports whether the check passed.
//
//subpoena:enforcement_point
func checkRows(tb testing.TB, w witness.DBWitness, traceID string, rule RowRule) bool {
	failedBefore := tb.Failed()
	stopWitness(w)
	ok := true
	for _, e := range w.Committed(traceID) {
		if !e.Effect() {
			continue
		}
		switch {
		case slices.ContainsFunc(rule.Never, e.Touches):
			WitnessErrorf(tb, "refused table written for %s: %q %v (%s)", traceID, e.Statement, e.Tables, e.Attribution) //subpoena:enforcement
			ok = false
		case rule.Allowed != nil && !allowedWrite(e, rule.Allowed):
			WitnessErrorf(tb, "write not allowed for %s: %q %v %s (%s)", traceID, e.Statement, e.Tables, e.Reason, e.Attribution) //subpoena:enforcement
			ok = false
		case failedBefore:
			tb.Logf("%s: after an earlier failure, saw %q %v (%s)", TagWitness, e.Statement, e.Tables, e.Attribution)
		}
	}
	if err := captureHealth(w); err != nil {
		tb.Errorf("%s: %s: capture unhealthy, absence of refused writes is not proven: %v", TagInconclusive, traceID, err) //subpoena:enforcement
		return false
	}
	return ok
}

// allowedWrite reports whether every table e wrote is on the list. An event with
// no readable table is on no list.
func allowedWrite(e witness.RowEvent, allowed []string) bool {
	if e.Opaque || len(e.Tables) == 0 {
		return false
	}
	for _, t := range e.Tables {
		named := witness.RowEvent{Tables: []string{t}}
		if !slices.ContainsFunc(allowed, named.Touches) {
			return false
		}
	}
	return true
}
