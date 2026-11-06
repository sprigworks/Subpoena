package harness

import (
	"fmt"
	"slices"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoCommit checks a SQLite database after the file witness's window has ended.
// With tables, the claim is that no commit changed them, and a commit to
// another table (an audit row, say) does not contradict it. With none, the
// claim is that nothing was committed. A commit the claim covers is Fail even
// if capture was unhealthy. Short of that, it is Inconclusive when the files
// cannot settle it, when the table list may omit a table, when a named table
// is not in the database, when the witness does not watch the database, and on
// missing or bad capture health. Pass needs all of those clear.
//
//subpoena:enforcement_point
func NoCommit(w witness.FileWitness, db witness.SQLiteReader, traceID string, tables ...string) (Verdict, error) {
	c := db.Change(w.Wrote(traceID))
	if len(tables) == 0 && c.Verdict == witness.SQLiteCommitted {
		return Fail, fmt.Errorf("witness saw a commit to %s for %s: %+v", db.Path(), traceID, c) //subpoena:enforcement
	}
	if slices.ContainsFunc(tables, c.Changed) {
		return Fail, fmt.Errorf("witness saw a commit to %v in %s for %s: %+v", c.Tables, db.Path(), traceID, c) //subpoena:enforcement
	}
	if !w.Covers(db.Path()) {
		return Inconclusive, fmt.Errorf("witness does not watch %s, so the reader cannot be told what reached it", db.Path()) //subpoena:enforcement
	}
	if c.Verdict == witness.SQLiteUnknown {
		return Inconclusive, fmt.Errorf("%s: %s", db.Path(), c.Reason) //subpoena:enforcement
	}
	if len(tables) != 0 && !c.Exact {
		return Inconclusive, fmt.Errorf("%s: the table list may be missing a table: %s%s", db.Path(), c.Reason, c.TableError) //subpoena:enforcement
	}
	for _, table := range tables {
		if !c.Knows(table) {
			return Inconclusive, fmt.Errorf("%s has no table %s, so a claim about it proves nothing", db.Path(), table) //subpoena:enforcement
		}
	}
	if err := captureHealth(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	return Pass, nil
}

// RequireNoCommit fails the test unless the checks in NoCommit all clear.
func RequireNoCommit(tb testing.TB, w witness.FileWitness, db witness.SQLiteReader, traceID string, tables ...string) {
	tb.Helper()
	v, err := NoCommit(w, db, traceID, tables...)
	if v != Pass {
		tb.Fatalf("%s", noCommitMessage(tb, traceID, v, err))
	}
}

// CheckNoCommit is RequireNoCommit without stopping the test. It reports
// whether the check passed.
func CheckNoCommit(tb testing.TB, w witness.FileWitness, db witness.SQLiteReader, traceID string, tables ...string) bool {
	tb.Helper()
	v, err := NoCommit(w, db, traceID, tables...)
	if v != Pass {
		tb.Errorf("%s", noCommitMessage(tb, traceID, v, err))
		return false
	}
	return true
}

func noCommitMessage(tb testing.TB, traceID string, v Verdict, err error) string {
	return verdictText(tb, fmt.Sprintf("no commit for %s: %s: %v", traceID, v, err), v)
}
