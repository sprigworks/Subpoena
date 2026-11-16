//subpoena:impl_derived
//subpoena:pure_logic

// Transaction boundaries, savepoints, and prepared statement invalidation.
package dbproxy

import (
	"slices"
	"testing"
)

// H5: LOCK TABLES commits before it opens the table, so its ERR has committed
// what came before. So may anything not known to leave the transaction alone.
func TestFailedStatementThatMayCommit(t *testing.T) {
	for _, tc := range []struct {
		sql, want string
	}{
		{"LOCK TABLES no_such WRITE", "committed INSERT"},
		{"UNLOCK TABLES", "committed INSERT"},
		{"RESET MASTER", "committed INSERT"},
		{"ANALYZE TABLE no_such", "committed INSERT"},
		{"DROP TABLE no_such", "committed INSERT"},
		{"SELECT * FROM no_such", "rolled_back INSERT"},
		{"INSERT INTO no_such VALUES (1)", "rolled_back INSERT"},
		{"SET x = 1", "rolled_back INSERT"},
		{"ROLLBACK TO no_such", "rolled_back INSERT"},
	} {
		w := myReadyWire(t, 0)
		w.client(myQuery("START TRANSACTION"))
		w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
		w.client(myQuery("INSERT INTO a VALUES (1)"))
		w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
		w.client(myQuery(tc.sql))
		w.server(myErr(1))
		w.client(myQuery("ROLLBACK"))
		w.server(myOK(1, 0, stAutocommit, 0))
		if got := w.outcomes(); !slices.Contains(got, tc.want) {
			t.Errorf("%q: %v, want %s", tc.sql, got, tc.want)
		}
	}
}

// H6: MySQL compares savepoint names without case, quoted or not, and a second
// savepoint of a name replaces the first.
func TestMySQLSavepointNames(t *testing.T) {
	run := func(second, back string) []string {
		w := myReadyWire(t, 0)
		for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", "INSERT INTO t VALUES (1)", second, back, "COMMIT"} {
			w.client(myQuery(q))
			status := uint16(stAutocommit | stInTrans)
			if q == "COMMIT" {
				status = stAutocommit
			}
			w.server(myOK(1, 0, status, 0))
		}
		return w.outcomes()
	}
	for _, tc := range []struct {
		second, back, want string
	}{
		{"SAVEPOINT `A`", "ROLLBACK TO a", "committed INSERT"},
		{"SAVEPOINT A", "ROLLBACK TO `a`", "committed INSERT"},
		{"SAVEPOINT a", "ROLLBACK TO SAVEPOINT A", "committed INSERT"},
		{"SAVEPOINT `á`", "ROLLBACK TO a", "committed INSERT"},  // a _ci collation folds accents
		{"SAVEPOINT `a `", "ROLLBACK TO a", "committed INSERT"}, // and pads with spaces
		{"SAVEPOINT b", "ROLLBACK TO A", "rolled_back INSERT"},
		{"SAVEPOINT b", "ROLLBACK TO `a`", "rolled_back INSERT"},
	} {
		if got := run(tc.second, tc.back); !slices.Contains(got, tc.want) {
			t.Errorf("%s, %s: %v, want %s", tc.second, tc.back, got, tc.want)
		}
	}
}

// Only the one of that name goes: a savepoint between them stays.
func TestMySQLSavepointBetweenStays(t *testing.T) {
	w := myReadyWire(t, 0)
	for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", "SAVEPOINT b", "SAVEPOINT a", "INSERT INTO t VALUES (1)", "ROLLBACK TO b", "COMMIT"} {
		w.client(myQuery(q))
		status := uint16(stAutocommit | stInTrans)
		if q == "COMMIT" {
			status = stAutocommit
		}
		w.server(myOK(1, 0, status, 0))
	}
	w.want("rolled_back INSERT")
}

// Postgres keeps both, and a quoted name is its own.
func TestPostgresSavepointNames(t *testing.T) {
	w := pgReadyWire(t)
	for _, q := range [][2]string{{"BEGIN", "BEGIN"}, {"SAVEPOINT a", "SAVEPOINT"}, {"INSERT INTO t VALUES (1)", "INSERT 0 1"},
		{`SAVEPOINT "A"`, "SAVEPOINT"}, {`ROLLBACK TO a`, "ROLLBACK"}, {"COMMIT", "COMMIT"}} {
		w.client(pgQuery(q[0]))
		status := byte('T')
		if q[0] == "COMMIT" {
			status = 'I'
		}
		w.server(pgDone(q[1]), pgReady(status))
	}
	w.want("rolled_back INSERT")
}

// M1: a routine can swap what a prepared name holds, and neither a rollback nor a
// failure takes that back.
func TestOpaqueStatementForgetsPreparedNames(t *testing.T) {
	setup := func(t *testing.T) *wire {
		w := pgReadyWire(t)
		w.client(pgParse("s7", "SELECT 1"), pgBind("p7", "s7"), pgSync())
		w.server(frame('1'), frame('2'), pgReady('I'))
		return w
	}
	check := func(t *testing.T, w *wire, frames ...[]byte) {
		t.Helper()
		w.client(frames...)
		w.server(frame('2'), pgDone("SELECT 1"), pgReady('I'))
		found := false
		for _, e := range w.cap.snapshot() {
			found = found || (e.Verb == "EXECUTE" && e.Opaque)
		}
		if !found {
			t.Fatalf("a name a routine could have changed read as what it held: %+v", w.cap.snapshot())
		}
	}
	t.Run("after a rollback", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("BEGIN; SELECT rp(); ROLLBACK"))
		w.server(pgDone("BEGIN"), pgDone("SELECT 1"), pgDone("ROLLBACK"), pgReady('I'))
		check(t, w, pgBind("", "s7"), pgExecute(""), pgSync())
	})
	t.Run("after a failure", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("SELECT rp()"))
		w.server(pgError(), pgReady('I'))
		check(t, w, pgBind("", "s7"), pgExecute(""), pgSync())
	})
	t.Run("a portal too", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("SELECT rp()"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		w.client(pgExecute("p7"), pgSync())
		w.server(pgDone("SELECT 1"), pgReady('I'))
		last := w.cap.snapshot()
		if e := last[len(last)-1]; !e.Opaque {
			t.Fatalf("%+v", last)
		}
	})
	t.Run("a fast-path call", func(t *testing.T) {
		w := setup(t)
		w.client(frame('F'))
		w.server(frame('V'), pgReady('I'))
		check(t, w, pgBind("", "s7"), pgExecute(""), pgSync())
	})
	t.Run("a read leaves them", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("SELECT lower('x')"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		w.client(pgBind("", "s7"), pgExecute(""), pgSync())
		w.server(frame('2'), pgDone("SELECT 1"), pgReady('I'))
		for _, e := range w.cap.snapshot() {
			if e.Opaque {
				t.Fatalf("%+v", e)
			}
		}
	})
}
