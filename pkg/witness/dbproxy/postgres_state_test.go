//subpoena:impl_derived
//subpoena:pure_logic

// PostgreSQL protocol confirmations, session taint, and transaction outcomes.
package dbproxy

import (
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

func expectUnknown(t *testing.T, w *wire, verb string) {
	t.Helper()
	for _, e := range w.cap.snapshot() {
		if e.Verb == verb {
			if e.Outcome != witness.OutcomeUnknown {
				t.Fatalf("%s: %+v", verb, e)
			}
			if len(w.cap.faultList()) == 0 {
				t.Fatal("an unknown outcome with healthy capture reads as no row")
			}
			return
		}
	}
	t.Fatalf("no %s in %+v", verb, w.cap.snapshot())
}

// H4.
func TestPostgresPreparedTransactionSettlesAtItsTag(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN; INSERT INTO a VALUES (1); PREPARE TRANSACTION 'x'; ROLLBACK"))
	w.server(pgDone("BEGIN"), pgDone("INSERT 0 1"), pgDone("PREPARE TRANSACTION"), pgDone("ROLLBACK"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed INSERT" {
		t.Fatalf("%q", got)
	}

	w = pgReadyWire(t)
	w.client(pgQuery("BEGIN; INSERT INTO a VALUES (1); PREPARE TRANSACTION 'y'; SELECT 1/0"))
	w.server(pgDone("BEGIN"), pgDone("INSERT 0 1"), pgDone("PREPARE TRANSACTION"), pgError(), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed INSERT" {
		t.Fatalf("%q", got)
	}

	// PREPARE TRANSACTION in a failed block is answered ROLLBACK: the tag decides.
	w = pgReadyWire(t)
	w.client(pgQuery("INSERT INTO a VALUES (1); PREPARE TRANSACTION 'z'"))
	w.server(pgDone("INSERT 0 1"), pgDone("ROLLBACK"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "rolled_back INSERT" {
		t.Fatalf("%q", got)
	}
}

// H6: the server's copy of a name changes only when it says so.
func TestPostgresRefusedParseChangesNothing(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("s", "DELETE FROM a"), pgSync())
	w.server(frame('1'), pgReady('I'))
	w.client(pgParse("s", "SELECT 1"), pgSync())
	w.server(pgError(), pgReady('I'))
	w.client(pgBind("", "s"), pgExecute(""), pgSync())
	w.server(frame('2'), pgDone("DELETE 1"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed DELETE" {
		t.Fatalf("%q", got)
	}
	w.healthy()
}

func TestPostgresPipelinedRefusalSkipsToSync(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("s", "DELETE FROM a"), pgSync())
	w.server(frame('1'), pgReady('I'))
	// All one write: the Parse is refused, and the rest is skipped unanswered.
	w.client(pgParse("s", "SELECT 1"), pgBind("", "s"), pgExecute(""), pgClose('S', "s"), pgSync())
	w.server(pgError(), pgReady('I'))
	w.client(pgBind("", "s"), pgExecute(""), pgSync())
	w.server(frame('2'), pgDone("DELETE 1"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed DELETE" {
		t.Fatalf("%q", got)
	}
	w.healthy()
}

// The error can overtake the proxy: the rest of the pipeline reaches the queue
// after the server has already refused the head of it.
func TestPostgresErrorOvertakesThePipeline(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "SELECT 1/0"), pgBind("", ""), pgExecute(""))
	w.server(frame('1'), frame('2'), pgError())
	w.client(pgParse("", "DELETE FROM a"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(pgReady('I'))
	w.healthy()
	w.client(pgQuery("SELECT 1"))
	w.server(pgDone("SELECT 1"), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 0 {
		t.Fatalf("the skipped DELETE never ran: %q", got)
	}
}

func TestPostgresPipelinedParseBindExecute(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "DELETE FROM a"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("DELETE 1"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed DELETE" {
		t.Fatalf("%q", got)
	}
}

func TestPostgresConfirmationWithNothingWaiting(t *testing.T) {
	for _, typ := range []byte{'1', '2', '3'} {
		w := pgReadyWire(t)
		w.server(frame(typ))
		if len(w.cap.faultList()) == 0 {
			t.Errorf("%q with nothing waiting must fault", typ)
		}
		// The wrong confirmation for what is waiting must not apply it.
		w = pgReadyWire(t)
		w.client(pgExecute("p"), pgSync())
		w.server(frame(typ))
		if f := w.cap.faultList(); len(f) != 1 || !strings.Contains(f[0], "nothing waiting") {
			t.Errorf("%q ahead of an Execute: %q", typ, f)
		}
	}
}

func TestPostgresParameterStatusWithoutTerminator(t *testing.T) {
	for _, body := range [][]byte{[]byte("name"), []byte("name\x00value")} {
		w := pgReadyWire(t)
		w.server(frame('S', body))
		if f := w.cap.faultList(); len(f) != 1 || !strings.Contains(f[0], "ParameterStatus") {
			t.Errorf("%q: %q", body, f)
		}
	}
}

// The connection drops before the server answers: what was pipelined still counts.
func TestPostgresDropKeepsUnconfirmedExecute(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "DELETE FROM a"), pgBind("", ""), pgExecute(""), pgSync())
	w.s.finish()
	e := w.first()
	if e.Outcome != witness.OutcomeUnknown || len(e.Tables) != 1 || e.Tables[0] != "a" {
		t.Fatalf("%+v", e)
	}
}

// The fixture's sql_prepare_rebind: PREPARE and DEALLOCATE share Parse's names.
func TestPostgresSQLPrepareRebindsTheName(t *testing.T) {
	for _, drop := range []string{"DEALLOCATE s", "DEALLOCATE PREPARE s", "DEALLOCATE ALL", "DISCARD ALL"} {
		w := pgReadyWire(t)
		w.client(pgParse("s", "SELECT 1"), pgSync())
		w.server(frame('1'), pgReady('I'))
		w.client(pgQuery(drop))
		w.server(pgDone(strings.Fields(drop)[0]), pgReady('I'))
		// A SELECT's tag, so nothing but the name can give it away.
		w.client(pgQuery("PREPARE s AS WITH d AS (DELETE FROM a RETURNING 1) SELECT 1"))
		w.server(pgDone("PREPARE"), pgReady('I'))
		w.client(pgBind("", "s"), pgExecute(""), pgSync())
		w.server(frame('2'), pgDone("SELECT 1"), pgReady('I'))
		found := false
		for _, e := range w.cap.snapshot() {
			found = found || (e.Opaque && e.Outcome == witness.OutcomeCommitted)
		}
		if !found {
			t.Errorf("%s: %+v", drop, w.cap.snapshot())
		}
	}
}

func parameterStatus(k, v string) []byte { return frame('S', cstr(k), cstr(v)) }

// H7: the server's report outranks the text, however the setting changed.
func TestPostgresParameterStatusTaints(t *testing.T) {
	for _, tc := range []struct {
		k, v  string
		taint bool
	}{
		{"standard_conforming_strings", "off", true},
		{"standard_conforming_strings", "on", false},
		{"client_encoding", "SJIS", true},
		{"client_encoding", "BIG5", true},
		{"client_encoding", "GBK", true},
		{"client_encoding", "UTF8", false},
		{"client_encoding", "LATIN1", false},
		{"search_path", `"$user", public`, false},
		{"search_path", "app, pg_catalog", true},
		{"TimeZone", "off", false},
	} {
		w := pgReadyWire(t)
		w.server(parameterStatus(tc.k, tc.v))
		w.client(pgQuery("SELECT 1"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		if got := w.first().Opaque; got != tc.taint {
			t.Errorf("%s=%s: opaque %v", tc.k, tc.v, got)
		}
	}
}

func TestPostgresTaintIsForGood(t *testing.T) {
	w := pgReadyWire(t)
	w.server(parameterStatus("standard_conforming_strings", "off"))
	w.server(parameterStatus("standard_conforming_strings", "on"))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('I'))
	if e := w.first(); !e.Opaque || e.Outcome != witness.OutcomeCommitted {
		t.Fatalf("%+v", e)
	}
}

// A statement pipelined behind the SET is answered before ParameterStatus comes.
func TestPostgresTaintReachesPipelinedStatement(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "SET standard_conforming_strings = off"), pgBind("", ""), pgExecute(""),
		pgParse("", "SELECT 1"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("SET"), frame('1'), frame('2'), pgDone("SELECT 1"),
		parameterStatus("standard_conforming_strings", "off"), pgReady('I'))
	for _, e := range w.cap.snapshot() {
		if !e.Opaque {
			t.Fatalf("%+v", e)
		}
	}
	if len(w.cap.snapshot()) != 2 {
		t.Fatalf("%+v", w.cap.snapshot())
	}
}

// A suspended portal of a read, on a session that can't be read.
func TestPostgresTaintReachesSuspendedPortal(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "SELECT 1"), pgBind("", ""), pgSync())
	w.server(frame('1'), frame('2'), pgReady('I'))
	w.server(parameterStatus("standard_conforming_strings", "off"))
	w.client(pgExecute(""), pgSync())
	w.server(frame('s'), pgReady('I'))
	if e := w.first(); !e.Opaque || e.Outcome != witness.OutcomeCommitted {
		t.Fatalf("%+v", e)
	}
}

func TestPostgresTaintFromText(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("SET search_path = app, pg_catalog"))
	w.server(pgDone("SET"), pgReady('I'))
	w.client(pgQuery("SELECT lower('x')"))
	w.server(pgDone("SELECT 1"), pgReady('I'))
	for _, e := range w.cap.snapshot() {
		if !e.Opaque {
			t.Fatalf("%+v", e)
		}
	}
}

func TestPostgresStartupSearchPath(t *testing.T) {
	for _, tc := range []struct {
		params string
		taint  bool
	}{
		{"user\x00u\x00search_path\x00app,pg_catalog\x00\x00", true},
		{"options\x00-csearch_path=app,pg_catalog\x00\x00", true},
		{"user\x00u\x00search_path\x00app\x00\x00", false},
		{"user\x00u\x00options\x00-cstatement_timeout=5\x00\x00", false},
		{"user\x00u\x00\x00", false},
	} {
		w := newPG(t)
		w.client(pgStartup(codeV3, []byte(tc.params)...))
		w.server(frame('R', []byte{0, 0, 0, 0}), pgReady('I'))
		if !strings.Contains(w.up.String(), tc.params) {
			t.Fatalf("the startup packet must reach the server: %q", w.up.String())
		}
		w.client(pgQuery("SELECT 1"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		if got := w.first().Opaque; got != tc.taint {
			t.Errorf("%q: opaque %v", tc.params, got)
		}
	}
}

// An answer that is not what the text says, on a statement read as harmless.
func TestPostgresTagMustFitARead(t *testing.T) {
	for _, tc := range []struct{ sql, tag string }{
		{"SELECT 1", "CALL"},
		{"SELECT 1", "CREATE TABLE"},
		{"BEGIN", "DO"},
		{"SHOW x", "DROP TABLE"},
	} {
		w := pgReadyWire(t)
		w.client(pgQuery(tc.sql))
		w.server(pgDone(tc.tag), pgReady('I'))
		if e := w.first(); !e.Opaque || e.Outcome != witness.OutcomeCommitted {
			t.Errorf("%q answered %q: %+v", tc.sql, tc.tag, e)
		}
	}
}

// M1.
func TestPostgresFailedRoutineOutsideATransaction(t *testing.T) {
	for _, sql := range []string{"CALL p()", "DO $$ BEGIN COMMIT; RAISE EXCEPTION 'x'; END $$"} {
		w := pgReadyWire(t)
		w.client(pgQuery(sql))
		w.server(pgError(), pgReady('I'))
		expectUnknown(t, w, strings.Fields(sql)[0])
	}
}

func TestPostgresFailedRoutineInsideATransactionFailed(t *testing.T) {
	// A routine called inside a transaction block cannot commit.
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("CALL p()"))
	w.server(pgError(), pgReady('E'))
	w.client(pgQuery("ROLLBACK"))
	w.server(pgDone("ROLLBACK"), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "failed CALL" {
		t.Fatalf("%q", got)
	}

	// The block ended earlier in the pipeline, with no ReadyForQuery to say so.
	w = pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgParse("", "COMMIT"), pgBind("", ""), pgExecute(""), pgParse("", "CALL p()"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("COMMIT"), frame('1'), frame('2'), pgError(), pgReady('I'))
	expectUnknown(t, w, "CALL")
}

func TestPostgresFailedFunctionIsFailed(t *testing.T) {
	// A function runs inside its statement, and goes with it.
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT write_it()"))
	w.server(pgError(), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "failed SELECT" {
		t.Fatalf("%q", got)
	}
}

func TestPostgresRolledBackRoutineOutsideATransaction(t *testing.T) {
	// The fixture's pipeline_call_commit_then_error.
	w := pgReadyWire(t)
	w.client(pgParse("", "CALL p()"), pgBind("", ""), pgExecute(""), pgParse("", "SELECT 1/0"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("CALL"), frame('1'), frame('2'), pgError(), pgReady('I'))
	expectUnknown(t, w, "CALL")

	// In a block it cannot commit, and the rollback is the whole story.
	w = pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("CALL p()"))
	w.server(pgDone("CALL"), pgReady('T'))
	w.client(pgQuery("ROLLBACK"))
	w.server(pgDone("ROLLBACK"), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "rolled_back CALL" {
		t.Fatalf("%q", got)
	}
}

func TestPostgresMoreResultsThanStatementsMayCommit(t *testing.T) {
	// Misread text: the extra result failed, and it could have been a routine.
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT 1"))
	w.server(pgDone("SELECT 1"), pgError(), pgReady('I'))
	if len(w.cap.faultList()) == 0 {
		t.Fatalf("%+v", w.cap.snapshot())
	}
}
