//subpoena:impl_derived
//subpoena:pure_logic

// MySQL protocol settings, session taint, and transaction outcomes.
package dbproxy

import (
	"testing"
)

func myStatus(status uint16) []byte { return myOK(1, 0, status, 0) }

// H7's twin: the server's flag says backslash no longer escapes.
func TestMySQLNoBackslashEscapesTaints(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT 1"))
	w.server(myOK(1, 0, stAutocommit|myStatusNoBackslash, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|myStatusNoBackslash, 0))
	got := w.cap.snapshot()
	if len(got) != 2 || !got[1].Opaque {
		t.Fatalf("%+v", got)
	}
}

// MySQL lexes the second statement after running the first.
func TestMySQLTaintReachesLaterStatementInTheText(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SET sql_mode = 'ANSI_QUOTES'; SELECT 1"))
	w.server(myOK(1, 0, stAutocommit|myStatusMoreResults, 0), myOK(2, 0, stAutocommit, 0))
	for _, e := range w.cap.snapshot() {
		if !e.Opaque {
			t.Fatalf("%+v", e)
		}
	}
}

func TestMySQLPreparedSetTaints(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("SET sql_mode = 'ANSI_QUOTES'"))
	w.server(myPrepareOK(1, 5, 0, 0))
	w.client(myQuery("SELECT 1"))
	w.server(myStatus(stAutocommit))
	if e := w.first(); !e.Opaque {
		t.Fatalf("%+v", e)
	}
}

func TestMySQLHandshakeCharsetTaints(t *testing.T) {
	for _, tc := range []struct {
		collation byte
		taint     bool
	}{{28, true}, {1, true}, {13, true}, {95, true}, {248, true}, {45, false}, {8, false}} {
		w := newMy(t)
		w.server(myGreeting(capProtocol41))
		resp := append(append(le32(capProtocol41), le32(0)...), tc.collation)
		w.client(packet(1, resp))
		w.server(myOK(2, 0, stAutocommit, 0))
		w.client(myQuery("SELECT 1"))
		w.server(myStatus(stAutocommit))
		if got := w.first().Opaque; got != tc.taint {
			t.Errorf("collation %d: opaque %v", tc.collation, got)
		}
	}
}

func TestMySQLChangeUserTaints(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(packet(0, []byte{0x11}, []byte("u\x00")))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.client(myQuery("SELECT 1"))
	w.server(myStatus(stAutocommit))
	if e := w.first(); !e.Opaque {
		t.Fatalf("%+v", e)
	}
}

// M1's twin: a procedure's work stays when it fails, and ERR has no status.
func TestMySQLFailedRoutine(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("CALL p()"))
	w.server(myErr(1))
	expectUnknown(t, w, "CALL")

	// Inside a transaction too: a procedure may COMMIT.
	w = myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("CALL p()"))
	w.server(myErr(1))
	expectUnknown(t, w, "CALL")
	if got := w.outcomes(); len(got) < 1 || got[0] != "committed INSERT" {
		t.Fatalf("the procedure may have committed what came before: %q", got)
	}
}

func TestMySQLRolledBackRoutine(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("CALL p()"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 0))
	expectUnknown(t, w, "CALL")
}

func TestMySQLFailedFunctionIsFailed(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT write_it()"))
	w.server(myErr(1))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "failed SELECT" {
		t.Fatalf("%q", got)
	}
}

// A statement that commits implicitly did so before it failed.
func TestMySQLFailedDDLCommitsWhatCameBefore(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("DROP TABLE no_such"))
	w.server(myErr(1))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 0))
	if got := w.outcomes(); len(got) < 1 || got[0] != "committed INSERT" {
		t.Fatalf("%q", got)
	}
}
