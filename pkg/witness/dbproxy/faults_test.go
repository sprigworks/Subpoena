//subpoena:impl_derived
//subpoena:pure_logic

// The fail-closed guards one by one, each by the fault it raises. Written after
// the code, against subpoena-cross: where one guard's removal falls through to
// another's, only the text tells them apart.
package dbproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

func TestPostgresUnreadableFrames(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		setup      func(*wire)
	}{
		{"unknown client type", "client message type", func(w *wire) { w.client(frame('@', []byte{1})) }},
		{"client length below four", "has length", func(w *wire) { w.client([]byte{'Q', 0, 0, 0, 3, 0, 0, 0}) }},
		{"query without terminator", "Query without", func(w *wire) { w.client(frame('Q', []byte("SELECT 1"))) }},
		{"parse without terminator", "Parse without", func(w *wire) { w.client(frame('P', []byte("s"))) }},
		{"parse with no query", "Parse without", func(w *wire) { w.client(frame('P', cstr("s"))) }},
		{"bind without statement", "Bind without", func(w *wire) { w.client(frame('B', cstr("p"))) }},
		{"execute without terminator", "Execute without", func(w *wire) { w.client(frame('E', []byte("p"))) }},
		{"close too short", "Close too short", func(w *wire) { w.client(frame('C')) }},
		{"close without terminator", "Close without", func(w *wire) { w.client(frame('C', []byte("Sx"))) }},
		{"client frame too large", "client message", func(w *wire) {
			b := []byte{'Q', 0, 0, 0, 0}
			binary.BigEndian.PutUint32(b[1:], maxFrame+5)
			w.client(b)
		}},
		{"unknown server type", "server message type", func(w *wire) { w.server(frame('@', []byte{1})) }},
		{"server length below four", "has length", func(w *wire) { w.server([]byte{'Z', 0, 0, 0, 1, 0, 0}) }},
		{"server frame too large", "bytes", func(w *wire) {
			b := []byte{'C', 0, 0, 0, 0}
			binary.BigEndian.PutUint32(b[1:], maxFrame+5)
			w.server(b)
		}},
		{"ready without status", "ReadyForQuery status", func(w *wire) { w.server(frame('Z')) }},
		{"ready with bad status", "ReadyForQuery status", func(w *wire) { w.server(frame('Z', []byte{'X'})) }},
		{"complete without terminator", "CommandComplete without", func(w *wire) {
			w.client(pgQuery("SELECT 1"))
			w.server(frame('C', []byte("SELECT 1")))
		}},
		{"complete with nothing sent", "no command waiting", func(w *wire) { w.server(pgDone("DELETE 1")) }},
		{"suspended with nothing sent", "PortalSuspended", func(w *wire) { w.server(frame('s')) }},
		{"function result with nothing sent", "FunctionCallResponse", func(w *wire) { w.server(frame('V', []byte{0, 0, 0, 0})) }},
		{"ready with nothing sent", "ReadyForQuery with no command", func(w *wire) { w.server(pgReady('I')) }},
		{"ready before a reply", "before an Execute", func(w *wire) {
			w.client(pgParse("", "SELECT 1"), pgBind("", ""), pgExecute(""), pgSync())
			w.server(pgReady('I'))
		}},
		{"copy both", "CopyBoth", func(w *wire) {
			w.client(pgQuery("START_REPLICATION"))
			w.server(frame('W', []byte{0, 0, 0}))
		}},
		{"bad startup code", "startup code", func(w *wire) {
			x := newPG(t)
			x.client(pgStartup(12345))
			w.cap, w.err = x.cap, x.err
		}},
		{"bad startup length", "startup packet of length", func(w *wire) {
			x := newPG(t)
			x.client([]byte{0, 0, 0, 2, 0, 0, 0, 0})
			w.cap, w.err = x.cap, x.err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := pgReadyWire(t)
			tc.setup(w)
			w.faulted("unreadable")
			w.faulted(tc.want)
			if !errors.Is(w.err, errBlind) {
				t.Fatalf("the connection must go on unread: %v", w.err)
			}
		})
	}
}

func TestMySQLUnreadable(t *testing.T) {
	greeted := func(t *testing.T) *wire {
		w := newMy(t)
		w.server(myGreeting(capProtocol41))
		return w
	}
	for _, tc := range []struct {
		name, want string
		setup      func(*testing.T) *wire
	}{
		{"old greeting", "protocol version", func(t *testing.T) *wire {
			w := newMy(t)
			g := myGreeting(capProtocol41)
			g[4] = 9
			w.server(g)
			return w
		}},
		{"empty greeting", "protocol version", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(packet(0))
			return w
		}},
		{"short greeting", "a greeting of", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(packet(0, []byte{10}, cstr("8.4")))
			return w
		}},
		{"no version terminator", "a greeting of", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(packet(0, []byte{10, 'a'}))
			return w
		}},
		{"client before the greeting", "before the greeting", func(t *testing.T) *wire {
			w := newMy(t)
			w.client(myResponse(capProtocol41))
			return w
		}},
		{"short response", "a handshake response", func(t *testing.T) *wire {
			w := greeted(t)
			w.client(packet(1, []byte{1}))
			return w
		}},
		{"no protocol 41", "protocol 4.1", func(t *testing.T) *wire {
			w := greeted(t)
			w.client(myResponse(capLongPassword))
			return w
		}},
		{"unknown command", "command 0x7f", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0, []byte{0x7f}))
			return w
		}},
		{"empty command", "an empty command", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0))
			return w
		}},
		{"short execute", "COM_STMT_EXECUTE", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0, []byte{0x17, 1}))
			return w
		}},
		{"short close", "COM_STMT_CLOSE", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0, []byte{0x19, 1}))
			return w
		}},
		{"reply with nothing asked", "no command waiting", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.server(myOK(1, 1, stAutocommit, 0))
			return w
		}},
		{"empty reply", "an empty reply", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1))
			return w
		}},
		{"short ok", "an OK of", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("INSERT INTO t VALUES (1)"))
			w.server(packet(1, []byte{0, 1}))
			return w
		}},
		{"short end as the first packet", "an end packet", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{0xfe, 0}))
			return w
		}},
		{"short eof after columns", "an EOF of", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{1}), myCol(2), packet(3, []byte{0xfe, 0}))
			return w
		}},
		{"short end after rows", "an end packet", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{1}), myCol(2), myEOF(3, stAutocommit), packet(4, []byte{0xfe, 0}))
			return w
		}},
		{"missing eof after columns", "no EOF", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{1}), myCol(2), myRow(3))
			return w
		}},
		{"bad column count", "a column count", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{0xfc, 1}))
			return w
		}},
		{"short prepare ok", "COM_STMT_PREPARE_OK", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myPrepare("SELECT 1"))
			w.server(packet(1, []byte{0, 1, 2}))
			return w
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.setup(t)
			w.faulted("unreadable")
			w.faulted(tc.want)
			if !errors.Is(w.err, errBlind) {
				t.Fatalf("the connection must go on unread: %v", w.err)
			}
		})
	}
}

func TestMySQLBlindConnectionStaysBlind(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(packet(0, []byte{0x7f}))
	if err := w.s.client(bufio.NewReader(bytes.NewReader(myQuery("DELETE FROM b"))), &w.up, &w.back); !errors.Is(err, errBlind) {
		t.Fatalf("client after blind: %v", err)
	}
	if err := w.s.server(bufio.NewReader(bytes.NewReader(myErr(1))), &w.back); !errors.Is(err, errBlind) {
		t.Fatalf("server after blind: %v", err)
	}
}

// A frame that breaks the parser is a fault, not a crash of the test binary.
func TestParserPanicIsUnreadable(t *testing.T) {
	w := pgReadyWire(t)
	w.s.(*pgSession).queue = []*pgItem{nil}
	w.server(pgDone("SELECT 1"))
	w.faulted("broke the parser")

	w = myReadyWire(t, 0)
	w.s.(*mySession).queue = []*myItem{nil}
	w.server(myOK(1, 0, stAutocommit, 0))
	w.faulted("broke the parser")
}

// ROLLBACK AND CHAIN leaves a transaction open, so only the warning keeps a
// non-transactional table's write.
func TestMySQLChainedRollbackWithWarningKeepsWrites(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO m VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("ROLLBACK AND CHAIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 1))
	w.want("committed INSERT")
}

// A command longer than the witness keeps: what follows the cut could be anything.
func TestMySQLCommandTooLongToRead(t *testing.T) {
	defer func(n int) { maxCommand = n }(maxCommand)
	maxCommand = 100
	head := "SELECT 1" + strings.Repeat(" ", 0xffffff)
	whole := append([]byte{0x03}, head...)
	tail := "; DELETE FROM users"
	big := func(w *wire, body []byte) {
		w.client(append([]byte{0xff, 0xff, 0xff, 0}, body[:0xffffff]...), packet(1, body[0xffffff:], []byte(tail)))
	}
	w := myReadyWire(t, 0)
	big(w, whole)
	w.server(myOK(1, 0, stAutocommit, 0))
	if e := w.firstCommitted(); !e.Opaque || !strings.Contains(e.Reason, "too long") {
		t.Fatalf("%+v", e)
	}

	w = myReadyWire(t, 0)
	prepare := append([]byte{0x16}, head...)
	big(w, prepare)
	w.server(myPrepareOK(1, 7, 0, 0))
	w.client(myExecute(7))
	w.server(myOK(1, 0, stAutocommit, 0))
	if e := w.firstCommitted(); !e.Opaque || !strings.Contains(e.Reason, "too long") {
		t.Fatalf("%+v", e)
	}
}

// Statements that fall through one parser guard to another.
func TestOpaqueReasons(t *testing.T) {
	for _, tc := range []struct {
		d         dialect
		sql, want string
	}{
		{dialectPostgres, "1 + 1", "keyword"},
		{dialectPostgres, "INSERT INTO", "no table"},
		{dialectPostgres, "INSERT", "no table"},
		{dialectPostgres, "DELETE x y", "one-table"},
		{dialectPostgres, "MERGE", "no table"},
		{dialectPostgres, "MERGE INTO", "no table"},
		{dialectPostgres, "DROP TABLE", "no table"},
		{dialectPostgres, "CREATE TABLE", "no table"},
		{dialectPostgres, "COPY t", "direction"},
		{dialectMySQL, "LOAD XML", "LOAD DATA"},
		{dialectMySQL, `SELECT "unterminated`, "tokenize"},
		{dialectMySQL, "/* unterminated", "tokenize"},
		{dialectMySQL, "/*! DELETE FROM users */", "tokenize"},
		{dialectPostgres, "SELECT 'unterminated", "tokenize"},
		{dialectPostgres, `SELECT "unterminated`, "tokenize"},
		{dialectPostgres, "SELECT $a$ unterminated", "tokenize"},
	} {
		got := parseSQL(tc.d, tc.sql)
		if len(got) != 1 || got[0].class != classOpaque || !strings.Contains(got[0].reason, tc.want) {
			t.Errorf("%q: %+v, want opaque for %q", tc.sql, got, tc.want)
		}
	}
}

// A write that failed on a blind connection is not a capture of nothing.
func TestFaultsFillCoverage(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("DELETE FROM users"))
	w.s.finish()
	cov := w.cap.coverage()
	if cov.Unknown != 1 || len(cov.Faults) != 1 {
		t.Fatalf("%+v", cov)
	}
	if e := w.first(); e.Outcome != witness.OutcomeUnknown {
		t.Fatalf("%+v", e)
	}
}
