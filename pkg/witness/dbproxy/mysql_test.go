//subpoena:spec_derived
//subpoena:pure_logic

// From the MySQL client/server protocol documentation (packets, capability
// flags, OK/ERR/EOF, COM_QUERY, COM_STMT_*, status flags) and the round 2 brief.
// The packets here are built from the documented formats; recorded_test.go
// replays bytes from a real server.
package dbproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

const (
	capLongPassword = 0x1
	capCompress     = 0x20
	capProtocol41   = 0x200
	capSSL          = 0x800
	capDeprecateEOF = 0x01000000
	capQueryAttrs   = 0x08000000
	capZstd         = 0x04000000
	stAutocommit    = 0x0002
	stInTrans       = 0x0001
	stMoreResults   = 0x0008
	stCursorExists  = 0x0040
)

func packet(seq byte, payload ...[]byte) []byte {
	b := bytes.Join(payload, nil)
	out := []byte{byte(len(b)), byte(len(b) >> 8), byte(len(b) >> 16), seq}
	return append(out, b...)
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// myGreeting is a v10 handshake offering caps.
func myGreeting(caps uint32) []byte {
	return packet(0, []byte{10}, cstr("8.4.0"), le32(7), []byte("abcdefgh"), []byte{0},
		le16(uint16(caps)), []byte{255}, le16(stAutocommit), le16(uint16(caps>>16)),
		[]byte{21}, make([]byte, 10), []byte("ijklmnopqrst"), []byte{0}, cstr("caching_sha2_password"))
}

// greetingCaps reads the capability flags out of a forwarded greeting.
func greetingCaps(t *testing.T, b []byte) uint32 {
	t.Helper()
	p := b[4:]
	i := bytes.IndexByte(p[1:], 0) + 2 + 4 + 8 + 1
	return uint32(binary.LittleEndian.Uint16(p[i:])) | uint32(binary.LittleEndian.Uint16(p[i+5:]))<<16
}

// myResponse is a HandshakeResponse41.
func myResponse(caps uint32) []byte {
	return packet(1, le32(caps), le32(1<<24), []byte{255}, make([]byte, 23), cstr("app"), []byte{0}, cstr("caching_sha2_password"))
}

func myOK(seq byte, affected byte, status, warnings uint16) []byte {
	return packet(seq, []byte{0, affected, 0}, le16(status), le16(warnings))
}

func myEOF(seq byte, status uint16) []byte {
	return packet(seq, []byte{0xfe}, le16(0), le16(status))
}

func myErr(seq byte) []byte {
	return packet(seq, []byte{0xff}, le16(1064), []byte("#42000"), []byte("bad"))
}

func myQuery(sql string) []byte { return packet(0, []byte{0x03}, []byte(sql)) }

func myPrepare(sql string) []byte { return packet(0, []byte{0x16}, []byte(sql)) }

func myExecute(id uint32) []byte {
	return packet(0, []byte{0x17}, le32(id), []byte{0}, le32(1))
}

func myPrepareOK(seq byte, id uint32, cols, params uint16) []byte {
	return packet(seq, []byte{0}, le32(id), le16(cols), le16(params), []byte{0}, le16(0))
}

func myCol(seq byte) []byte {
	return packet(seq, []byte("\x03def\x00\x00\x00\x01a\x00\x0c?\x00\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00"))
}

func myRow(seq byte) []byte { return packet(seq, []byte{1, '1'}) }

func newMy(t *testing.T) *wire {
	c := newCapture()
	return &wire{t: t, cap: c, s: newMySQLSession(c, 1)}
}

// myReadyWire is a session past authentication, with caps negotiated.
func myReadyWire(t *testing.T, caps uint32) *wire {
	w := newMy(t)
	w.server(myGreeting(caps | capProtocol41))
	w.client(myResponse(caps | capProtocol41))
	w.server(myOK(2, 0, stAutocommit, 0))
	w.up.Reset()
	w.back.Reset()
	return w
}

func TestMySQLAutocommitWriteCommits(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.want() // sent is not committed
	w.server(myOK(1, 1, stAutocommit, 0))
	w.want("committed INSERT")
	e := w.cap.snapshot()[0]
	if e.Rows != 1 || !slices.Equal(e.Tables, []string{"users"}) {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

func TestMySQLExplicitTransaction(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("START TRANSACTION"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.want()
	w.client(myQuery("COMMIT"))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.want("committed INSERT")
	w.healthy()
}

func TestMySQLRollbackIsNotAnEffect(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("DELETE FROM users"))
	w.server(myOK(1, 3, stAutocommit|stInTrans, 0))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.want("rolled_back DELETE")
	w.healthy()
}

// A non-transactional table keeps its rows through ROLLBACK, and the server says
// so with a warning.
func TestMySQLRollbackWithWarningKeepsWrites(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO myisam_table VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 1))
	w.want("committed INSERT")
}

func TestMySQLRollbackToWithWarningKeepsWrites(t *testing.T) {
	w := myReadyWire(t, 0)
	for _, s := range []struct {
		sql string
		n   byte
	}{{"BEGIN", 0}, {"SAVEPOINT s", 0}, {"INSERT INTO m VALUES (1)", 1}} {
		w.client(myQuery(s.sql))
		w.server(myOK(1, s.n, stAutocommit|stInTrans, 0))
	}
	w.client(myQuery("ROLLBACK TO s"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 1))
	w.client(myQuery("COMMIT"))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.want("committed INSERT")
}

func TestMySQLFailedStatementIsNotAnEffect(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.server(myErr(1))
	w.want("failed INSERT")
	w.healthy()
}

// autocommit=0: a write leaves a transaction open with no BEGIN.
func TestMySQLAutocommitOff(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SET autocommit = 0"))
	w.server(myOK(1, 0, 0, 0))
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.server(myOK(1, 1, stInTrans, 0))
	w.want()
	w.client(myQuery("COMMIT"))
	w.server(myOK(1, 0, 0, 0))
	w.want("committed INSERT")
	w.healthy()
}

// DDL commits implicitly, and the status flag shows it with no COMMIT said.
func TestMySQLImplicitCommit(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("CREATE TABLE x (a int)"))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.want("committed INSERT", "committed CREATE")
	w.healthy()
}

// BEGIN inside a transaction commits it, though the flag stays set.
func TestMySQLBeginCommitsOpenTransaction(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.want("committed INSERT")
	w.healthy()
}

func TestMySQLCommitAndChain(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO users VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("COMMIT AND CHAIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.want("committed INSERT")
}

func TestMySQLSavepoints(t *testing.T) {
	w := myReadyWire(t, 0)
	for _, s := range []struct {
		sql string
		n   byte
	}{
		{"BEGIN", 0}, {"INSERT INTO a VALUES (1)", 1}, {"SAVEPOINT s", 0}, {"INSERT INTO b VALUES (1)", 1},
		{"ROLLBACK TO SAVEPOINT s", 0}, {"SAVEPOINT t", 0}, {"RELEASE SAVEPOINT t", 0}, {"INSERT INTO c VALUES (1)", 1},
	} {
		w.client(myQuery(s.sql))
		w.server(myOK(1, s.n, stAutocommit|stInTrans, 0))
	}
	w.want("rolled_back INSERT")
	w.client(myQuery("COMMIT"))
	w.server(myOK(1, 0, stAutocommit, 0))
	var got []string
	for _, e := range w.cap.committed() {
		got = append(got, e.Tables[0])
	}
	if !slices.Equal(got, []string{"a", "c"}) {
		t.Fatalf("committed %q", got)
	}
	w.healthy()
}

func TestMySQLResultSet(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT a FROM t"))
	w.server(packet(1, []byte{1}), myCol(2), myEOF(3, stAutocommit), myRow(4), myEOF(5, stAutocommit))
	w.client(myQuery("INSERT INTO t VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit, 0))
	w.want("committed INSERT")
	if e := w.cap.snapshot()[0]; e.Outcome != witness.OutcomeRead {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

// With CLIENT_DEPRECATE_EOF no EOF follows the columns, and an OK with a 0xFE
// header ends the rows.
func TestMySQLResultSetDeprecateEOF(t *testing.T) {
	w := myReadyWire(t, capDeprecateEOF)
	w.client(myQuery("SELECT a FROM t"))
	w.server(packet(1, []byte{1}), myCol(2), myRow(3), packet(4, []byte{0xfe, 0, 0}, le16(stAutocommit), le16(0)))
	w.client(myQuery("INSERT INTO t VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit, 0))
	w.want("committed INSERT")
	w.healthy()
}

func TestMySQLErrorInsideRows(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT a FROM t"))
	w.server(packet(1, []byte{1}), myCol(2), myEOF(3, stAutocommit), myRow(4), myErr(5))
	w.client(myQuery("INSERT INTO t VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit, 0))
	w.want("committed INSERT")
	w.healthy()
}

func TestMySQLMultiStatement(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("INSERT INTO a VALUES (1); DELETE FROM b; SELECT 1"))
	w.server(myOK(1, 1, stAutocommit|stMoreResults, 0), myOK(2, 2, stAutocommit|stMoreResults, 0),
		packet(3, []byte{1}), myCol(4), myEOF(5, stAutocommit), myRow(6), myEOF(7, stAutocommit))
	w.want("committed INSERT", "committed DELETE")
	w.healthy()
}

func TestMySQLMoreResultsThanStatements(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT 1"))
	w.server(myOK(1, 0, stAutocommit|stMoreResults, 0), myOK(2, 3, stAutocommit, 0))
	got := w.cap.committed()
	if len(got) != 1 || !got[0].Opaque {
		t.Fatalf("%+v", got)
	}
	w.healthy()
}

func TestMySQLReadThatChangedRowsIsOpaque(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT 1"))
	w.server(myOK(1, 2, stAutocommit, 0))
	got := w.cap.committed()
	if len(got) != 1 || !got[0].Opaque || !got[0].Touches("anything") {
		t.Fatalf("%+v", got)
	}
}

func TestMySQLZeroRows(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("DELETE FROM users WHERE owner = 9"))
	w.server(myOK(1, 0, stAutocommit, 0))
	e := w.cap.committed()[0]
	if e.Rows != 0 || e.Effect() {
		t.Fatalf("%+v", e)
	}
}

func TestMySQLTruncateCountsAsUnknown(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("TRUNCATE TABLE users"))
	w.server(myOK(1, 0, stAutocommit, 0))
	if e := w.cap.committed()[0]; !e.Effect() {
		t.Fatalf("%+v", e)
	}
}

func TestMySQLOpaqueCounts(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("CALL do_things()"))
	w.server(myOK(1, 0, stAutocommit, 0))
	if e := w.cap.committed()[0]; !e.Opaque || !e.Effect() {
		t.Fatalf("%+v", e)
	}
}

func TestMySQLPreparedStatement(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("INSERT INTO users VALUES (?)"))
	w.server(myPrepareOK(1, 7, 0, 1), myCol(2), myEOF(3, stAutocommit))
	w.want() // prepared is not run
	for i := 0; i < 2; i++ {
		w.client(myExecute(7))
		w.server(myOK(1, 1, stAutocommit, 0))
	}
	w.want("committed INSERT", "committed INSERT")
	if e := w.cap.committed()[0]; e.Tables[0] != "users" || e.Rows != 1 {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

func TestMySQLPreparedInTransaction(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("DELETE FROM users"))
	w.server(myPrepareOK(1, 8, 0, 0))
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myExecute(8))
	w.server(myOK(1, 4, stAutocommit|stInTrans, 0))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.want("rolled_back DELETE")
	w.healthy()
}

func TestMySQLPreparedColumnsAndParams(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps uint32
		tail [][]byte
	}{
		{"with eof", 0, [][]byte{myCol(2), myEOF(3, 0), myCol(4), myEOF(5, 0)}},
		{"deprecate eof", capDeprecateEOF, [][]byte{myCol(2), myCol(3)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := myReadyWire(t, tc.caps)
			w.client(myPrepare("SELECT a FROM t WHERE b = ?"))
			w.server(append([][]byte{myPrepareOK(1, 9, 1, 1)}, tc.tail...)...)
			w.client(myExecute(9))
			w.server(packet(1, []byte{1}), myCol(2))
			if tc.caps == 0 {
				w.server(myEOF(3, stAutocommit))
			}
			w.server(packet(4, []byte{0, 0, 1}))
			if tc.caps == 0 {
				w.server(myEOF(5, stAutocommit))
			} else {
				w.server(packet(5, []byte{0xfe, 0, 0}, le16(stAutocommit), le16(0)))
			}
			w.healthy()
		})
	}
}

func TestMySQLCursorFetch(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("SELECT a FROM t"))
	w.server(myPrepareOK(1, 3, 1, 0), myCol(2), myEOF(3, 0))
	w.client(packet(0, []byte{0x17}, le32(3), []byte{1}, le32(1)))
	w.server(packet(1, []byte{1}), myCol(2), myEOF(3, stAutocommit|stCursorExists))
	w.client(packet(0, []byte{0x1c}, le32(3), le32(1)))
	w.server(packet(1, []byte{0, 0, 1}), myEOF(2, stAutocommit))
	w.healthy()
	if w.s.inFlight() {
		t.Fatal("a reply is still owed")
	}
}

func TestMySQLUnknownStatementIDIsOpaque(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myExecute(99))
	w.server(myOK(1, 0, stAutocommit, 0))
	got := w.cap.committed()
	if len(got) != 1 || !got[0].Opaque {
		t.Fatalf("%+v", got)
	}
}

func TestMySQLStatementClose(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("SELECT 1"))
	w.server(myPrepareOK(1, 5, 1, 0), myCol(2), myEOF(3, 0))
	w.client(packet(0, []byte{0x19}, le32(5))) // no reply
	w.client(myExecute(5))
	w.server(myErr(1))
	e := w.cap.snapshot()
	if len(e) != 1 || !e[0].Opaque {
		t.Fatalf("a closed id must not resolve: %+v", e)
	}
	w.healthy()
}

func TestMySQLLongDataHasNoReply(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(packet(0, []byte{0x18}, le32(5), le16(0), []byte("x")))
	if w.s.inFlight() {
		t.Fatal("COM_STMT_SEND_LONG_DATA has no reply")
	}
}

func TestMySQLUtilityCommands(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(packet(0, []byte{0x0e})) // ping
	w.server(myOK(1, 0, stAutocommit, 0))
	w.client(packet(0, []byte{0x02}, []byte("db"))) // init db
	w.server(myOK(1, 0, stAutocommit, 0))
	w.client(packet(0, []byte{0x09})) // statistics: a bare string
	w.server(packet(1, []byte("Uptime: 1")))
	w.client(packet(0, []byte{0x1b}, le16(0))) // set option
	w.server(myEOF(1, stAutocommit))
	w.client(packet(0, []byte{0x1a}, le32(1))) // stmt reset
	w.server(myOK(1, 0, stAutocommit, 0))
	w.client(packet(0, []byte{0x04}, cstr("t"))) // field list
	w.server(myCol(1), myEOF(2, stAutocommit))
	w.healthy()
	if w.s.inFlight() {
		t.Fatal("a reply is still owed")
	}
}

func TestMySQLLocalInfile(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("LOAD DATA LOCAL INFILE 'x' INTO TABLE t"))
	w.server(packet(1, []byte{0xfb}, []byte("x")))
	w.client(packet(2, []byte("1\n")), packet(3))
	w.server(myOK(4, 1, stAutocommit, 0))
	w.want("committed LOAD")
	w.healthy()
}

func TestMySQLResetConnectionRollsBack(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("SELECT 1"))
	w.server(myPrepareOK(1, 5, 0, 0))
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(packet(0, []byte{0x1f}))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.want("rolled_back INSERT")
	w.client(myExecute(5))
	w.server(myOK(1, 0, stAutocommit, 0))
	if got := w.cap.committed(); len(got) != 1 || !got[0].Opaque {
		t.Fatalf("a reset must forget statements: %+v", got)
	}
	w.s.finish()
	w.healthy()
}

func TestMySQLChangeUserRollsBack(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(packet(0, []byte{0x11}, cstr("other")))
	w.server(packet(1, []byte{0xfe}, cstr("mysql_native_password"), []byte("abc")))
	w.client(packet(2, []byte("reply")))
	w.server(myOK(3, 0, stAutocommit, 0))
	w.want("rolled_back INSERT")
	w.client(myQuery("SELECT 1"))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.s.finish()
	w.healthy()
}

func TestMySQLBigCommandSpansPackets(t *testing.T) {
	w := myReadyWire(t, 0)
	sql := "INSERT INTO big VALUES ('" + string(bytes.Repeat([]byte("x"), 0xffffff)) + "')"
	whole := append([]byte{0x03}, sql...)
	first := append([]byte{0xff, 0xff, 0xff, 0}, whole[:0xffffff]...)
	second := packet(1, whole[0xffffff:])
	w.client(first, second)
	w.server(myOK(1, 1, stAutocommit, 0))
	got := w.cap.committed()
	if len(got) != 1 || got[0].Tables[0] != "big" {
		t.Fatalf("%d events", len(got))
	}
	w.healthy()
}

func TestMySQLBigRowSpansPackets(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT big"))
	w.server(packet(1, []byte{1}), myCol(2), myEOF(3, stAutocommit))
	// The continuation starts with bytes that would read as a terminator.
	body := make([]byte, 0xffffff)
	w.server(append([]byte{0xff, 0xff, 0xff, 4}, body...), packet(5, []byte{0xfe, 0, 0, 0, 0}))
	if !w.s.inFlight() {
		t.Fatal("a continuation packet must not end the rows")
	}
	w.server(myEOF(6, stAutocommit))
	w.healthy()
	if w.s.inFlight() {
		t.Fatal("a reply is still owed")
	}
}

// ---- TLS ----

func TestMySQLClearsTLSAndCompressionInTheGreeting(t *testing.T) {
	w := newMy(t)
	offered := uint32(capProtocol41 | capSSL | capCompress | capZstd | capQueryAttrs | capDeprecateEOF | capLongPassword)
	w.server(myGreeting(offered))
	got := greetingCaps(t, w.back.Bytes())
	if got != capProtocol41|capDeprecateEOF|capLongPassword|capQueryAttrs {
		t.Fatalf("caps %#x", got)
	}
	if n := w.cap.coverage(); n.TLSRefused != 1 || n.Connections != 1 {
		t.Fatalf("%+v", n)
	}
}

func TestMySQLClientInsistsOnTLS(t *testing.T) {
	w := newMy(t)
	w.server(myGreeting(capProtocol41 | capSSL))
	w.s.finish() // ssl-mode=REQUIRED: read the greeting, and left
	w.faulted("TLS")
}

func TestMySQLClientSendsSSLRequestAnyway(t *testing.T) {
	w := newMy(t)
	w.server(myGreeting(capProtocol41 | capSSL))
	w.client(packet(1, le32(capProtocol41|capSSL), le32(1<<24), []byte{255}, make([]byte, 23)))
	w.faulted("TLS")
	if !errors.Is(w.err, errClose) {
		t.Fatalf("the connection must close: %v", w.err)
	}
	if w.up.Len() != 0 {
		t.Fatal("the request must not reach the server")
	}
}

func TestMySQLClientInsistsOnCompression(t *testing.T) {
	for _, c := range []uint32{capCompress, capZstd} {
		w := newMy(t)
		w.server(myGreeting(capProtocol41 | c))
		w.client(myResponse(capProtocol41 | c))
		w.faulted("unreadable")
		if !errors.Is(w.err, errBlind) {
			t.Fatalf("%v", w.err)
		}
	}
}

func TestMySQLFailedLoginIsClean(t *testing.T) {
	w := newMy(t)
	w.server(myGreeting(capProtocol41))
	w.client(myResponse(capProtocol41))
	w.server(myErr(2))
	w.s.finish()
	w.healthy()
}

func TestMySQLServerRefusesAtGreeting(t *testing.T) {
	w := newMy(t)
	w.server(packet(0, []byte{0xff}, le16(1040), []byte("Too many connections")))
	w.s.finish()
	w.healthy()
}

func TestMySQLAuthRoundTrips(t *testing.T) {
	w := newMy(t)
	w.server(myGreeting(capProtocol41))
	w.client(myResponse(capProtocol41))
	w.server(packet(2, []byte{0xfe}, cstr("caching_sha2_password"), []byte("salt")))
	w.client(packet(3, []byte("scramble")))
	w.server(packet(4, []byte{0x01, 0x04}))
	w.client(packet(5, []byte{0x02}))
	w.server(packet(6, []byte{0x01}, []byte("-----BEGIN PUBLIC KEY-----")))
	w.client(packet(7, []byte("encrypted")))
	w.server(myOK(8, 0, stAutocommit, 0))
	w.client(myQuery("INSERT INTO t VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit, 0))
	w.want("committed INSERT")
	w.healthy()
}

// ---- Inconclusive ----

func TestMySQLUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T) *wire
	}{
		{"old greeting", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(packet(0, []byte{9}, cstr("old")))
			return w
		}},
		{"short greeting", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(packet(0, []byte{10}, cstr("8.4")))
			return w
		}},
		{"no version terminator", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(packet(0, []byte{10, 'a'}))
			return w
		}},
		{"short response", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(myGreeting(capProtocol41))
			w.client(packet(1, []byte{1}))
			return w
		}},
		{"no protocol 41", func(t *testing.T) *wire {
			w := newMy(t)
			w.server(myGreeting(capProtocol41))
			w.client(myResponse(capLongPassword))
			return w
		}},
		{"unknown command", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0, []byte{0x7f}))
			return w
		}},
		{"empty command", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0))
			return w
		}},
		{"short execute", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0, []byte{0x17, 1}))
			return w
		}},
		{"short close", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(packet(0, []byte{0x19, 1}))
			return w
		}},
		{"reply with nothing asked", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.server(myOK(1, 1, stAutocommit, 0))
			return w
		}},
		{"empty reply", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1))
			return w
		}},
		{"short ok", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("INSERT INTO t VALUES (1)"))
			w.server(packet(1, []byte{0, 1}))
			return w
		}},
		{"short eof", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{1}), myCol(2), packet(3, []byte{0xfe, 0}))
			return w
		}},
		{"missing eof after columns", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{1}), myCol(2), myRow(3))
			return w
		}},
		{"bad column count", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myQuery("SELECT 1"))
			w.server(packet(1, []byte{0xfc, 1}))
			return w
		}},
		{"short prepare ok", func(t *testing.T) *wire {
			w := myReadyWire(t, 0)
			w.client(myPrepare("SELECT 1"))
			w.server(packet(1, []byte{0, 1, 2}))
			return w
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.setup(t)
			w.faulted("unreadable")
			if !errors.Is(w.err, errBlind) {
				t.Fatalf("the connection must go on unread: %v", w.err)
			}
		})
	}
}

// With query attributes negotiated COM_QUERY has a prefix, and real attribute
// values ahead of the SQL, which cannot be read as text.
func TestMySQLQueryAttributes(t *testing.T) {
	w := newMy(t)
	w.server(myGreeting(capProtocol41 | capQueryAttrs))
	w.client(myResponse(capProtocol41 | capQueryAttrs))
	w.server(myOK(2, 0, stAutocommit, 0))
	w.client(packet(0, []byte{0x03, 0, 1}, []byte("INSERT INTO a VALUES (1)")))
	w.server(myOK(1, 1, stAutocommit, 0))
	if got := w.cap.committed(); len(got) != 1 || got[0].Tables[0] != "a" {
		t.Fatalf("no attributes: %+v", got)
	}
	w.client(packet(0, []byte{0x03, 1, 1}, []byte("anything")))
	w.server(myOK(1, 0, stAutocommit, 0))
	got := w.cap.committed()
	if len(got) != 2 || !got[1].Opaque {
		t.Fatalf("attributes: %+v", got)
	}
}

func TestMySQLDroppedMidTransaction(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.s.finish()
	w.want("unknown INSERT")
	w.faulted("dropped")
}

func TestMySQLDroppedInFlight(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.s.finish()
	w.want("unknown INSERT")
	w.faulted("dropped")
}

func TestMySQLQuitRollsBackCleanly(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(packet(0, []byte{0x01}))
	w.s.finish()
	w.want("rolled_back INSERT")
	w.healthy()
}

func TestMySQLBlindConnectionIsUnknown(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(packet(0, []byte{0x7f}))
	w.s.finish()
	w.want("unknown INSERT")
}

func TestMySQLIdleCloseIsClean(t *testing.T) {
	w := myReadyWire(t, 0)
	w.s.finish()
	w.healthy()
}

// The server's idle-timeout notice comes with nothing asked.
func TestMySQLUnpromptedErrorIsNotDesync(t *testing.T) {
	w := myReadyWire(t, 0)
	w.server(myErr(1))
	w.healthy()
}
