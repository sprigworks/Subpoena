//subpoena:spec_derived
//subpoena:pure_logic

// From the PostgreSQL protocol chapter (message formats, "Multiple Statements in
// a Simple Query", pipelining, SSL session encryption) and the round 2 brief:
// report what was committed, not what was sent; what cannot be read is
// Inconclusive. The frames here are built from the documented formats;
// recorded_test.go replays bytes from real servers.
package dbproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

func frame(typ byte, body ...[]byte) []byte {
	b := bytes.Join(body, nil)
	out := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(b)+4))
	return append(out, b...)
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func pgQuery(sql string) []byte       { return frame('Q', cstr(sql)) }
func pgParse(name, sql string) []byte { return frame('P', cstr(name), cstr(sql), []byte{0, 0}) }
func pgBind(portal, name string) []byte {
	return frame('B', cstr(portal), cstr(name), []byte{0, 0, 0, 0, 0, 0})
}
func pgExecute(portal string) []byte     { return frame('E', cstr(portal), []byte{0, 0, 0, 0}) }
func pgClose(kind byte, n string) []byte { return frame('C', []byte{kind}, cstr(n)) }
func pgSync() []byte                     { return frame('S') }
func pgDone(tag string) []byte           { return frame('C', cstr(tag)) }
func pgReady(status byte) []byte         { return frame('Z', []byte{status}) }
func pgError() []byte                    { return frame('E', cstr("SERROR"), cstr("C42000"), []byte{0}) }
func pgFatal() []byte                    { return frame('E', cstr("SFATAL"), cstr("C57P01"), []byte{0}) }

// pgStartup is a startup packet with the given request code.
func pgStartup(code uint32, rest ...byte) []byte {
	out := make([]byte, 8, 8+len(rest))
	binary.BigEndian.PutUint32(out, uint32(8+len(rest)))
	binary.BigEndian.PutUint32(out[4:], code)
	return append(out, rest...)
}

const (
	codeSSL    = 80877103
	codeGSS    = 80877104
	codeCancel = 80877102
	codeV3     = 196608
)

type wire struct {
	t    *testing.T
	cap  *capture
	s    session
	up   bytes.Buffer // what reached the server
	back bytes.Buffer // what reached the client
	err  error        // the last step error that was not EOF
}

func newCapture() *capture {
	return &capture{engine: "test"}
}

func newPG(t *testing.T) *wire {
	c := newCapture()
	return &wire{t: t, cap: c, s: newPostgresSession(c, 1)}
}

// pgReadyWire is a session past startup and authentication.
func pgReadyWire(t *testing.T) *wire {
	w := newPG(t)
	w.client(pgStartup(codeV3, 0))
	w.server(frame('R', []byte{0, 0, 0, 0}), pgReady('I'))
	w.up.Reset()
	w.back.Reset()
	return w
}

func (w *wire) client(frames ...[]byte) {
	w.t.Helper()
	r := bufio.NewReader(bytes.NewReader(bytes.Join(frames, nil)))
	for {
		err := w.s.client(r, &w.up, &w.back)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			w.err = err
			io.Copy(&w.up, r)
			return
		}
	}
}

func (w *wire) server(frames ...[]byte) {
	w.t.Helper()
	r := bufio.NewReader(bytes.NewReader(bytes.Join(frames, nil)))
	for {
		err := w.s.server(r, &w.back)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			w.err = err
			io.Copy(&w.back, r)
			return
		}
	}
}

func (w *wire) outcomes() []string {
	var out []string
	for _, e := range w.cap.snapshot() {
		if e.Outcome == witness.OutcomeRead || (len(e.Tables) == 0 && !e.Opaque) {
			continue // the writes are what these tests are about
		}
		out = append(out, string(e.Outcome)+" "+e.Verb)
	}
	return out
}

// first is the first statement recorded; a test that needs one fails cleanly
// without it.
func (w *wire) first() witness.RowEvent {
	w.t.Helper()
	all := w.cap.snapshot()
	if len(all) == 0 {
		w.t.Fatal("nothing recorded")
	}
	return all[0]
}

func (w *wire) firstCommitted() witness.RowEvent {
	w.t.Helper()
	all := w.cap.committed()
	if len(all) == 0 {
		w.t.Fatal("nothing committed")
	}
	return all[0]
}

func (w *wire) want(outcomes ...string) {
	w.t.Helper()
	if got := w.outcomes(); !slices.Equal(got, outcomes) {
		w.t.Fatalf("outcomes %q, want %q", got, outcomes)
	}
}

func (w *wire) healthy() {
	w.t.Helper()
	if f := w.cap.faultList(); len(f) != 0 {
		w.t.Fatalf("faults: %q", f)
	}
}

func (w *wire) faulted(text string) {
	w.t.Helper()
	f := w.cap.faultList()
	if len(f) == 0 || !strings.Contains(strings.Join(f, "\n"), text) {
		w.t.Fatalf("want a fault containing %q, got %q", text, f)
	}
}

func TestPostgresAutocommitWriteCommits(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("INSERT INTO users VALUES (1)"))
	w.want() // sent is not committed
	w.server(pgDone("INSERT 0 1"))
	w.want() // done, but the server has not said the transaction ended
	w.server(pgReady('I'))
	w.want("committed INSERT")
	e := w.first()
	if e.Rows != 1 || !slices.Equal(e.Tables, []string{"users"}) || e.Conn != 1 || e.Attribution != witness.ByDestination {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

func TestPostgresExplicitTransaction(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO users VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.want() // inside a transaction: nothing yet
	w.client(pgQuery("COMMIT"))
	w.server(pgDone("COMMIT"), pgReady('I'))
	w.want("committed INSERT")
	w.healthy()
}

func TestPostgresRollbackIsNotAnEffect(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("DELETE FROM users"))
	w.server(pgDone("DELETE 4"), pgReady('T'))
	w.client(pgQuery("ROLLBACK"))
	w.server(pgDone("ROLLBACK"), pgReady('I'))
	w.want("rolled_back DELETE")
	w.healthy()
}

func TestPostgresFailedStatementIsNotAnEffect(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("INSERT INTO users VALUES (1)"))
	w.server(pgError(), pgReady('I'))
	w.want("failed INSERT")
	w.healthy()
}

// COMMIT of a failed transaction is answered with a ROLLBACK tag.
func TestPostgresCommitOfFailedTransactionRollsBack(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO users VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(pgQuery("SELECT 1/0"))
	w.server(pgError(), pgReady('E'))
	w.client(pgQuery("COMMIT"))
	w.server(pgDone("ROLLBACK"), pgReady('I'))
	w.want("rolled_back INSERT")
	w.healthy()
}

// A COMMIT the server refuses (a deferred constraint) ends the transaction.
func TestPostgresCommitErrorRollsBack(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO users VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(pgQuery("COMMIT"))
	w.server(pgError(), pgReady('I'))
	w.want("rolled_back INSERT")
	w.healthy()
}

// "Multiple Statements in a Simple Query": one implicit transaction.
func TestPostgresSimpleQueryIsOneTransaction(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("INSERT INTO a VALUES (1); INSERT INTO b VALUES (2); SELECT 1/0"))
	w.server(pgDone("INSERT 0 1"), pgDone("INSERT 0 1"), pgError(), pgReady('I'))
	w.want("rolled_back INSERT", "rolled_back INSERT")
	w.healthy()
}

// The manual's own example: the first INSERT is committed by the explicit
// COMMIT, and the second is undone by the error.
func TestPostgresCommitInsideSimpleQuery(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("INSERT INTO a VALUES (1); COMMIT; INSERT INTO b VALUES (2); SELECT 1/0"))
	w.server(pgDone("INSERT 0 1"), pgDone("COMMIT"), pgDone("INSERT 0 1"), pgError(), pgReady('I'))
	w.want("committed INSERT", "rolled_back INSERT")
	if got := w.first(); got.Tables[0] != "a" {
		t.Fatalf("%+v", got)
	}
	w.healthy()
}

func TestPostgresPreparedStatement(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("s1", "INSERT INTO users VALUES ($1)"), pgSync())
	w.server(frame('1'), pgReady('I'))
	w.want() // parsed is not run
	for i := 0; i < 2; i++ {
		w.client(pgBind("", "s1"), pgExecute(""), pgSync())
		w.server(frame('2'), pgDone("INSERT 0 1"), pgReady('I'))
	}
	w.want("committed INSERT", "committed INSERT")
	if e := w.cap.snapshot(); len(e) == 0 || e[len(e)-1].Tables[0] != "users" {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

func TestPostgresBoundValuesAreNotLogged(t *testing.T) {
	w := pgReadyWire(t)
	secret := []byte("hunter2-value")
	w.client(pgParse("", "INSERT INTO users VALUES ($1)"),
		frame('B', cstr(""), cstr(""), []byte{0, 0, 0, 1}, []byte{0, 0, 0, byte(len(secret))}, secret, []byte{0, 0}),
		pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("INSERT 0 1"), pgReady('I'))
	for _, e := range w.cap.snapshot() {
		if strings.Contains(e.Statement, "hunter2") {
			t.Fatalf("%+v", e)
		}
	}
	if !bytes.Contains(w.up.Bytes(), secret) {
		t.Fatal("the value must still reach the server")
	}
}

// Execute with no Sync between runs in one implicit transaction: an error in the
// second undoes the first.
func TestPostgresPipelineIsOneTransactionPerSync(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "INSERT INTO a VALUES (1)"), pgBind("", ""), pgExecute(""),
		pgParse("", "INSERT INTO b VALUES (2)"), pgBind("", ""), pgExecute(""),
		pgParse("", "INSERT INTO c VALUES (3)"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("INSERT 0 1"), frame('1'), frame('2'), pgError(), pgReady('I'))
	w.want("failed INSERT", "rolled_back INSERT")
	w.healthy()

	w = pgReadyWire(t)
	w.client(pgParse("", "INSERT INTO a VALUES (1)"), pgBind("", ""), pgExecute(""),
		pgParse("", "INSERT INTO b VALUES (2)"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("INSERT 0 1"), frame('1'), frame('2'), pgDone("INSERT 0 1"))
	w.want()
	w.server(pgReady('I'))
	w.want("committed INSERT", "committed INSERT")
	w.healthy()
}

func TestPostgresPipelineAcrossSyncs(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "INSERT INTO a VALUES (1)"), pgBind("", ""), pgExecute(""), pgSync(),
		pgParse("", "INSERT INTO b VALUES (2)"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("INSERT 0 1"), pgReady('I'))
	w.want("committed INSERT")
	w.server(frame('1'), frame('2'), pgError(), pgReady('I'))
	w.want("committed INSERT", "failed INSERT")
	w.healthy()
}

// After an error the server skips to Sync: the messages between get no reply.
func TestPostgresErrorSkipsToSync(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "BROKEN"), pgBind("", ""), pgExecute(""), pgSync(), pgQuery("SELECT 1"))
	w.server(pgError(), pgReady('I'))
	w.server(frame('T', []byte{0, 0}), frame('D', []byte{0, 0}), pgDone("SELECT 1"), pgReady('I'))
	w.healthy()
}

func TestPostgresSavepoints(t *testing.T) {
	w := pgReadyWire(t)
	steps := []struct{ sql, tag string }{
		{"BEGIN", "BEGIN"},
		{"INSERT INTO a VALUES (1)", "INSERT 0 1"},
		{"SAVEPOINT s", "SAVEPOINT"},
		{"INSERT INTO b VALUES (1)", "INSERT 0 1"},
		{"ROLLBACK TO SAVEPOINT s", "ROLLBACK"},
		{"INSERT INTO c VALUES (1)", "INSERT 0 1"},
		{"SAVEPOINT t", "SAVEPOINT"},
		{"RELEASE SAVEPOINT t", "RELEASE"},
	}
	for _, s := range steps {
		w.client(pgQuery(s.sql))
		w.server(pgDone(s.tag), pgReady('T'))
	}
	w.want("rolled_back INSERT")
	w.client(pgQuery("COMMIT"))
	w.server(pgDone("COMMIT"), pgReady('I'))
	w.want("rolled_back INSERT", "committed INSERT", "committed INSERT")
	var got []string
	for _, e := range w.cap.snapshot() {
		if e.Outcome == witness.OutcomeCommitted {
			got = append(got, e.Tables[0])
		}
	}
	if !slices.Equal(got, []string{"a", "c"}) {
		t.Fatalf("committed %q", got)
	}
	w.healthy()
}

// A savepoint the log does not know keeps everything: over-report.
func TestPostgresUnknownSavepointKeepsWrites(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(pgQuery("ROLLBACK TO nobody"))
	w.server(pgDone("ROLLBACK"), pgReady('T'))
	w.client(pgQuery("COMMIT"))
	w.server(pgDone("COMMIT"), pgReady('I'))
	w.want("committed INSERT")
}

func TestPostgresChainedTransactions(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(pgQuery("COMMIT AND CHAIN"))
	w.server(pgDone("COMMIT"), pgReady('T'))
	w.want("committed INSERT")
	w.client(pgQuery("INSERT INTO b VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(pgQuery("ROLLBACK AND CHAIN"))
	w.server(pgDone("ROLLBACK"), pgReady('T'))
	w.want("committed INSERT", "rolled_back INSERT")
	w.healthy()
}

func TestPostgresZeroRowsAreCommittedButNoEffect(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("DELETE FROM users WHERE owner = 9"))
	w.server(pgDone("DELETE 0"), pgReady('I'))
	w.want("committed DELETE")
	e := w.first()
	if e.Rows != 0 || e.Effect() {
		t.Fatalf("%+v", e)
	}
}

func TestPostgresOpaqueCountsEvenWithZero(t *testing.T) {
	w := pgReadyWire(t)
	// A data-modifying CTE's tag counts only the outer statement.
	w.client(pgQuery("WITH d AS (DELETE FROM a RETURNING *) INSERT INTO b SELECT * FROM d WHERE false"))
	w.server(pgDone("INSERT 0 0"), pgReady('I'))
	e := w.first()
	if !e.Opaque || !e.Effect() || !e.Touches("anything") {
		t.Fatalf("%+v", e)
	}
}

// The server's tag beats the text: a read that reports a write is opaque.
func TestPostgresTagContradictsText(t *testing.T) {
	for _, tc := range []struct{ sql, tag string }{
		{"SELECT 1", "DELETE 3"},
		{"INSERT INTO a VALUES (1)", "DELETE 3"},
		{"UPDATE a SET b = 1", "MERGE 2"},
		{"SHOW x", "COPY 3"},
	} {
		w := pgReadyWire(t)
		w.client(pgQuery(tc.sql))
		w.server(pgDone(tc.tag), pgReady('I'))
		e := w.first()
		if !e.Opaque || e.Outcome != witness.OutcomeCommitted || !e.Touches("anything") {
			t.Errorf("%q answered %q: %+v", tc.sql, tc.tag, e)
		}
	}
}

// More results than parsed statements: the text was misread, so the extra result
// is a statement nobody can name.
func TestPostgresMoreResultsThanStatements(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT 1"))
	w.server(pgDone("SELECT 1"), pgDone("DELETE 2"), pgReady('I'))
	var opaque int
	for _, e := range w.cap.snapshot() {
		if e.Opaque && e.Outcome == witness.OutcomeCommitted {
			opaque++
		}
	}
	if opaque != 1 {
		t.Fatalf("%+v", w.cap.snapshot())
	}
}

func TestPostgresBindToUnknownStatementIsOpaque(t *testing.T) {
	w := pgReadyWire(t)
	// The name came from SQL-level PREPARE, which the protocol allows.
	w.client(pgBind("", "from_sql"), pgExecute(""), pgSync())
	w.server(frame('2'), pgDone("UPDATE 1"), pgReady('I'))
	e := w.first()
	if !e.Opaque || e.Outcome != witness.OutcomeCommitted {
		t.Fatalf("%+v", e)
	}
}

func TestPostgresExecuteOfUnknownPortalIsOpaque(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgExecute("a_cursor"), pgSync())
	w.server(pgDone("FETCH 1"), pgReady('I'))
	e := w.first()
	if !e.Opaque {
		t.Fatalf("%+v", e)
	}
}

func TestPostgresCloseForgetsStatement(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("s", "SELECT 1"), pgClose('S', "s"), pgSync())
	w.server(frame('1'), frame('3'), pgReady('I'))
	w.client(pgParse("p", "SELECT 1"), pgBind("q", "p"), pgClose('P', "q"), pgExecute("q"), pgSync())
	w.server(frame('1'), frame('2'), frame('3'), pgError(), pgReady('I'))
	w.client(pgBind("", "s"), pgExecute(""), pgSync())
	w.server(pgError(), pgReady('I'))
	w.healthy()
	for _, e := range w.cap.snapshot() {
		if e.Outcome != witness.OutcomeFailed || !e.Opaque {
			t.Fatalf("a closed name must not resolve: %+v", e)
		}
	}
}

// A write's work is done at the first Execute; a limited Execute of RETURNING
// suspends, and the client may never run the portal to its CommandComplete.
func TestPostgresSuspendedPortalStillWrote(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "INSERT INTO a VALUES (1), (2) RETURNING id"), pgBind("", ""),
		frame('E', cstr(""), []byte{0, 0, 0, 1}), pgSync())
	w.server(frame('1'), frame('2'), frame('D', []byte{0, 0}), frame('s'), pgReady('I'))
	w.want("committed INSERT")
	if e := w.first(); e.Rows != witness.RowsUnknown {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

func TestPostgresCopyIn(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("COPY users FROM STDIN"))
	w.server(frame('G', []byte{0, 0, 0}))
	w.client(frame('d', []byte("1\n")), frame('c'))
	w.server(pgDone("COPY 1"), pgReady('I'))
	w.want("committed COPY")
	if e := w.first(); e.Rows != 1 || e.Tables[0] != "users" {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

func TestPostgresCopyFailed(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("COPY users FROM STDIN"))
	w.server(frame('G', []byte{0, 0, 0}))
	w.client(frame('f', cstr("no")))
	w.server(pgError(), pgReady('I'))
	w.want("failed COPY")
	w.healthy()
}

func TestPostgresFunctionCallIsOpaque(t *testing.T) {
	w := pgReadyWire(t)
	w.client(frame('F', []byte{0, 0, 3, 232}, []byte{0, 0, 0, 0, 0, 0}))
	w.server(frame('V', []byte{255, 255, 255, 255}), pgReady('I'))
	e := w.first()
	if !e.Opaque || e.Outcome != witness.OutcomeCommitted {
		t.Fatalf("%+v", e)
	}
	w.healthy()
}

// PREPARE TRANSACTION makes the writes durable. Whether they ever commit can be
// decided on another connection, so they are reported here.
func TestPostgresPreparedTransactionOverReports(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(pgQuery("PREPARE TRANSACTION 'x'"))
	w.server(pgDone("PREPARE TRANSACTION"), pgReady('I'))
	w.want("committed INSERT")
	w.healthy()
}

func TestPostgresReadsAreLoggedNotCommitted(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT * FROM users"))
	w.server(frame('T', []byte{0, 0}), frame('D', []byte{0, 0}), pgDone("SELECT 1"), pgReady('I'))
	all := w.cap.snapshot()
	if len(all) != 1 || all[0].Outcome != witness.OutcomeRead {
		t.Fatalf("%+v", all)
	}
	if got := w.cap.committed(); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestPostgresEmptyQuery(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery(""))
	w.server(frame('I'), pgReady('I'))
	w.healthy()
	w.want()
}

// ---- TLS ----

func TestPostgresRefusesTLS(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeSSL))
	if !bytes.Equal(w.back.Bytes(), []byte("N")) || w.up.Len() != 0 {
		t.Fatalf("back %q, up %q", w.back.Bytes(), w.up.Bytes())
	}
	w.client(pgStartup(codeV3, 0))
	if w.up.Len() == 0 {
		t.Fatal("the startup packet must go on")
	}
	w.s.finish()
	w.healthy()
	if got := w.cap.coverage().TLSRefused; got != 1 {
		t.Fatalf("TLSRefused %d", got)
	}
}

func TestPostgresRefusesGSSEncryption(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeGSS))
	if !bytes.Equal(w.back.Bytes(), []byte("N")) || w.up.Len() != 0 {
		t.Fatalf("back %q, up %q", w.back.Bytes(), w.up.Bytes())
	}
}

func TestPostgresClientInsistsOnTLS(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeSSL))
	w.s.finish() // told no, and left: sslmode=require
	w.cap.close()
	w.faulted("TLS")
}

// pgx with sslmode=prefer does not go on after 'N': it redials in the clear.
// Found against a real client; a fault here makes pgx's default DSN Inconclusive.
func TestPostgresPreferRedialsInTheClear(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeSSL))
	w.s.finish()
	plain := newPostgresSession(w.cap, 2)
	w.s = plain
	w.client(pgStartup(codeV3, 0))
	w.cap.close()
	w.healthy()
}

// A plain connection answers for one departure, not two.
func TestPostgresOnePlainConnectionDoesNotExcuseTwo(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeSSL))
	w.s.finish()
	w.s = newPostgresSession(w.cap, 2)
	w.client(pgStartup(codeSSL))
	w.s.finish()
	w.s = newPostgresSession(w.cap, 3)
	w.client(pgStartup(codeV3, 0))
	w.cap.close()
	w.faulted("TLS")
}

// A connection that asked, was told no and went on is no excuse for another.
func TestPostgresGoingOnAfterRefusalExcusesNobody(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeSSL))
	w.s.finish()
	w.s = newPostgresSession(w.cap, 2)
	w.client(pgStartup(codeSSL), pgStartup(codeV3, 0))
	w.cap.close()
	w.faulted("TLS")
}

// PostgreSQL 17 direct TLS: the first byte is a TLS record, not a length.
func TestPostgresDirectTLSIsInconclusive(t *testing.T) {
	w := newPG(t)
	w.client([]byte{0x16, 0x03, 0x01, 0x00, 0xf1, 0x01, 0x00, 0x00})
	w.faulted("TLS")
	if !errors.Is(w.err, errClose) {
		t.Fatalf("the connection must close: %v", w.err)
	}
}

func TestPostgresPlainDisconnectIsNotInsisting(t *testing.T) {
	w := newPG(t)
	w.s.finish()
	w.healthy()
}

func TestPostgresCancelGoesThrough(t *testing.T) {
	w := newPG(t)
	cancel := pgStartup(codeCancel, 0, 0, 0, 1, 0, 0, 0, 2)
	w.client(cancel)
	if !bytes.Equal(w.up.Bytes(), cancel) {
		t.Fatalf("up %q", w.up.Bytes())
	}
	if !errors.Is(w.err, errClose) {
		t.Fatalf("%v", w.err)
	}
	if w.cap.coverage().Connections != 0 {
		t.Fatal("a cancel request is not a connection")
	}
	w.s.finish()
	w.healthy()
}

// ---- Inconclusive ----

// Once a frame is unreadable the bytes still flow, so the application is not
// broken by its witness, and every later step is a raw copy.
func TestPostgresBlindConnectionStaysBlind(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(frame('@', []byte{1}))
	if err := w.s.client(bufio.NewReader(bytes.NewReader(pgQuery("DELETE FROM b"))), &w.up, &w.back); !errors.Is(err, errBlind) {
		t.Fatalf("client after blind: %v", err)
	}
	if err := w.s.server(bufio.NewReader(bytes.NewReader(frame('N', []byte{0}))), &w.back); !errors.Is(err, errBlind) {
		t.Fatalf("server after blind: %v", err)
	}
	w.s.finish()
	w.want("unknown INSERT")
	w.faulted("unreadable")
}

func TestPostgresDroppedMidTransaction(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.s.finish()
	w.want("unknown INSERT")
	w.faulted("dropped")
}

func TestPostgresDroppedInEmptyTransaction(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.s.finish()
	w.faulted("dropped")
}

func TestPostgresDroppedWithCommitInFlight(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.s.finish()
	w.faulted("dropped")
}

func TestPostgresTerminateRollsBackCleanly(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('T'))
	w.client(frame('X'))
	w.s.finish()
	w.want("rolled_back INSERT")
	w.healthy()
}

func TestPostgresIdleCloseIsClean(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT 1"))
	w.server(pgDone("SELECT 1"), pgReady('I'))
	w.s.finish()
	w.healthy()
}

func TestPostgresFailedLoginIsClean(t *testing.T) {
	w := newPG(t)
	w.client(pgStartup(codeV3, 0))
	w.server(pgFatal())
	w.s.finish()
	w.healthy()
}

// A server shutting down says FATAL with nothing asked of it.
func TestPostgresUnpromptedFatalIsNotDesync(t *testing.T) {
	w := pgReadyWire(t)
	w.server(pgFatal())
	w.s.finish()
	w.healthy()
}

func TestPostgresAsyncMessagesPassThrough(t *testing.T) {
	w := pgReadyWire(t)
	w.server(frame('N', []byte{0}), frame('A', []byte{0, 0, 0, 1, 0, 0}), frame('S', cstr("a"), cstr("b")))
	w.healthy()
	if w.back.Len() == 0 {
		t.Fatal("async messages must reach the client")
	}
}

func TestPostgresLargeRowStreams(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT big"))
	big := make([]byte, maxFrame+1024)
	w.server(frame('D', big), pgDone("SELECT 1"), pgReady('I'))
	w.healthy()
	if w.back.Len() < len(big) {
		t.Fatal("a row larger than the parse limit must stream")
	}
}
