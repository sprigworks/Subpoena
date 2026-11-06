package dbproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// Startup request codes, from the protocol's message formats.
const (
	pgSSLRequest    = 80877103
	pgGSSENCRequest = 80877104
	pgCancelRequest = 80877102
	pgMaxStartup    = 10000 // the server's own limit
	tlsRecord       = 0x16  // first byte of a TLS handshake record
)

// pgClientTypes and pgServerTypes are every message type in protocol 3.x.
const (
	pgClientTypes = "QPBECFSHDXdcfp"
	pgServerTypes = "RKSNATDtn123cdGHWIsEZCVv"
)

type pgItemKind int

const (
	pgItemSimple  pgItemKind = iota // a Query or FunctionCall: ends at ReadyForQuery
	pgItemExecute                   // an Execute: ends at its own reply
	pgItemSync                      // a Sync: ends at ReadyForQuery
)

// pgItem is a message sent to the server that it has not finished answering.
type pgItem struct {
	kind  pgItemKind
	stmts []statement
	next  int
	text  string // the whole query, for naming an unexpected result
}

// pgSession follows one connection. Every reply is tied to the message that
// caused it through queue; the client side adds before forwarding, so a reply
// always finds its message.
type pgSession struct {
	cap *capture
	id  int

	mu         sync.Mutex
	tx         txLog
	inStartup  bool
	counted    bool
	tlsAsked   bool
	ready      bool // the server has reached its first ReadyForQuery
	blind      bool
	terminated bool
	status     byte
	failed     bool // an error since the last ReadyForQuery
	queue      []*pgItem
	prepared   map[string]*statement
	portals    map[string]*statement
}

func newPostgresSession(c *capture, id int) *pgSession {
	return &pgSession{
		cap: c, id: id, tx: txLog{cap: c, conn: id},
		inStartup: true, status: 'I',
		prepared: map[string]*statement{}, portals: map[string]*statement{},
	}
}

// unreadable faults the connection and stops reading it: it goes on as a raw
// copy, so the application keeps working, and absence can no longer rest on it.
func (s *pgSession) unreadable(format string, a ...any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unreadableLocked(format, a...)
}

//subpoena:enforcement_point
func (s *pgSession) unreadableLocked(format string, a ...any) error {
	s.blind = true //subpoena:enforcement
	s.cap.fault("connection %d: unreadable: "+format, append([]any{s.id}, a...)...)
	return errBlind
}

// guard runs a step of the parser. A frame that breaks it is an unreadable frame:
// a panic here would take the test binary with it, and lose the capture.
//
//subpoena:enforcement_point
func (s *pgSession) guard(step func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = s.unreadableLocked("a frame broke the parser: %v", r) //subpoena:enforcement
		}
	}()
	return step()
}

func (s *pgSession) stepState() (blind, inStartup bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blind, s.inStartup
}

// client moves one client message towards the server.
//
//subpoena:enforcement_point
func (s *pgSession) client(r *bufio.Reader, up, back io.Writer) error {
	blind, inStartup := s.stepState()
	if blind {
		return errBlind //subpoena:enforcement
	}
	if inStartup {
		return s.startup(r, up, back)
	}
	h, err := r.Peek(5)
	if err != nil {
		return err
	}
	typ, n := h[0], int64(binary.BigEndian.Uint32(h[1:]))
	switch {
	case n < 4:
		return s.unreadable("client message %q has length %d", typ, n) //subpoena:enforcement
	case strings.IndexByte(pgClientTypes, typ) < 0:
		return s.unreadable("client message type %q", typ) //subpoena:enforcement
	case strings.IndexByte("QPBECF", typ) < 0:
		// Nothing to read in it: forward it whole, however long.
		s.mu.Lock()
		err := s.guard(func() error { return s.onClient(typ, nil) })
		s.mu.Unlock()
		if _, werr := io.CopyN(up, r, n+1); werr != nil {
			return werr
		}
		return err
	case n-4 > maxFrame:
		return s.unreadable("client message %q of %d bytes", typ, n) //subpoena:enforcement
	}
	buf := make([]byte, n+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	s.mu.Lock()
	stepErr := s.guard(func() error { return s.onClient(typ, buf[5:]) })
	s.mu.Unlock()
	if _, err := up.Write(buf); err != nil {
		return err
	}
	return stepErr
}

// startup handles the messages before the first real one, which have no type
// byte. TLS and GSS requests are answered here and never reach the server: bytes
// the witness cannot read cannot be allowed to read as no row.
//
//subpoena:enforcement_point
func (s *pgSession) startup(r *bufio.Reader, up, back io.Writer) error {
	first, err := r.Peek(1)
	if err != nil {
		return err
	}
	if first[0] == tlsRecord {
		s.cap.noteConnection()
		s.cap.fault("connection %d: the client began TLS without asking; its traffic was not proxied", s.id) //subpoena:enforcement
		return errClose
	}
	h, err := r.Peek(8)
	if err != nil {
		return err
	}
	n, code := int64(binary.BigEndian.Uint32(h)), binary.BigEndian.Uint32(h[4:])
	if n < 8 || n > pgMaxStartup {
		return s.unreadable("startup packet of length %d", n) //subpoena:enforcement
	}
	if code != pgSSLRequest && code != pgGSSENCRequest && code != pgCancelRequest && code>>16 != 3 {
		return s.unreadable("startup code %d", code) //subpoena:enforcement
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if code != pgCancelRequest && !s.counted {
		s.counted = true
		s.cap.noteConnection()
	}
	switch {
	case code == pgSSLRequest || code == pgGSSENCRequest:
		r.Discard(int(n))
		s.tlsAsked = true //subpoena:enforcement
		s.cap.noteTLSRefused()
		_, err := back.Write([]byte{'N'})
		return err
	case code == pgCancelRequest:
		if _, err := io.CopyN(up, r, n); err != nil {
			return err
		}
		return errClose
	}
	s.inStartup = false
	if !s.tlsAsked {
		s.cap.notePlainStart()
	}
	_, err = io.CopyN(up, r, n)
	return err
}

func cstring(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

// onClient updates the session for one client message, before it is forwarded.
//
//subpoena:enforcement_point
func (s *pgSession) onClient(typ byte, body []byte) error {
	switch typ {
	case 'Q':
		sql, _, ok := cstring(body)
		if !ok {
			return s.unreadableLocked("Query without a terminator") //subpoena:enforcement
		}
		s.queue = append(s.queue, &pgItem{kind: pgItemSimple, stmts: parseSQL(dialectPostgres, sql), text: sql})
	case 'P':
		name, rest, ok := cstring(body)
		sql, _, ok2 := cstring(rest)
		if !ok || !ok2 {
			return s.unreadableLocked("Parse without a terminator") //subpoena:enforcement
		}
		s.prepared[name] = onePrepared(dialectPostgres, sql)
	case 'B':
		portal, rest, ok := cstring(body)
		name, _, ok2 := cstring(rest)
		if !ok || !ok2 {
			return s.unreadableLocked("Bind without a terminator") //subpoena:enforcement
		}
		st := s.prepared[name]
		if st == nil {
			o := opaqueStatement("", "EXECUTE", "bound to %q, a statement the witness did not see parsed", name)
			st = &o
		}
		s.portals[portal] = st
	case 'E':
		portal, _, ok := cstring(body)
		if !ok {
			return s.unreadableLocked("Execute without a terminator") //subpoena:enforcement
		}
		st := s.portals[portal]
		if st == nil {
			o := opaqueStatement("", "EXECUTE", "ran portal %q, which the witness did not see bound", portal)
			st = &o
		}
		s.queue = append(s.queue, &pgItem{kind: pgItemExecute, stmts: []statement{*st}})
	case 'C':
		if len(body) < 2 {
			return s.unreadableLocked("Close too short") //subpoena:enforcement
		}
		name, _, ok := cstring(body[1:])
		if !ok {
			return s.unreadableLocked("Close without a terminator") //subpoena:enforcement
		}
		if body[0] == 'S' {
			delete(s.prepared, name)
		} else {
			delete(s.portals, name)
		}
	case 'F':
		o := opaqueStatement("", "FUNCTION CALL", "a fast-path function call")
		s.queue = append(s.queue, &pgItem{kind: pgItemSimple, stmts: []statement{o}})
	case 'S':
		s.queue = append(s.queue, &pgItem{kind: pgItemSync})
	case 'X':
		s.terminated = true
	}
	return nil
}

// onePrepared is the statement a prepare names. Both protocols take one; text
// that reads as several is opaque, and the server will refuse it.
func onePrepared(d dialect, sql string) *statement {
	stmts := parseSQL(d, sql)
	switch len(stmts) {
	case 0:
		return &statement{text: sql}
	case 1:
		return &stmts[0]
	}
	o := opaqueStatement(sql, firstWord(sql), "several statements in one prepare")
	return &o
}

// server moves one server message towards the client.
//
//subpoena:enforcement_point
func (s *pgSession) server(r *bufio.Reader, back io.Writer) error {
	if blind, _ := s.stepState(); blind {
		return errBlind //subpoena:enforcement
	}
	h, err := r.Peek(5)
	if err != nil {
		return err
	}
	typ, n := h[0], int64(binary.BigEndian.Uint32(h[1:]))
	switch {
	case n < 4:
		return s.unreadable("server message %q has length %d", typ, n) //subpoena:enforcement
	case strings.IndexByte(pgServerTypes, typ) < 0:
		return s.unreadable("server message type %q", typ) //subpoena:enforcement
	case strings.IndexByte("CZ", typ) < 0:
		s.mu.Lock()
		err := s.guard(func() error { return s.onServer(typ, nil) })
		s.mu.Unlock()
		if _, werr := io.CopyN(back, r, n+1); werr != nil {
			return werr
		}
		return err
	case n-4 > maxFrame:
		return s.unreadable("server message %q of %d bytes", typ, n) //subpoena:enforcement
	}
	buf := make([]byte, n+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	s.mu.Lock()
	stepErr := s.guard(func() error { return s.onServer(typ, buf[5:]) })
	s.mu.Unlock()
	if _, err := back.Write(buf); err != nil {
		return err
	}
	return stepErr
}

// current is the statement the next result belongs to. A result past the parsed
// statements means the text was misread, and it can have been anything.
func (it *pgItem) current() *statement {
	if it.next < len(it.stmts) {
		return &it.stmts[it.next]
	}
	o := opaqueStatement(it.text, firstWord(it.text), "more results than statements were read")
	return &o
}

// result is the head of the queue if it can take a command's result.
func (s *pgSession) result() *pgItem {
	if len(s.queue) == 0 || s.queue[0].kind == pgItemSync {
		return nil
	}
	return s.queue[0]
}

func (s *pgSession) advance(it *pgItem) {
	it.next++
	if it.kind == pgItemExecute {
		s.queue = s.queue[1:]
	}
}

// onServer updates the session for one server message, before it is forwarded,
// so a client that has its answer finds the outcome recorded.
//
//subpoena:enforcement_point
func (s *pgSession) onServer(typ byte, body []byte) error {
	switch typ {
	case 'C':
		tag, _, ok := cstring(body)
		if !ok {
			return s.unreadableLocked("CommandComplete without a terminator") //subpoena:enforcement
		}
		it := s.result()
		if it == nil {
			return s.unreadableLocked("CommandComplete %q with no command waiting", tag) //subpoena:enforcement
		}
		s.complete(it.current(), tag)
		s.advance(it)
	case 'I':
		if it := s.result(); it != nil {
			s.advance(it)
		}
	case 's':
		// A limited Execute of a write did its work at the first run, and the
		// client may close the portal without running it to completion.
		it := s.result()
		if it == nil {
			return s.unreadableLocked("PortalSuspended with no command waiting") //subpoena:enforcement
		}
		if st := it.current(); st.class != classRead {
			s.tx.add(st, witness.RowsUnknown) //subpoena:enforcement
		}
		s.advance(it)
	case 'V':
		it := s.result()
		if it == nil {
			return s.unreadableLocked("FunctionCallResponse with no call waiting") //subpoena:enforcement
		}
		s.tx.add(it.current(), witness.RowsUnknown) //subpoena:enforcement
		s.advance(it)
	case 'W':
		return s.unreadableLocked("CopyBothResponse: a replication stream") //subpoena:enforcement
	case 'E':
		s.serverError()
	case 'Z':
		if len(body) != 1 || strings.IndexByte("ITE", body[0]) < 0 {
			return s.unreadableLocked("ReadyForQuery status %q", body) //subpoena:enforcement
		}
		return s.readyForQuery(body[0])
	}
	return nil
}

// serverError applies an ErrorResponse. With nothing asked of it the server is
// saying FATAL at login or at shutdown, and the end of the connection decides.
func (s *pgSession) serverError() {
	if len(s.queue) == 0 {
		return
	}
	s.failed = true
	it := s.result()
	if it == nil {
		return // at a Sync: the implicit commit failed, and ReadyForQuery settles it
	}
	st := it.current()
	s.tx.done(st, witness.RowsUnknown, witness.OutcomeFailed)
	if it.kind == pgItemSimple {
		it.next = len(it.stmts) // the rest of the text will not run
		return
	}
	// Everything up to the next Sync is skipped by the server, unanswered.
	for len(s.queue) > 0 && s.queue[0].kind != pgItemSync {
		s.queue = s.queue[1:]
	}
}

// readyForQuery ends a cycle. Status 'I' after a cycle means any write still
// pending has ended with the implicit or explicit transaction it was in, and an
// error in the cycle means that ending was a rollback. PREPARE TRANSACTION ends
// this way too, and counts as committed: it is durable now, and decided later,
// maybe on another connection.
//
//subpoena:enforcement_point
func (s *pgSession) readyForQuery(status byte) error {
	if len(s.queue) == 0 {
		if s.ready {
			return s.unreadableLocked("ReadyForQuery with no command waiting") //subpoena:enforcement
		}
		s.ready = true
		s.status = status
		return nil
	}
	s.ready = true
	if s.queue[0].kind == pgItemExecute {
		return s.unreadableLocked("ReadyForQuery before an Execute was answered") //subpoena:enforcement
	}
	s.queue = s.queue[1:]
	s.status = status
	if status == 'I' {
		if s.failed {
			s.tx.rollback()
		} else {
			s.tx.commit()
		}
	}
	s.failed = false
	return nil
}

var pgWriteTags = wordSet("INSERT UPDATE DELETE MERGE COPY")

// parseTag reads a CommandComplete tag: its first word, and the row count if the
// tag is one that carries it.
func parseTag(tag string) (verb string, rows int64) {
	f := strings.Fields(tag)
	if len(f) == 0 {
		return "", witness.RowsUnknown
	}
	if pgWriteTags[f[0]] {
		if n, err := strconv.ParseInt(f[len(f)-1], 10, 64); err == nil {
			return f[0], n
		}
	}
	return f[0], witness.RowsUnknown
}

// complete applies one statement's CommandComplete. The tag decides the
// transaction: COMMIT of a failed transaction is answered ROLLBACK. It also
// checks the text: a tag that contradicts it means the text was misread, and the
// statement is opaque.
//
//subpoena:enforcement_point
func (s *pgSession) complete(st *statement, tag string) {
	verb, rows := parseTag(tag)
	switch tag {
	case "COMMIT":
		s.tx.commit()
	case "ROLLBACK":
		if st.tx == txRollbackTo {
			s.tx.rollbackTo(st.savepoint)
		} else {
			s.tx.rollback()
		}
	case "SAVEPOINT":
		s.tx.savepoint(st.savepoint)
	case "RELEASE":
		s.tx.release(st.savepoint)
	}
	switch {
	case st.class == classOpaque:
		s.tx.add(st, witness.RowsUnknown)
	case pgWriteTags[verb] && st.class != classWrite && st.verb != "COPY",
		st.class == classWrite && pgWriteTags[st.verb] && verb != st.verb:
		s.tx.add(st.opaqued("answered %q", tag), witness.RowsUnknown) //subpoena:enforcement
	case st.class == classWrite:
		if st.noCount {
			rows = witness.RowsUnknown
		}
		s.tx.add(st, rows)
	default:
		s.tx.done(st, witness.RowsUnknown, witness.OutcomeRead)
	}
}

func (s *pgSession) inFlight() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) != 0
}

// finish settles the connection once both directions have ended. A client that
// said Terminate with nothing in flight has rolled back by the protocol's rules.
// Anything else open at the end was dropped, and its outcome was not seen.
//
//subpoena:enforcement_point
func (s *pgSession) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.inStartup && s.tlsAsked:
		s.cap.noteTLSLeft(s.id) //subpoena:enforcement
	case s.blind:
		s.settleInFlight()
		s.tx.abandon() //subpoena:enforcement
	case len(s.queue) != 0 || s.status != 'I' || len(s.tx.pending) != 0:
		if s.terminated && len(s.queue) == 0 {
			s.tx.rollback()
			return
		}
		s.cap.fault("connection %d: dropped mid-transaction (status %q, %d replies owed, %d writes open)", s.id, s.status, len(s.queue), len(s.tx.pending)) //subpoena:enforcement
		s.settleInFlight()
		s.tx.abandon() //subpoena:enforcement
	}
}

// settleInFlight adds the writes the server never answered for to the
// transaction, so that they are reported as unknown.
func (s *pgSession) settleInFlight() {
	for _, it := range s.queue {
		for i := it.next; i < len(it.stmts); i++ {
			if st := &it.stmts[i]; st.class == classWrite || st.class == classOpaque {
				s.tx.add(st, witness.RowsUnknown)
			}
		}
	}
	s.queue = nil
}
