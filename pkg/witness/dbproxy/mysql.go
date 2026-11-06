package dbproxy

import (
	"bufio"
	"encoding/binary"
	"io"
	"sync"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// Capability and status flags, from the protocol documentation.
const (
	myCapCompress     = 0x00000020
	myCapProtocol41   = 0x00000200
	myCapSSL          = 0x00000800
	myCapDeprecateEOF = 0x01000000
	myCapZstd         = 0x04000000
	myCapQueryAttrs   = 0x08000000

	// myCapsCleared are what the witness takes out of the greeting: encryption
	// and compression it could not read. Query attributes stay: libmysql sets
	// that flag whatever the greeting offered and then writes no attribute prefix,
	// which the server refuses as malformed.
	myCapsCleared = myCapSSL | myCapCompress | myCapZstd

	myStatusInTrans      = 0x0001
	myStatusMoreResults  = 0x0008
	myStatusCursorExists = 0x0040
	myStatusNoBackslash  = 0x0200

	myMaxPacket = 0xffffff
)

// maxCommand is the most of one command it keeps to read. A longer one is opaque.
var maxCommand = maxFrame

// Commands.
const (
	comQuit        = 0x01
	comInitDB      = 0x02
	comQuery       = 0x03
	comFieldList   = 0x04
	comStatistics  = 0x09
	comDebug       = 0x0d
	comPing        = 0x0e
	comChangeUser  = 0x11
	comStmtPrepare = 0x16
	comStmtExecute = 0x17
	comStmtLong    = 0x18
	comStmtClose   = 0x19
	comStmtReset   = 0x1a
	comSetOption   = 0x1b
	comStmtFetch   = 0x1c
	comReset       = 0x1f
)

type myPhase int

const (
	phaseGreeting myPhase = iota // waiting for the server's greeting
	phaseResponse                // greeted; waiting for the client's answer
	phaseAuth                    // relaying authentication
	phaseCommand
	phaseRefused // the server said no; it will close
)

type myKind int

const (
	myResult    myKind = iota // COM_QUERY, COM_STMT_EXECUTE: OK, ERR or a result set
	kindPrepare               // COM_STMT_PREPARE
	mySimple                  // one OK, EOF or ERR
	myBare                    // one packet of anything
	myRows                    // packets up to an EOF or ERR
	myResetting               // COM_RESET_CONNECTION
)

type myState int

const (
	myFirst   myState = iota // the reply's first packet
	myColumns                // n column definitions
	myColumnsEOF
	myRowData
	mySkip // n packets that say nothing
)

// myItem is a command the server has not finished answering.
type myItem struct {
	kind  myKind
	state myState
	n     uint64 // packets left in myColumns or mySkip
	stmts []statement
	next  int
	text  string
	cut   bool // the text lost its tail to maxFrame
}

// mySession follows one connection. As in the PostgreSQL session, the client side
// queues a command before forwarding it, so a reply always finds its command.
type mySession struct {
	cap *capture
	id  int

	mu         sync.Mutex
	tx         txLog
	phase      myPhase
	serverCaps uint32 // as the server offered, before clearing
	caps       uint32 // as negotiated
	status     uint16
	blind      bool
	terminated bool
	taint      string // why no statement on this connection can be read any more
	infile     bool   // the client is sending a LOAD DATA LOCAL file
	resetting  bool   // COM_CHANGE_USER is re-authenticating
	queue      []*myItem
	prepared   map[uint32]*statement

	serverCont bool // the next server packet continues a full one
	clientCont bool
	big        []byte // a command longer than one packet
	bigCut     bool   // big lost its tail to maxFrame
}

func newMySQLSession(c *capture, id int) *mySession {
	return &mySession{cap: c, id: id, tx: txLog{cap: c, conn: id}, prepared: map[uint32]*statement{}}
}

// tainted marks the connection as one whose statements can't be read, for good,
// as pgSession's.
//
//subpoena:enforcement_point
func (s *mySession) tainted(why string) {
	if s.taint == "" {
		s.taint = why //subpoena:enforcement
	}
}

// readable is st as far as the session's state allows, asked at the reply: MySQL
// lexes each statement of a multi-statement text only when it reaches it.
//
//subpoena:enforcement_point
func (s *mySession) readable(st *statement) *statement {
	if s.taint != "" && (st.class == classRead || st.class == classWrite) {
		return st.opaqued("the session cannot be read: %s", s.taint) //subpoena:enforcement
	}
	return st
}

// noteStatus reads the one lexing setting the server reports.
//
//subpoena:enforcement_point
func (s *mySession) noteStatus(status uint16) {
	if status&myStatusNoBackslash != 0 {
		s.tainted("NO_BACKSLASH_ESCAPES is on") //subpoena:enforcement
	}
}

// failed applies an ERR to the statement it ends. ERR carries no status flags. A
// routine that failed may have committed part of its work, in or out of a
// transaction, and a statement that commits implicitly did so before it failed.
//
//subpoena:enforcement_point
func (s *mySession) failed(st *statement) {
	st = s.readable(st)
	if st.mayCommit() {
		s.tx.commit()
		s.tx.unknown(st) //subpoena:enforcement
		return
	}
	if myImplicitCommit[st.verb] {
		s.tx.commit() //subpoena:enforcement
	}
	s.tx.done(st, witness.RowsUnknown, witness.OutcomeFailed)
}

// myImplicitCommit are the known verbs that commit the open transaction before
// they run, so before they can fail.
var myImplicitCommit = wordSet("CREATE ALTER DROP TRUNCATE")

// myAsciiTrailCollations are the handshake's collation ids of big5, sjis, gbk,
// cp932 and gb18030, whose multibyte characters can end in a backslash.
var myAsciiTrailCollations = map[byte]bool{1: true, 84: true, 13: true, 88: true, 28: true, 87: true, 95: true,
	96: true, 248: true, 249: true, 250: true}

// unreadableLocked faults the connection and stops reading it, as pgSession's.
//
//subpoena:enforcement_point
func (s *mySession) unreadableLocked(format string, a ...any) error {
	s.blind = true //subpoena:enforcement
	s.cap.fault("connection %d: unreadable: "+format, append([]any{s.id}, a...)...)
	return errBlind
}

// guard runs a step of the parser, as pgSession's does.
//
//subpoena:enforcement_point
func (s *mySession) guard(step func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = s.unreadableLocked("a packet broke the parser: %v", r) //subpoena:enforcement
		}
	}()
	return step()
}

func (s *mySession) isBlind() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blind
}

// readPacket reads one packet, header and all.
func readPacket(r *bufio.Reader) ([]byte, error) {
	h, err := r.Peek(4)
	if err != nil {
		return nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	buf := make([]byte, n+4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// client moves one client packet towards the server.
//
//subpoena:enforcement_point
func (s *mySession) client(r *bufio.Reader, up, back io.Writer) error {
	if s.isBlind() {
		return errBlind //subpoena:enforcement
	}
	buf, err := readPacket(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	stepErr := s.guard(func() error { return s.onClient(buf[4:]) })
	s.mu.Unlock()
	if stepErr == errClose {
		return stepErr //subpoena:enforcement
	}
	if _, err := up.Write(buf); err != nil {
		return err
	}
	return stepErr
}

// onClient updates the session for one client packet, before it is forwarded.
//
//subpoena:enforcement_point
func (s *mySession) onClient(p []byte) error {
	switch s.phase {
	case phaseGreeting:
		return s.unreadableLocked("a client packet before the greeting") //subpoena:enforcement
	case phaseResponse:
		return s.handshakeResponse(p)
	case phaseCommand:
		return s.commandPacket(p)
	}
	return nil
}

// handshakeResponse reads the client's answer to the greeting. The greeting no
// longer offered TLS or compression; a client that asks anyway is speaking
// something the witness cannot read.
//
//subpoena:enforcement_point
func (s *mySession) handshakeResponse(p []byte) error {
	if len(p) < 4 {
		return s.unreadableLocked("a handshake response of %d bytes", len(p)) //subpoena:enforcement
	}
	caps := binary.LittleEndian.Uint32(p)
	switch {
	case caps&myCapSSL != 0:
		s.phase = phaseRefused
		s.cap.fault("connection %d: the client insists on TLS; its traffic was not proxied", s.id) //subpoena:enforcement
		return errClose
	case caps&(myCapCompress|myCapZstd) != 0:
		return s.unreadableLocked("the client insists on compression") //subpoena:enforcement
	case caps&myCapProtocol41 == 0:
		return s.unreadableLocked("the client does not speak protocol 4.1") //subpoena:enforcement
	}
	s.caps = caps & s.serverCaps
	if len(p) > 8 && myAsciiTrailCollations[p[8]] {
		s.tainted("the client charset can hide quotes in multibyte characters") //subpoena:enforcement
	}
	s.phase = phaseAuth
	return nil
}

// commandPacket gathers a command that may span packets. Each packet is forwarded
// as it comes; the command takes effect with the last.
func (s *mySession) commandPacket(p []byte) error {
	if s.infile {
		s.infile = len(p) != 0 // an empty packet ends the file
		return nil
	}
	if !s.clientCont && len(p) < myMaxPacket {
		return s.command(p, false)
	}
	room := min(maxCommand-len(s.big), len(p))
	s.big = append(s.big, p[:room]...)
	s.bigCut = s.bigCut || room < len(p)
	s.clientCont = len(p) == myMaxPacket
	if s.clientCont {
		return nil
	}
	big, cut := s.big, s.bigCut
	s.big, s.bigCut = nil, false
	return s.command(big, cut)
}

// queryText is a COM_QUERY's SQL, past any query attributes. ok is false if the
// attributes are there: their values come first, in a form with no plain text.
func (s *mySession) queryText(p []byte) (string, bool) {
	if s.caps&myCapQueryAttrs == 0 {
		return string(p), true
	}
	params, n := lenenc(p)
	if n == 0 {
		return "", false
	}
	_, m := lenenc(p[n:])
	if m == 0 || params != 0 {
		return "", false
	}
	return string(p[n+m:]), true
}

// command applies one whole command. cut means its tail was not kept.
//
//subpoena:enforcement_point
func (s *mySession) command(p []byte, cut bool) error {
	if len(p) == 0 {
		return s.unreadableLocked("an empty command") //subpoena:enforcement
	}
	cmd, body := p[0], p[1:]
	switch cmd {
	case comQuit:
		s.terminated = true
	case comInitDB, comPing, comDebug, comStmtReset, comSetOption:
		s.push(&myItem{kind: mySimple})
	case comStatistics:
		s.push(&myItem{kind: myBare})
	case comFieldList, comStmtFetch:
		s.push(&myItem{kind: myRows, state: myRowData})
	case comReset:
		s.push(&myItem{kind: myResetting})
	case comChangeUser:
		s.phase, s.resetting = phaseAuth, true
		s.tainted("COM_CHANGE_USER can set a charset") //subpoena:enforcement
	case comStmtLong:
	case comQuery:
		sql, ok := s.queryText(body)
		stmts := parseSQL(dialectMySQL, sql)
		if cut {
			stmts = []statement{opaqueStatement(sql, "QUERY", "too long to read")} //subpoena:enforcement
		}
		if !ok {
			stmts = []statement{opaqueStatement("", "QUERY", "query attributes ahead of the text")} //subpoena:enforcement
		}
		for i := range stmts {
			s.tainted(stmts[i].taint)
		}
		s.push(&myItem{stmts: stmts, text: sql})
	case comStmtPrepare:
		s.push(&myItem{kind: kindPrepare, text: string(body), cut: cut})
	case comStmtExecute:
		if len(body) < 4 {
			return s.unreadableLocked("COM_STMT_EXECUTE of %d bytes", len(p)) //subpoena:enforcement
		}
		id := binary.LittleEndian.Uint32(body)
		st := s.prepared[id]
		if st == nil {
			st = unseenStatement("ran statement %d, which the witness did not see prepared", id)
		}
		s.push(&myItem{stmts: []statement{*st}})
	case comStmtClose:
		if len(body) < 4 {
			return s.unreadableLocked("COM_STMT_CLOSE of %d bytes", len(p)) //subpoena:enforcement
		}
		delete(s.prepared, binary.LittleEndian.Uint32(body))
	default:
		return s.unreadableLocked("command %#x", cmd) //subpoena:enforcement
	}
	return nil
}

func (s *mySession) push(it *myItem) { s.queue = append(s.queue, it) }

func (s *mySession) pop() { s.queue = s.queue[1:] }

// server moves one server packet towards the client.
//
//subpoena:enforcement_point
func (s *mySession) server(r *bufio.Reader, back io.Writer) error {
	if s.isBlind() {
		return errBlind //subpoena:enforcement
	}
	buf, err := readPacket(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	stepErr := s.guard(func() error { return s.onServer(buf[4:]) })
	s.mu.Unlock()
	if _, err := back.Write(buf); err != nil {
		return err
	}
	return stepErr
}

// onServer updates the session for one server packet, before it is forwarded, so
// a client that has its answer finds the outcome recorded. p may be changed.
func (s *mySession) onServer(p []byte) error {
	cont := s.serverCont
	s.serverCont = len(p) == myMaxPacket
	if cont {
		return nil // the tail of a row: nothing in it is a header
	}
	switch s.phase {
	case phaseGreeting:
		return s.greeting(p)
	case phaseAuth:
		return s.authReply(p)
	case phaseCommand:
		return s.reply(p)
	}
	return nil
}

// greeting reads the server's greeting and takes TLS and compression out of it.
// A client that prefers TLS then goes on in the clear; one that requires it
// leaves, and finish reports that.
//
//subpoena:enforcement_point
func (s *mySession) greeting(p []byte) error {
	s.cap.noteConnection()
	if len(p) > 0 && p[0] == 0xff {
		s.phase = phaseRefused
		return nil
	}
	if len(p) == 0 || p[0] != 10 {
		return s.unreadableLocked("a greeting of protocol version %v", p[:min(len(p), 1)]) //subpoena:enforcement
	}
	i := 1
	for i < len(p) && p[i] != 0 {
		i++
	}
	low := i + 1 + 4 + 8 + 1 // past the version, thread id, salt and filler
	high := low + 2 + 1 + 2  // past the low flags, charset and status
	if high+2 > len(p) {
		return s.unreadableLocked("a greeting of %d bytes", len(p)) //subpoena:enforcement
	}
	s.serverCaps = uint32(binary.LittleEndian.Uint16(p[low:])) | uint32(binary.LittleEndian.Uint16(p[high:]))<<16
	if s.serverCaps&myCapSSL != 0 {
		s.cap.noteTLSRefused()
	}
	offered := s.serverCaps
	offered &^= myCapsCleared //subpoena:enforcement
	binary.LittleEndian.PutUint16(p[low:], uint16(offered))
	binary.LittleEndian.PutUint16(p[high:], uint16(offered>>16))
	s.phase = phaseResponse
	return nil
}

// authReply follows authentication, whose packets it relays unread, to the end.
func (s *mySession) authReply(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	switch p[0] {
	case 0xff:
		s.phase = phaseRefused
	case 0x00:
		s.phase = phaseCommand
		if s.resetting {
			s.resetting = false
			s.resetSession()
		}
		if ok, good := parseOK(p); good {
			s.status = ok.status
			s.noteStatus(ok.status)
		}
	}
	return nil
}

// resetSession applies what COM_CHANGE_USER and COM_RESET_CONNECTION do: the open
// transaction rolls back and prepared statements go.
func (s *mySession) resetSession() {
	s.tx.rollback()
	clear(s.prepared)
}

type myOKPacket struct {
	affected uint64
	status   uint16
	warnings uint16
}

// lenenc reads a length-encoded integer, and the bytes it took (0: unreadable).
func lenenc(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	var n int
	switch b[0] {
	case 0xfc:
		n = 2
	case 0xfd:
		n = 3
	case 0xfe:
		n = 8
	case 0xfb, 0xff:
		return 0, 0
	default:
		return uint64(b[0]), 1
	}
	if len(b) < 1+n {
		return 0, 0
	}
	var v uint64
	for i := n; i >= 1; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, 1 + n
}

// parseOK reads an OK packet, header byte and all.
func parseOK(p []byte) (myOKPacket, bool) {
	var ok myOKPacket
	affected, n := lenenc(p[1:])
	if n == 0 {
		return ok, false
	}
	_, m := lenenc(p[1+n:])
	if m == 0 || len(p) < 1+n+m+4 {
		return ok, false
	}
	b := p[1+n+m:]
	ok.affected = affected
	ok.status = binary.LittleEndian.Uint16(b)
	ok.warnings = binary.LittleEndian.Uint16(b[2:])
	return ok, true
}

// parseEOF reads a classic EOF packet.
func parseEOF(p []byte) (myOKPacket, bool) {
	if len(p) < 5 {
		return myOKPacket{}, false
	}
	return myOKPacket{warnings: binary.LittleEndian.Uint16(p[1:]), status: binary.LittleEndian.Uint16(p[3:])}, true
}

func (s *mySession) deprecateEOF() bool { return s.caps&myCapDeprecateEOF != 0 }

// isEnd reports whether p ends a run of rows. A row can start with 0xFE only as
// a length of 2^24 or more, so its packet is full.
func (s *mySession) isEnd(p []byte) bool {
	if p[0] != 0xfe {
		return false
	}
	if s.deprecateEOF() {
		return len(p) < myMaxPacket
	}
	return len(p) < 9
}

// parseEnd reads the packet that ends rows.
func (s *mySession) parseEnd(p []byte) (myOKPacket, bool) {
	if s.deprecateEOF() {
		return parseOK(p)
	}
	return parseEOF(p)
}

// reply applies one packet of the reply to the command at the head of the queue.
//
//subpoena:enforcement_point
func (s *mySession) reply(p []byte) error {
	if len(s.queue) == 0 {
		if len(p) > 0 && p[0] == 0xff {
			return nil // the server gives notice of an idle timeout, then closes
		}
		return s.unreadableLocked("a reply with no command waiting") //subpoena:enforcement
	}
	if len(p) == 0 {
		return s.unreadableLocked("an empty reply") //subpoena:enforcement
	}
	it := s.queue[0]
	switch it.kind {
	case myBare:
		s.pop()
		return nil
	case mySimple:
		s.pop()
		return nil
	case myResetting:
		if p[0] == 0x00 {
			s.resetSession()
			s.status = 0
			if ok, good := parseOK(p); good {
				s.status = ok.status
			}
		}
		s.pop()
		return nil
	case kindPrepare:
		return s.prepareReply(it, p)
	}
	switch it.state {
	case myFirst:
		return s.firstPacket(it, p)
	case myColumns:
		if it.n--; it.n == 0 {
			it.state = myColumnsEOF
			if s.deprecateEOF() {
				it.state = myRowData
			}
		}
		return nil
	case myColumnsEOF:
		return s.columnsEnd(it, p)
	}
	return s.rowPacket(it, p)
}

// prepareReply reads COM_STMT_PREPARE_OK, then skips the definitions after it.
//
//subpoena:enforcement_point
func (s *mySession) prepareReply(it *myItem, p []byte) error {
	if it.state == mySkip {
		if it.n--; it.n == 0 {
			s.pop()
		}
		return nil
	}
	if p[0] == 0xff {
		s.pop()
		return nil
	}
	if len(p) < 12 {
		return s.unreadableLocked("COM_STMT_PREPARE_OK of %d bytes", len(p)) //subpoena:enforcement
	}
	id := binary.LittleEndian.Uint32(p[1:])
	columns := uint64(binary.LittleEndian.Uint16(p[5:]))
	params := uint64(binary.LittleEndian.Uint16(p[7:]))
	st := onePrepared(dialectMySQL, it.text)
	s.tainted(st.taint)
	if it.cut {
		st = st.opaqued("too long to read") //subpoena:enforcement
	}
	s.prepared[id] = st
	it.n = columns + params
	if !s.deprecateEOF() {
		if columns != 0 {
			it.n++
		}
		if params != 0 {
			it.n++
		}
	}
	it.state = mySkip
	if it.n == 0 {
		s.pop()
	}
	return nil
}

// firstPacket reads the first packet of a command's reply.
//
//subpoena:enforcement_point
func (s *mySession) firstPacket(it *myItem, p []byte) error {
	switch {
	case p[0] == 0x00:
		ok, good := parseOK(p)
		if !good {
			return s.unreadableLocked("an OK of %d bytes", len(p)) //subpoena:enforcement
		}
		s.resultDone(it, ok, true)
	case p[0] == 0xff:
		s.failed(it.current())
		s.pop()
	case p[0] == 0xfb:
		s.infile = true
	case s.isEnd(p):
		ok, good := s.parseEnd(p)
		if !good {
			return s.unreadableLocked("an end packet of %d bytes", len(p)) //subpoena:enforcement
		}
		s.resultDone(it, ok, true)
	default:
		n, used := lenenc(p)
		if used == 0 || n == 0 {
			return s.unreadableLocked("a column count of %v", p[:min(len(p), 4)]) //subpoena:enforcement
		}
		it.state, it.n = myColumns, n
	}
	return nil
}

// columnsEnd reads the EOF after column definitions. A cursor's rows come later,
// by COM_STMT_FETCH, so its reply ends here.
//
//subpoena:enforcement_point
func (s *mySession) columnsEnd(it *myItem, p []byte) error {
	if p[0] == 0xff {
		s.failed(it.current())
		s.pop()
		return nil
	}
	if !s.isEnd(p) {
		return s.unreadableLocked("no EOF after the columns") //subpoena:enforcement
	}
	ok, good := parseEOF(p)
	if !good {
		return s.unreadableLocked("an EOF of %d bytes", len(p)) //subpoena:enforcement
	}
	if ok.status&myStatusCursorExists != 0 {
		s.resultDone(it, ok, false)
		return nil
	}
	it.state = myRowData
	return nil
}

// rowPacket reads one packet of rows.
//
//subpoena:enforcement_point
func (s *mySession) rowPacket(it *myItem, p []byte) error {
	switch {
	case p[0] == 0xff:
		if it.kind == myResult {
			s.failed(it.current())
		}
		s.pop()
	case s.isEnd(p):
		ok, good := s.parseEnd(p)
		if !good {
			return s.unreadableLocked("an end packet of %d bytes", len(p)) //subpoena:enforcement
		}
		if it.kind == myResult {
			s.resultDone(it, ok, false)
			return nil
		}
		s.pop()
	}
	return nil
}

func (it *myItem) current() *statement {
	if it.next < len(it.stmts) {
		return &it.stmts[it.next]
	}
	o := opaqueStatement(it.text, firstWord(it.text), "more results than statements were read")
	o.unread = true
	return &o
}

// resultDone ends one statement's result, and the command unless more follow.
func (s *mySession) resultDone(it *myItem, ok myOKPacket, hasCount bool) {
	s.apply(it.current(), ok, hasCount)
	if ok.status&myStatusMoreResults != 0 {
		it.next++
		it.state = myFirst
		return
	}
	s.pop()
}

// apply takes one finished statement into the transaction. The status flags
// decide what is committed: with no transaction open after a statement, everything
// pending has committed, whether by COMMIT, by autocommit, or implicitly by DDL.
// A ROLLBACK that leaves a warning could not undo a non-transactional table, and
// its writes stand. After a deadlock's ERR the transaction is gone with no status
// to say so, and pending writes over-report until the next flags are seen.
//
//subpoena:enforcement_point
func (s *mySession) apply(st *statement, ok myOKPacket, hasCount bool) {
	st = s.readable(st)
	switch st.tx {
	case txBegin, txCommit:
		s.tx.commit() // BEGIN commits a transaction already open
	case txRollback:
		if ok.warnings == 0 {
			s.tx.rollback()
		} else {
			s.tx.commit() //subpoena:enforcement
		}
	case txRollbackTo:
		if ok.warnings == 0 {
			s.tx.rollbackTo(st.savepoint)
		}
	case txSavepoint:
		s.tx.savepoint(st.savepoint)
	case txRelease:
		s.tx.release(st.savepoint)
	}
	switch {
	case st.mayCommit():
		s.tx.addAutonomous(st) //subpoena:enforcement
	case st.class == classOpaque:
		s.tx.add(st, witness.RowsUnknown)
	case st.class == classWrite:
		rows := int64(ok.affected)
		if st.noCount || !hasCount {
			rows = witness.RowsUnknown
		}
		s.tx.add(st, rows)
	case ok.affected != 0:
		s.tx.add(st.opaqued("changed %d rows", ok.affected), witness.RowsUnknown) //subpoena:enforcement
	default:
		s.tx.done(st, witness.RowsUnknown, witness.OutcomeRead)
	}
	s.status = ok.status
	s.noteStatus(ok.status)
	if ok.status&myStatusInTrans == 0 {
		s.tx.commit() //subpoena:enforcement
	}
}

func (s *mySession) inFlight() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) != 0
}

// finish settles the connection once both directions have ended, as pgSession's
// does. A client that read the greeting and left without answering may have
// wanted the TLS the greeting no longer offered. So may a port probe: it cannot
// be told apart from here, and the safe reading is the one that says so.
//
//subpoena:enforcement_point
func (s *mySession) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.phase == phaseResponse:
		s.cap.fault("connection %d: the client left at the greeting; it may insist on TLS, and its traffic was not proxied", s.id) //subpoena:enforcement
	case s.blind:
		s.settleInFlight()
		s.tx.abandon() //subpoena:enforcement
	case len(s.queue) != 0 || s.status&myStatusInTrans != 0 || len(s.tx.pending) != 0:
		if s.terminated && len(s.queue) == 0 {
			s.tx.rollback()
			return
		}
		s.cap.fault("connection %d: dropped mid-transaction (status %#x, %d replies owed, %d writes open)", s.id, s.status, len(s.queue), len(s.tx.pending)) //subpoena:enforcement
		s.settleInFlight()
		s.tx.abandon() //subpoena:enforcement
	}
}

// settleInFlight adds the writes the server never answered for, so that they are
// reported as unknown.
func (s *mySession) settleInFlight() {
	for _, it := range s.queue {
		for i := it.next; i < len(it.stmts); i++ {
			if st := &it.stmts[i]; st.class == classWrite || st.class == classOpaque {
				s.tx.add(st, witness.RowsUnknown)
			}
		}
	}
	s.queue = nil
}
