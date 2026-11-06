package dbproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// maxStatementText bounds the SQL kept per event. Parsing sees all of it.
const maxStatementText = 8 << 10

// capture is what one witness has seen, across its connections.
type capture struct {
	engine string
	dest   netip.AddrPort

	mu          sync.Mutex
	events      []witness.RowEvent // in the order their outcome became known
	mark        int                // events before this index are hidden from Committed
	faults      []string
	connections int
	tlsRefused  int
	tlsLeft     []int // connections that asked for TLS, were told no, and left
	plainStarts int   // connections that started in the clear without asking
	stopped     bool
	enc         *json.Encoder // nil without Config.Output
}

// fault records a capture fault. Any fault fails Health for the whole capture:
// a connection the witness lost could have held any statement.
//
//subpoena:enforcement_point
func (c *capture) fault(format string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.faults = append(c.faults, fmt.Sprintf(format, a...)) //subpoena:enforcement
}

func (c *capture) noteConnection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connections++
}

func (c *capture) noteTLSRefused() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tlsRefused++
}

// noteTLSLeft keeps a connection that was refused TLS and left. Whether that
// means anything is decided at close: see close.
func (c *capture) noteTLSLeft(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tlsLeft = append(c.tlsLeft, id)
}

func (c *capture) notePlainStart() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.plainStarts++
}

// record keeps e and writes it out, if there is a file.
//
//subpoena:enforcement_point
func (c *capture) record(e witness.RowEvent) {
	e.Attribution = witness.ByDestination
	e.Engine, e.Dest = c.engine, c.dest
	if len(e.Statement) > maxStatementText {
		e.Statement = e.Statement[:maxStatementText] + "..."
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	if c.enc == nil {
		return
	}
	if err := c.enc.Encode(witness.RowLineOf(e)); err != nil {
		c.faults = append(c.faults, fmt.Sprintf("writing the witness file: %v", err)) //subpoena:enforcement
	}
}

// open starts the witness file, if there is one.
func (c *capture) open(w io.Writer) error {
	if w == nil {
		return nil
	}
	c.enc = json.NewEncoder(w)
	return c.enc.Encode(witness.Record{Time: time.Now().UTC(), Record: witness.RecordStart})
}

// close ends the capture, and the file with a stop record carrying its health.
//
// A client that was refused TLS and left may have insisted on it, or may be pgx
// with sslmode=prefer, which redials in the clear. Each plain connection answers
// for one such departure; any left over insisted.
//
//subpoena:enforcement_point
func (c *capture) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true
	if len(c.tlsLeft) > c.plainStarts {
		c.faults = append(c.faults, fmt.Sprintf("%d connections left when TLS was refused, and no plain connection followed: a client insists on TLS, and its traffic was not proxied", len(c.tlsLeft)-c.plainStarts)) //subpoena:enforcement
	}
	if c.enc == nil {
		return
	}
	stop := witness.Record{Time: time.Now().UTC(), Record: witness.RecordStop, Healthy: len(c.faults) == 0}
	if !stop.Healthy {
		stop.Error = c.faults[0]
	}
	if err := c.enc.Encode(stop); err != nil {
		c.faults = append(c.faults, fmt.Sprintf("writing the witness file: %v", err)) //subpoena:enforcement
	}
}

func (c *capture) snapshot() []witness.RowEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]witness.RowEvent(nil), c.events...)
}

func (c *capture) faultList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.faults...)
}

func (c *capture) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

// setMark hides what has committed so far from committed.
func (c *capture) setMark() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mark = len(c.events)
}

func (c *capture) committed() []witness.RowEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []witness.RowEvent
	for _, e := range c.events[c.mark:] {
		if e.Outcome == witness.OutcomeCommitted {
			out = append(out, e)
		}
	}
	return out
}

// alwaysMissed is true of every capture.
var alwaysMissed = []string{
	"connections that do not go through this listener",
	"rows written by triggers, rules and foreign-key actions, on tables the statement does not name",
	"rows changed by a statement that reports zero rows, such as an insert a trigger redirected",
	"the bound values of a statement: it sees that a table was written, not with what",
	"routines installed before the capture that read as something else: a view over a writing function, an overload of a listed function, operator or cast for other argument types",
	"work a function on another connection committed, such as dblink inside a statement that then failed",
}

func (c *capture) coverage() witness.DBCoverage {
	c.mu.Lock()
	defer c.mu.Unlock()
	cov := witness.DBCoverage{
		Connections: c.connections,
		TLSRefused:  c.tlsRefused,
		Faults:      append([]string(nil), c.faults...),
		Missed:      append([]string(nil), alwaysMissed...),
	}
	for _, e := range c.events {
		cov.Statements++
		if e.Opaque {
			cov.Opaque++
		}
		switch e.Outcome {
		case witness.OutcomeCommitted:
			cov.Committed++
			if e.Rows == 0 {
				cov.ZeroRow++
			}
		case witness.OutcomeRolledBack:
			cov.RolledBack++
		case witness.OutcomeFailed:
			if len(e.Tables) != 0 || e.Opaque {
				cov.Failed++
			}
		case witness.OutcomeUnknown:
			cov.Unknown++
		}
	}
	if len(c.faults) != 0 {
		cov.Missed = append(cov.Missed, fmt.Sprintf("anything on the connections behind the %d capture faults", len(c.faults)))
	}
	if !c.stopped {
		cov.Missed = append(cov.Missed, "anything after this report: the capture has not stopped")
	}
	return cov
}

// txLog is one connection's transaction: writes the server has done but not yet
// committed, with the savepoints between them. Nothing here reads the wire;
// each protocol tells it what the server said.
type txLog struct {
	cap        *capture
	conn       int
	pending    []pendingRow
	savepoints []savepoint
}

// pendingRow is a write waiting for its transaction. autonomous marks a routine
// that ran where it could commit by itself: the end of the transaction around it
// does not decide what it did.
type pendingRow struct {
	witness.RowEvent
	autonomous bool
}

type savepoint struct {
	name string
	mark int // len(pending) when it was set
}

func (t *txLog) event(st *statement, rows int64, o witness.Outcome) witness.RowEvent {
	return witness.RowEvent{
		Conn: t.conn, Statement: st.text, Verb: st.verb, Tables: st.tables,
		Opaque: st.class == classOpaque, Reason: st.reason,
		Rows: rows, Outcome: o, SeenAt: time.Now().UTC(),
	}
}

// done records a statement whose outcome is already final.
func (t *txLog) done(st *statement, rows int64, o witness.Outcome) {
	t.cap.record(t.event(st, rows, o))
}

// add holds a write the server has done, until its transaction ends.
func (t *txLog) add(st *statement, rows int64) {
	t.pending = append(t.pending, pendingRow{RowEvent: t.event(st, rows, witness.OutcomeUnknown)})
}

// addAutonomous holds a routine that may have committed by itself.
func (t *txLog) addAutonomous(st *statement) {
	t.pending = append(t.pending, pendingRow{RowEvent: t.event(st, witness.RowsUnknown, witness.OutcomeUnknown), autonomous: true})
}

// unknown records a statement that ended in failure after it could have committed
// work of its own. Neither "failed" nor "committed" would be proof; the capture
// cannot certify absence.
//
//subpoena:enforcement_point
func (t *txLog) unknown(st *statement) {
	t.cap.fault("connection %d: %s failed where it could have committed part of its work", t.conn, st.verb) //subpoena:enforcement
	t.done(st, witness.RowsUnknown, witness.OutcomeUnknown)
}

//subpoena:enforcement_point
func (t *txLog) settle(from int, o witness.Outcome) {
	for _, p := range t.pending[from:] {
		e := p.RowEvent
		e.Outcome = o
		if p.autonomous && o == witness.OutcomeRolledBack {
			e.Outcome = witness.OutcomeUnknown //subpoena:enforcement
			t.cap.fault("connection %d: %s was rolled back after it could have committed part of its work", t.conn, e.Verb)
		}
		t.cap.record(e)
	}
	t.pending = t.pending[:from]
}

func (t *txLog) commit() {
	t.settle(0, witness.OutcomeCommitted)
	t.savepoints = nil
}

func (t *txLog) rollback() {
	t.settle(0, witness.OutcomeRolledBack)
	t.savepoints = nil
}

// abandon ends the transaction with its outcome unseen.
func (t *txLog) abandon() {
	t.settle(0, witness.OutcomeUnknown)
	t.savepoints = nil
}

func (t *txLog) savepoint(name string) {
	t.savepoints = append(t.savepoints, savepoint{name, len(t.pending)})
}

// find returns the index of the newest savepoint called name, or -1.
func (t *txLog) find(name string) int {
	for i := len(t.savepoints) - 1; i >= 0 && name != ""; i-- {
		if t.savepoints[i].name == name {
			return i
		}
	}
	return -1
}

// rollbackTo undoes the writes since the savepoint, which stays set. A savepoint
// it does not know undoes nothing: every write stays pending, the safe direction.
func (t *txLog) rollbackTo(name string) {
	if i := t.find(name); i >= 0 {
		t.settle(t.savepoints[i].mark, witness.OutcomeRolledBack)
		t.savepoints = t.savepoints[:i+1]
	}
}

func (t *txLog) release(name string) {
	if i := t.find(name); i >= 0 {
		t.savepoints = t.savepoints[:i]
	}
}
