package witness

import (
	"net/netip"
	"strings"
	"time"
)

// Outcome says what became of a statement a database witness saw.
type Outcome string

const (
	// OutcomeRead is a statement that writes nothing: a read, or a transaction
	// or session command.
	OutcomeRead Outcome = "read"
	// OutcomeCommitted is a write the server reported committed: an autocommit
	// statement that succeeded, or a write in a transaction that committed.
	OutcomeCommitted Outcome = "committed"
	// OutcomeRolledBack is a write the server accepted and then undid. It is not
	// an effect.
	OutcomeRolledBack Outcome = "rolled_back"
	// OutcomeFailed is a statement the server refused. It is not an effect. A
	// routine that could have committed part way gets OutcomeUnknown instead.
	OutcomeFailed Outcome = "failed"
	// OutcomeUnknown is a write whose fate the witness did not see: the
	// connection dropped, or was unreadable, with it still open. Health fails
	// whenever a capture holds one.
	OutcomeUnknown Outcome = "unknown"
)

// RowsUnknown is RowEvent.Rows when the server's reply gave no usable count.
const RowsUnknown int64 = -1

// RowEvent is one statement a database witness saw on the wire.
type RowEvent struct {
	Engine    string         // "postgres" or "mysql"
	Conn      int            // the witness's number for the connection, from 1
	Dest      netip.AddrPort // the address the application connected to
	Statement string         // SQL text as sent, cut if very long; never bound values
	Verb      string         // first keyword, upper case
	// Tables are the tables written, each as its name was written with quotes
	// removed and unquoted parts lower case: users, public.users.
	Tables []string
	// Opaque means the witness could not tell what the statement writes, so it
	// counts against every table. Reason says why.
	Opaque bool
	Reason string
	// Rows is the count of rows the server said it changed, or RowsUnknown.
	Rows        int64
	Outcome     Outcome
	Attribution Attribution
	SeenAt      time.Time
}

// Effect reports whether e changed the database, as far as the wire can say: a
// committed write of any number of rows other than zero. An unknown count is an
// effect. Zero is not, so DELETE ... WHERE owner = $1 refusing by matching
// nothing passes a no-row claim.
func (e RowEvent) Effect() bool {
	return e.Outcome == OutcomeCommitted && e.Rows != 0
}

// Touches reports whether e counts against table. The empty table is every
// table. An opaque event, or one naming no table, counts against every table.
// Names compare without case, on their dotted parts from the right, so users
// and public.users match each other and other.users matches neither way with
// public.users. Case and a missing schema are both resolved towards a match:
// over-reporting is the safe direction.
func (e RowEvent) Touches(table string) bool {
	if table == "" || e.Opaque || len(e.Tables) == 0 {
		return true
	}
	for _, t := range e.Tables {
		if sameTable(t, table) {
			return true
		}
	}
	return false
}

func sameTable(a, b string) bool {
	as := strings.Split(strings.ToLower(a), ".")
	bs := strings.Split(strings.ToLower(b), ".")
	for len(as) > 0 && len(bs) > 0 {
		if as[len(as)-1] != bs[len(bs)-1] {
			return false
		}
		as, bs = as[:len(as)-1], bs[:len(bs)-1]
	}
	return true
}

// DBWitness reports the writes a database committed. It is a sibling of Witness
// and NetworkWitness, under the same rules: independent of the application,
// over-reporting rather than under-reporting, and able to certify absence only
// through HealthReporter.
//
// Attribution is by destination, as with Sinkhole. The witness sees a socket,
// not a request: the harness drives one request at a time, so every statement
// holds for every trace.
type DBWitness interface {
	// Committed returns the writes committed on behalf of traceID, zero-row ones
	// included (see RowEvent.Effect). A rolled-back or refused write is not
	// here. Implementations must err toward over-reporting.
	Committed(traceID string) []RowEvent
}

// DBCoverage says what a database witness saw and what it may have missed. Log
// it next to an absence claim. A witness nothing connected to has Connections
// 0: pair a no-row claim with a positive control, as with Sinkhole, so an
// application pointed elsewhere cannot pass for the wrong reason.
type DBCoverage struct {
	Connections int // accepted from the application, cancel requests aside
	TLSRefused  int // connections told no at a TLS offer, which then went on in the clear
	Statements  int // every statement the server answered
	Committed   int // writes that committed, zero-row ones included
	ZeroRow     int // of Committed, those the server said changed no rows
	RolledBack  int // writes undone
	Failed      int // writes refused
	Unknown     int // writes with no seen outcome; these fail Health
	Opaque      int // statements counted against every table
	// Faults are the capture faults; Health fails if there are any.
	Faults []string
	// Missed says in words what this witness may have missed, in this capture
	// and in every capture.
	Missed []string
}
