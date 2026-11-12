package dbproxy

import (
	"fmt"
	"strings"
)

// dialect picks the lexical rules: PostgreSQL and MySQL disagree on what quotes
// mean, on backslashes, and on comments.
type dialect int

const (
	dialectPostgres dialect = iota
	dialectMySQL
)

func (d dialect) String() string {
	if d == dialectMySQL {
		return "mysql"
	}
	return "postgres"
}

// class says what a statement can do to rows.
type class int

const (
	classRead   class = iota // writes nothing
	classWrite               // writes statement.tables
	classOpaque              // may write anything; counts against every table
	classTx                  // transaction control
)

func (c class) String() string {
	return [...]string{"read", "write", "opaque", "tx"}[c]
}

// txOp is the transaction command a statement is.
type txOp int

const (
	txNone txOp = iota
	txBegin
	txCommit
	txRollback
	txSavepoint
	txRollbackTo
	txRelease
	txPrepare // PREPARE TRANSACTION
)

// statement is one SQL statement as far as text can say. The server's reply has
// the last word on whether it ran and what it changed.
type statement struct {
	text      string
	verb      string
	class     class
	tables    []string
	reason    string // why it is opaque
	noCount   bool   // the server's count says nothing about rows
	tx        txOp
	savepoint string
	dialect   dialect
	unread    bool   // no parser finished the text: it could hold anything
	atomic    bool   // opaque, but it cannot be a routine that commits
	taint     string // why the session's lexing or name lookup can't be followed after this
	forget    string // a server-side prepared name this ends or replaces; "*" is all of them
}

// opaqueStatement is a statement that counts against every table.
func opaqueStatement(text, verb, format string, a ...any) statement {
	return statement{text: text, verb: verb, class: classOpaque, reason: fmt.Sprintf(format, a...)}
}

// opaqued is st as a statement that counts against every table.
func (st *statement) opaqued(format string, a ...any) *statement {
	o := opaqueStatement(st.text, st.verb, format, a...)
	o.unread, o.taint, o.forget = st.unread, st.taint, st.forget
	return &o
}

// atomicVerbs start statements that run whole inside one transaction, whatever
// they call. Any other opaque statement may be a routine that commits part way
// (CALL, DO, MySQL's EXECUTE), so its failure proves nothing about what stayed.
var atomicVerbs = map[string]bool{"SELECT": true, "VALUES": true, "TABLE": true, "WITH": true, "INSERT": true,
	"REPLACE": true, "UPDATE": true, "DELETE": true, "MERGE": true, "TRUNCATE": true, "COPY": true, "LOAD": true,
	"EXPLAIN": true, "DESCRIBE": true, "DESC": true, "SET": true, "DECLARE": true, "FUNCTION CALL": true}

// mayCommit reports whether st could have committed work of its own before it
// ended, so that neither its failure nor a later rollback says the work is gone.
//
//subpoena:enforcement_point
func (st *statement) mayCommit() bool {
	if st.class == classOpaque && !st.atomic && (st.unread || !atomicVerbs[st.verb]) {
		return true //subpoena:enforcement
	}
	return false
}

type tokenKind int

const (
	tokWord   tokenKind = iota // keyword or unquoted identifier; up is its upper case
	tokQuoted                  // quoted identifier
	tokString                  // string literal
	tokNumber
	tokPunct
)

type token struct {
	kind tokenKind
	text string
	up   string
	pos  int
}

func (t token) is(words ...string) bool {
	if t.kind != tokWord {
		return false
	}
	for _, w := range words {
		if t.up == w {
			return true
		}
	}
	return false
}

func (t token) punct(p string) bool { return t.kind == tokPunct && t.text == p }

// parseSQL splits text into statements and classifies each. Text the tokenizer
// cannot finish comes back as one opaque statement: where the statements in it
// end cannot be told.
//
//subpoena:enforcement_point
func parseSQL(d dialect, text string) []statement {
	toks, err := tokenize(d, text)
	if err != nil {
		o := opaqueStatement(text, firstWord(text), "cannot tokenize: %v", err)
		o.unread, o.forget, o.taint = true, "*", tokenizeTaint(text)
		return []statement{o} //subpoena:enforcement
	}
	var out []statement
	depth, start := 0, 0
	flush := func(end int) {
		if end > start {
			st := classify(d, text, toks[start:end])
			if st.taint == "" && d == dialectPostgres {
				st.taint = pgConfigTaint(toks[start:end])
			}
			out = append(out, st)
		}
		start = end + 1
	}
	for i, t := range toks {
		switch {
		case t.punct("("):
			depth++
		case t.punct(")"):
			depth--
		case t.punct(";") && depth <= 0:
			flush(i)
		}
	}
	flush(len(toks))
	return out
}

// unseenStatement stands for a prepared statement or portal the protocol named
// and the witness has no record of. It saw every prepare on the connection, so
// the server has none either, or holds a SQL-level PREPARE, which can't hold a
// routine that commits.
func unseenStatement(format string, a ...any) *statement {
	o := opaqueStatement("", "EXECUTE", format, a...)
	o.atomic = true
	return &o
}

// firstWord is the leading word of text, for labelling a statement that did not
// tokenize.
func firstWord(text string) string {
	f := strings.Fields(text)
	if len(f) == 0 {
		return ""
	}
	return strings.ToUpper(f[0])
}

func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isWordByte(c byte) bool {
	return isWordStart(c) || (c >= '0' && c <= '9') || c == '$'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// tokenizeTaint is the taint of text the witness could not read: it may still
// have changed how the session reads what comes next. A SET in it counts whatever
// it names, since the name may be the part that could not be read: U&"search\005fpath".
//
//subpoena:enforcement_point
func tokenizeTaint(text string) string {
	up := strings.ToUpper(text)
	for _, w := range []string{"STANDARD_CONFORMING_STRINGS", "CLIENT_ENCODING", "SEARCH_PATH", "SQL_MODE", "NAMES", "CHARSET", "CHARACTER", "SET_CONFIG"} {
		if strings.Contains(up, w) {
			return "text that did not tokenize mentions " + strings.ToLower(w) //subpoena:enforcement
		}
	}
	for _, w := range strings.FieldsFunc(up, func(r rune) bool { return r >= 0x80 || !isWordByte(byte(r)) }) {
		if w == "SET" {
			return "text that did not tokenize holds a SET" //subpoena:enforcement
		}
	}
	return ""
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
