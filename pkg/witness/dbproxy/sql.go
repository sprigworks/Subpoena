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

// tokenize reads text into tokens, dropping comments. An error means the text
// ends inside a comment or quote, or holds something that only looks like a
// comment: MySQL runs what is inside /*! ... */. Each helper leaves the end of
// the text as its position on failure, so the loop always ends.
//
//subpoena:enforcement_point
func tokenize(d dialect, s string) ([]token, error) {
	var out []token
	var bad error
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case isSpace(c):
			i++
		case c == 0 && d == dialectMySQL:
			bad = fmt.Errorf("a NUL byte at %d", i) //subpoena:enforcement
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-' && (d == dialectPostgres || i+2 >= len(s) || s[i+2] <= ' ' || s[i+2] == 0x7f):
			end := lineEnd(d, s, i)
			if d == dialectMySQL && strings.IndexByte(s[i:end], 0) >= 0 {
				bad = fmt.Errorf("a NUL byte in a comment at %d", i) //subpoena:enforcement
			}
			i = end
		case c == '#' && d == dialectMySQL:
			end := lineEnd(d, s, i)
			if strings.IndexByte(s[i:end], 0) >= 0 {
				bad = fmt.Errorf("a NUL byte in a comment at %d", i) //subpoena:enforcement
			}
			i = end
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			if d == dialectMySQL && (strings.HasPrefix(s[i:], "/*!") || strings.HasPrefix(s[i:], "/*M!")) {
				bad = fmt.Errorf("a comment MySQL executes at %d", i) //subpoena:enforcement
			}
			end, err := commentEnd(d, s, i)
			if err != nil {
				bad = err //subpoena:enforcement
			}
			i = end
		case c == '\'':
			escapes := d == dialectMySQL || escapePrefix(s, i)
			end, err := quoteEnd(s, i, '\'', escapes)
			if err != nil {
				bad = err //subpoena:enforcement
			}
			if d == dialectPostgres && unicodePrefix(s, i) {
				bad = fmt.Errorf("a U& string at %d", i) //subpoena:enforcement
			}
			if d == dialectPostgres && escapes && continues(s, end) {
				bad = fmt.Errorf("an E string continued on another line at %d", i) //subpoena:enforcement
			}
			out = append(out, token{kind: tokString, text: s[i:end], pos: i})
			i = end
		case c == '"' && d == dialectMySQL:
			end, err := quoteEnd(s, i, '"', true)
			if err != nil {
				bad = err //subpoena:enforcement
			}
			out = append(out, token{kind: tokString, text: s[i:end], pos: i})
			i = end
		case c == '"' || (c == '`' && d == dialectMySQL):
			end, err := quoteEnd(s, i, c, false)
			if err != nil {
				bad = err //subpoena:enforcement
			}
			if d == dialectPostgres && unicodePrefix(s, i) {
				bad = fmt.Errorf("a U& identifier at %d", i) //subpoena:enforcement
			}
			name := strings.ReplaceAll(s[i+1:max(end-1, i+1)], string([]byte{c, c}), string(c))
			out = append(out, token{kind: tokQuoted, text: name, pos: i})
			i = end
		case c == '$' && d == dialectPostgres && dollarTag(s, i) != "":
			tag := dollarTag(s, i)
			next := len(s)
			if end := strings.Index(s[i+len(tag):], tag); end >= 0 {
				next = i + len(tag) + end + len(tag)
			} else {
				bad = fmt.Errorf("unterminated dollar quote at %d", i) //subpoena:enforcement
			}
			out = append(out, token{kind: tokString, text: s[i:next], pos: i})
			i = next
		case isWordStart(c):
			end := i
			for end < len(s) && isWordByte(s[end]) {
				end++
			}
			out = append(out, token{kind: tokWord, text: s[i:end], up: strings.ToUpper(s[i:end]), pos: i})
			i = end
		case isDigit(c):
			end := i
			for end < len(s) && (isWordByte(s[end]) || s[end] == '.') && (s[end] != '$' || d == dialectMySQL) {
				end++
			}
			out = append(out, token{kind: tokNumber, text: s[i:end], pos: i})
			i = end
		default:
			out = append(out, token{kind: tokPunct, text: s[i : i+1], pos: i})
			i++
		}
	}
	return out, bad
}

// lineEnd finds the end of the line comment at i. PostgreSQL's lexer ends one at
// a carriage return as well; MySQL's does not.
func lineEnd(d dialect, s string, i int) int {
	ends := "\n"
	if d == dialectPostgres {
		ends = "\r\n"
	}
	if n := strings.IndexAny(s[i:], ends); n >= 0 {
		return i + n + 1
	}
	return len(s)
}

// commentEnd finds the end of the /* comment at i. PostgreSQL's nest.
func commentEnd(d dialect, s string, i int) (int, error) {
	depth := 0
	for j := i; j+1 < len(s); {
		switch {
		case s[j] == '/' && s[j+1] == '*' && (depth == 0 || d == dialectPostgres):
			depth++
			j += 2
		case s[j] == '*' && s[j+1] == '/':
			depth--
			j += 2
			if depth == 0 {
				return j, nil
			}
		default:
			j++
		}
	}
	return len(s), fmt.Errorf("unterminated comment at %d", i)
}

// quoteEnd finds the end of the quoted text at i, past a doubled quote and, if
// escapes is set, past a backslash escape.
func quoteEnd(s string, i int, q byte, escapes bool) (int, error) {
	for j := i + 1; j < len(s); j++ {
		switch {
		case s[j] == '\\' && escapes:
			j++
		case s[j] == q && j+1 < len(s) && s[j+1] == q:
			j++
		case s[j] == q:
			return j + 1, nil
		}
	}
	return len(s), fmt.Errorf("unterminated quote at %d", i)
}

// escapePrefix reports whether the quote at i opens a PostgreSQL E” string.
func escapePrefix(s string, i int) bool {
	return i > 0 && (s[i-1] == 'E' || s[i-1] == 'e') && (i == 1 || !isWordByte(s[i-2]))
}

// unicodePrefix reports whether the quote at i opens a U&” string or U&""
// identifier. Its text is not what it spells: U&"\0075sers" is users.
func unicodePrefix(s string, i int) bool {
	return i > 1 && s[i-1] == '&' && (s[i-2] == 'U' || s[i-2] == 'u') && (i == 2 || !isWordByte(s[i-3]))
}

// continues reports whether a quote follows i past blanks and line comments: the
// server reads that as more of the same string, escapes included.
func continues(s string, i int) bool {
	for i < len(s) {
		switch {
		case isSpace(s[i]):
			i++
		case strings.HasPrefix(s[i:], "--"):
			i = lineEnd(dialectPostgres, s, i)
		default:
			return s[i] == '\''
		}
	}
	return false
}

// dollarTag returns the $tag$ opening at i, or "" if there is none: $1 is a
// parameter.
func dollarTag(s string, i int) string {
	for j := i + 1; j < len(s); j++ {
		switch {
		case s[j] == '$':
			return s[i : j+1]
		case !isWordByte(s[j]) || (j == i+1 && isDigit(s[j])):
			return ""
		}
	}
	return ""
}

// classify says what one statement's tokens can do. Its grammar is strict on
// purpose: every form it does not know is opaque, so the cost of a gap is a
// false alarm, never a missed write.
//
//subpoena:enforcement_point
func classify(d dialect, text string, toks []token) statement {
	st := statement{text: stmtText(text, toks), dialect: d}
	if d == dialectPostgres {
		var bad bool
		if toks, bad = clipNames(toks); bad {
			o := opaqueStatement(st.text, firstWord(st.text), "a long name the server's encoding decides how to cut")
			o.taint = tokenizeTaint(st.text)
			return o //subpoena:enforcement
		}
	}
	first := 0
	for first < len(toks) && toks[first].punct("(") {
		first++
	}
	if first == len(toks) || toks[first].kind != tokWord {
		return opaqueStatement(st.text, "", "does not start with a keyword") //subpoena:enforcement
	}
	st.verb = toks[first].up
	rest := toks[first+1:]
	switch st.verb {
	case "SET":
		return setStatement(st, toks, rest)
	case "SELECT", "VALUES", "TABLE", "WITH", "DECLARE":
		return readOnly(st, toks)
	case "DEALLOCATE", "DISCARD":
		st.forget = forgotten(rest)
		return st
	case "SHOW", "USE", "LISTEN", "UNLISTEN", "NOTIFY",
		"FETCH", "MOVE", "CLOSE", "LOCK", "UNLOCK", "RESET", "CHECKPOINT", "VACUUM", "ANALYZE":
		return st
	case "EXPLAIN", "DESCRIBE", "DESC":
		return explain(st, rest)
	case "PREPARE":
		if len(rest) > 0 && rest[0].is("TRANSACTION") {
			st.class, st.tx = classTx, txPrepare
			return st
		}
		st.forget = forgotten(rest)
		return st // the statement runs at EXECUTE, which is opaque
	case "START":
		if len(rest) == 0 || !rest[0].is("TRANSACTION") {
			return opaqueStatement(st.text, st.verb, "START of something other than a transaction") //subpoena:enforcement
		}
		st.class, st.tx = classTx, txBegin
		return st
	case "BEGIN":
		st.class, st.tx = classTx, txBegin
		return st
	case "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT", "RELEASE":
		return txCommand(st, rest)
	case "INSERT", "REPLACE":
		return insert(st, toks[first:])
	case "UPDATE":
		return update(st, toks[first:])
	case "DELETE":
		return deleteFrom(st, toks[first:])
	case "MERGE":
		return merge(st, rest)
	case "TRUNCATE":
		return truncate(st, rest)
	case "COPY":
		return copyStmt(st, rest)
	case "LOAD":
		return loadData(st, rest)
	case "CREATE", "DROP", "ALTER":
		return ddl(st, rest)
	}
	st = opaqueStatement(st.text, st.verb, "unrecognised statement") //subpoena:enforcement
	return st
}

// pgMaxName is the most bytes of a name PostgreSQL keeps (NAMEDATALEN-1). It cuts
// the rest without complaint, quoted or not.
const pgMaxName = 63

// clipNames applies the server's cut to every name, so a write is recorded under
// the table it reached. Where a cut lands in a non-ASCII name depends on the
// server's encoding, which the text does not say: bad is true.
//
//subpoena:enforcement_point
func clipNames(toks []token) (out []token, bad bool) {
	out = toks
	for i, t := range toks {
		if (t.kind != tokWord && t.kind != tokQuoted) || len(t.text) <= pgMaxName {
			continue
		}
		if strings.IndexFunc(t.text, func(r rune) bool { return r >= 0x80 }) >= 0 {
			return nil, true //subpoena:enforcement
		}
		if &out[0] == &toks[0] {
			out = append([]token(nil), toks...)
		}
		t.text = t.text[:pgMaxName] //subpoena:enforcement
		out[i] = t
	}
	return out, false
}

// forgotten is the name a PREPARE or DEALLOCATE acts on, or "*" for all of them
// or a name it cannot read.
func forgotten(rest []token) string {
	i := skip(rest, 0, "PREPARE")
	name, _, ok := tableName(rest, i)
	if !ok || rest[i].is("ALL") {
		return "*"
	}
	return name
}

// pgExplainOptions are the options of EXPLAIN's list that only change its report.
var pgExplainOptions = wordSet("VERBOSE COSTS SETTINGS GENERIC_PLAN BUFFERS WAL TIMING SUMMARY MEMORY SERIALIZE FORMAT")

// explain reads EXPLAIN and its MySQL spellings. Only a plain EXPLAIN stays a
// read: ANALYZE runs the statement, and an option list in any form this does not
// read could be saying so. Planning can fold a function, so calls still count.
//
//subpoena:enforcement_point
func explain(st statement, rest []token) statement {
	i := 0
	if st.dialect == dialectPostgres && len(rest) > 0 && rest[0].punct("(") {
		i = pastParens(rest, 0)
		for j := 1; j < i-1; {
			if rest[j].kind != tokWord || !pgExplainOptions[rest[j].up] {
				return opaqueStatement(st.text, st.verb, "an EXPLAIN option it cannot read") //subpoena:enforcement
			}
			j++
			if j < i-1 && !rest[j].punct(",") {
				j++ // the option's value
			}
			if j < i-1 && !rest[j].punct(",") {
				return opaqueStatement(st.text, st.verb, "an EXPLAIN option it cannot read") //subpoena:enforcement
			}
			j++
		}
	}
	for _, t := range rest[i:] {
		if t.is("ANALYZE", "ANALYSE") {
			return opaqueStatement(st.text, st.verb, "EXPLAIN ANALYZE runs the statement") //subpoena:enforcement
		}
	}
	return checked(st, rest[i:])
}

func stmtText(text string, toks []token) string {
	last := toks[len(toks)-1]
	return text[toks[0].pos : last.pos+tokenLen(text, last)]
}

// tokenLen is t's length in text. A quoted identifier's text has lost its
// quotes, and maybe an escape.
func tokenLen(text string, t token) int {
	if t.kind != tokQuoted {
		return len(t.text)
	}
	q := text[t.pos]
	for j := t.pos + 1; j < len(text); j++ {
		if text[j] == q {
			if j+1 < len(text) && text[j+1] == q {
				j++
				continue
			}
			return j + 1 - t.pos
		}
	}
	return len(text) - t.pos
}

// readOnly is the check for a statement that reads in form. It stays a read only
// if nothing in it can write: no write keyword (a data-modifying WITH), no INTO,
// nothing it cannot prove leaves rows alone.
//
//subpoena:enforcement_point
func readOnly(st statement, toks []token) statement {
	for i, t := range toks {
		switch {
		case t.is("INTO"):
			return opaqueStatement(st.text, st.verb, "writes INTO") //subpoena:enforcement
		case t.is("INSERT", "DELETE", "MERGE", "TRUNCATE"),
			t.is("UPDATE") && !(i > 0 && toks[i-1].is("FOR", "KEY")),
			t.is("REPLACE") && !(i+1 < len(toks) && toks[i+1].punct("(")):
			return opaqueStatement(st.text, st.verb, "a write inside a %s", st.verb) //subpoena:enforcement
		}
	}
	return checked(st, toks)
}

// checked finishes a statement: what it calls may write elsewhere.
//
//subpoena:enforcement_point
func checked(st statement, rest []token) statement {
	if why := unproven(&st, rest); why != "" {
		return opaqueStatement(st.text, st.verb, "%s", why) //subpoena:enforcement
	}
	return st
}

// unproven says why toks may run code that is not known to leave rows alone, or
// "". Everything the server can resolve to a routine is denied unless shown
// otherwise, and the application owns the names of routines, so the proof has to
// be one the application cannot arrange. What stays out of reach is in
// witnesses/README.md: an overload of a listed name, or a function called as a.b,
// installed before the capture looks the same as the built-in or the column.
func unproven(st *statement, toks []token) string {
	if name := unknownCall(st.dialect, toks); name != "" {
		return "calls " + name + ", which may write"
	}
	if st.dialect == dialectPostgres {
		return pgHidden(toks)
	}
	return ""
}

// unknownCall returns the first name called in toks that is not known to leave
// rows alone, or "".
//
//subpoena:enforcement_point
func unknownCall(d dialect, toks []token) string {
	for i := 0; i+1 < len(toks); i++ {
		t := toks[i]
		if !toks[i+1].punct("(") {
			continue
		}
		// MySQL's names may start with a digit, and a quoted name is not the
		// keyword or built-in it spells: neither is on any list below.
		if t.kind == tokString || t.kind == tokPunct {
			continue
		}
		if i > 0 && toks[i-1].punct(".") {
			if d != dialectPostgres || !catalogName(toks, i) || !pgSafeFuncs[t.up] {
				return t.text //subpoena:enforcement
			}
			continue
		}
		if notCall(d, toks, i) {
			continue
		}
		if !safeCall(d, toks, i) {
			return t.text //subpoena:enforcement
		}
	}
	return ""
}

// catalogName reports whether the name at i is written pg_catalog.name, with
// nothing before that.
func catalogName(toks []token, i int) bool {
	return i >= 2 && toks[i-2].is("PG_CATALOG") && (i == 2 || !toks[i-3].punct("."))
}

// safeCall reports whether the bare name at i is a listed built-in. In MySQL a
// built-in always beats a stored function of that name, but count (1) with a
// space is the stored function: the name and the parenthesis must touch.
func safeCall(d dialect, toks []token, i int) bool {
	t := toks[i]
	if d == dialectMySQL {
		return mySafeFuncs[t.up] && t.pos+len(t.text) == toks[i+1].pos
	}
	return pgSafeFuncs[t.up]
}

// notCall reports whether the word at i, followed by a parenthesis, cannot be a
// call: the server's grammar does not let that word name a function, or the words
// around it put it where no expression can start. Any other word is a name,
// whatever it looks like, so each excuse below is one exact position.
func notCall(d dialect, toks []token, i int) bool {
	t := toks[i]
	if (d == dialectPostgres && pgReserved[t.up]) || (d == dialectMySQL && myReserved[t.up]) {
		return true
	}
	if i == 0 {
		return t.is("SET", "VALUE") // the head of what follows an UPDATE or INSERT target
	}
	prev := toks[i-1]
	switch {
	case prev.is("AS", "REFERENCES"), cteColumns(toks, i):
		return true // an alias's column list, a table's columns, a WITH item's columns
	case d == dialectMySQL:
		return prev.punct(")") || (t.is("ANY", "SOME") && prev.kind == tokPunct && strings.Contains("=<>!", prev.text))
	case t.is("OPERATOR"):
		return pgCatalogOperator(toks, i) // written after an operand, and it runs a routine
	case pgAfterOperand(toks, i):
		return true // two operands in a row: this is a keyword, or the parser refuses it
	case t.is("LIKE", "ILIKE"):
		return prev.is("NOT") && pgAfterOperand(toks, i-1)
	case t.is("CUBE", "ROLLUP"):
		return prev.is("BY") && i >= 2 && toks[i-2].is("GROUP")
	case t.is("CONFLICT"):
		j := pastParens(toks, i+1)
		return prev.is("ON") && j < len(toks) && toks[j].is("DO")
	case t.is("INSERT"):
		return prev.is("THEN") && !inCase(toks, i-1) // MERGE's action
	case t.is("MATERIALIZED"):
		return prev.is("NOT") && i >= 2 && toks[i-2].is("AS")
	}
	for _, w := range pgAfter[t.up] {
		if prev.is(w) {
			return true
		}
	}
	return false
}

// pgAfter are PostgreSQL words a function may be named, that are keywords when
// they follow one of these, and no expression can start after those.
var pgAfter = map[string][]string{
	"BY":      {"GROUP", "ORDER", "PARTITION"},
	"GROUP":   {"WITHIN"},
	"JOIN":    {"INNER", "LEFT", "RIGHT", "OUTER", "FULL", "CROSS", "NATURAL"},
	"KEY":     {"PRIMARY", "FOREIGN"},
	"SET":     {"UPDATE"},
	"SETS":    {"GROUPING"},
	"VARYING": {"CHARACTER", "CHAR", "BIT"},
	"ZONE":    {"TIME"},
}

// cteColumns reports whether the name at i opens a WITH item's column list:
// name (a, b) AS [[NOT] MATERIALIZED] (.
func cteColumns(toks []token, i int) bool {
	if p := toks[i-1]; !p.is("WITH", "RECURSIVE") && !p.punct(",") {
		return false
	}
	j := pastParens(toks, i+1)
	if j >= len(toks) || !toks[j].is("AS") {
		return false
	}
	j = skip(toks, j+1, "NOT", "MATERIALIZED")
	return j < len(toks) && toks[j].punct("(")
}

// pgAfterOperand reports whether what comes before i ends an operand or a table
// reference. No expression can start there, so name( at i is a keyword, an alias's
// column list, or a syntax error. A word only counts if it can't be a keyword that
// takes an expression after it, and pgKeywords is every keyword the server has.
func pgAfterOperand(toks []token, i int) bool {
	if i == 0 {
		return false
	}
	p := toks[i-1]
	switch {
	case p.kind == tokString, p.kind == tokNumber, p.kind == tokQuoted, p.punct("]"):
		return true
	case p.punct(")"):
		o := openOf(toks, i-1)
		return !(o >= 2 && toks[o-1].is("ON") && toks[o-2].is("DISTINCT")) // a select list starts after DISTINCT ON (a)
	case p.kind == tokWord:
		if i >= 2 && (toks[i-2].punct(".") || toks[i-2].is("AS")) {
			return true // a column or an alias, whatever it spells
		}
		return !pgKeywords[p.up] || pgOperandWords[p.up]
	}
	return false
}

// openOf returns the index of the parenthesis that the one at i closes, or -1.
func openOf(toks []token, i int) int {
	depth := 0
	for ; i >= 0; i-- {
		switch {
		case toks[i].punct(")"):
			depth++
		case toks[i].punct("("):
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// inCase reports whether the word at i is inside a CASE at its own depth: a THEN
// there is the expression's, and what follows it is an expression.
func inCase(toks []token, i int) bool {
	open := 0
	for j := i; j >= 0; j-- {
		switch {
		case toks[j].punct(")"):
			if j = openOf(toks, j); j < 0 {
				return true
			}
		case toks[j].punct("("):
			return open > 0
		case toks[j].is("END"):
			open--
		case toks[j].is("CASE"):
			open++
		}
	}
	return open > 0
}

// pgCatalogOperator reports whether OPERATOR at i is a listed operator, spelled
// OPERATOR(pg_catalog.op), as psql writes them.
func pgCatalogOperator(toks []token, i int) bool {
	if i+4 >= len(toks) || !toks[i+2].is("PG_CATALOG") || !toks[i+3].punct(".") {
		return false
	}
	op, n := operatorAt(toks, i+4)
	return pgOperators[op] && i+4+n < len(toks) && toks[i+4+n].punct(")")
}

// pgReserved cannot name a function in PostgreSQL: its reserved words and the
// non-reserved ones that "cannot be function or type". Reserved words that can be
// a function name (LEFT, LIKE, JOIN and the like) are not here.
var pgReserved = wordSet(`ALL AND ANY ARRAY AS BETWEEN BIT CASE CAST CHAR CHARACTER CHECK COALESCE DECIMAL
	DEFAULT DISTINCT ELSE EXCEPT EXISTS EXTRACT FROM GREATEST GROUPING HAVING IN INTERSECT INTERVAL LATERAL LEAST
	LIMIT NOT NULLIF NUMERIC OFFSET ON OR OVERLAY POSITION RETURNING ROW SELECT SOME SUBSTRING TABLE THEN TIME
	TIMESTAMP TRIM UNION UNIQUE USING VALUES VARCHAR WHEN WHERE WITH`)

// myReserved cannot name an unquoted, unqualified function in MySQL 8.4.
var myReserved = wordSet(`ALL AND AS BETWEEN BINARY BY CASE CHAR CHARACTER CONVERT CROSS CUBE DECIMAL DEFAULT
	DISTINCT DIV ELSE EXCEPT EXISTS FROM GROUPING HAVING IN INNER INTERSECT INTERVAL JOIN KEY LATERAL LIKE LIMIT
	NOT NUMERIC ON OR OVER PARTITION REGEXP RLIKE ROW SELECT SET TABLE THEN UNION USING VALUES VARCHAR VARYING
	WHEN WHERE WITH XOR`)

// pgKeywords is every keyword of PostgreSQL 17, from pg_get_keywords(), which
// testdata/pg-keywords.txt holds and the live tests compare with a real server.
// Most can take an expression after them, or might one day: only pgOperandWords
// are shown not to.
var pgKeywords = wordSet(`ABORT ABSENT ABSOLUTE ACCESS ACTION ADD ADMIN AFTER AGGREGATE ALL ALSO ALTER ALWAYS ANALYSE
	ANALYZE AND ANY ARRAY AS ASC ASENSITIVE ASSERTION ASSIGNMENT ASYMMETRIC AT ATOMIC ATTACH ATTRIBUTE
	AUTHORIZATION BACKWARD BEFORE BEGIN BETWEEN BIGINT BINARY BIT BOOLEAN BOTH BREADTH BY CACHE CALL
	CALLED CASCADE CASCADED CASE CAST CATALOG CHAIN CHAR CHARACTER CHARACTERISTICS CHECK CHECKPOINT
	CLASS CLOSE CLUSTER COALESCE COLLATE COLLATION COLUMN COLUMNS COMMENT COMMENTS COMMIT COMMITTED
	COMPRESSION CONCURRENTLY CONDITIONAL CONFIGURATION CONFLICT CONNECTION CONSTRAINT CONSTRAINTS
	CONTENT CONTINUE CONVERSION COPY COST CREATE CROSS CSV CUBE CURRENT CURRENT_CATALOG CURRENT_DATE
	CURRENT_ROLE CURRENT_SCHEMA CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER CURSOR CYCLE DATA DATABASE
	DAY DEALLOCATE DEC DECIMAL DECLARE DEFAULT DEFAULTS DEFERRABLE DEFERRED DEFINER DELETE DELIMITER
	DELIMITERS DEPENDS DEPTH DESC DETACH DICTIONARY DISABLE DISCARD DISTINCT DO DOCUMENT DOMAIN DOUBLE
	DROP EACH ELSE EMPTY ENABLE ENCODING ENCRYPTED END ENUM ERROR ESCAPE EVENT EXCEPT EXCLUDE
	EXCLUDING EXCLUSIVE EXECUTE EXISTS EXPLAIN EXPRESSION EXTENSION EXTERNAL EXTRACT FALSE FAMILY
	FETCH FILTER FINALIZE FIRST FLOAT FOLLOWING FOR FORCE FOREIGN FORMAT FORWARD FREEZE FROM FULL
	FUNCTION FUNCTIONS GENERATED GLOBAL GRANT GRANTED GREATEST GROUP GROUPING GROUPS HANDLER HAVING
	HEADER HOLD HOUR IDENTITY IF ILIKE IMMEDIATE IMMUTABLE IMPLICIT IMPORT IN INCLUDE INCLUDING
	INCREMENT INDENT INDEX INDEXES INHERIT INHERITS INITIALLY INLINE INNER INOUT INPUT INSENSITIVE
	INSERT INSTEAD INT INTEGER INTERSECT INTERVAL INTO INVOKER IS ISNULL ISOLATION JOIN JSON
	JSON_ARRAY JSON_ARRAYAGG JSON_EXISTS JSON_OBJECT JSON_OBJECTAGG JSON_QUERY JSON_SCALAR
	JSON_SERIALIZE JSON_TABLE JSON_VALUE KEEP KEY KEYS LABEL LANGUAGE LARGE LAST LATERAL LEADING
	LEAKPROOF LEAST LEFT LEVEL LIKE LIMIT LISTEN LOAD LOCAL LOCALTIME LOCALTIMESTAMP LOCATION LOCK
	LOCKED LOGGED MAPPING MATCH MATCHED MATERIALIZED MAXVALUE MERGE MERGE_ACTION METHOD MINUTE
	MINVALUE MODE MONTH MOVE NAME NAMES NATIONAL NATURAL NCHAR NESTED NEW NEXT NFC NFD NFKC NFKD NO
	NONE NORMALIZE NORMALIZED NOT NOTHING NOTIFY NOTNULL NOWAIT NULL NULLIF NULLS NUMERIC OBJECT OF
	OFF OFFSET OIDS OLD OMIT ON ONLY OPERATOR OPTION OPTIONS OR ORDER ORDINALITY OTHERS OUT OUTER OVER
	OVERLAPS OVERLAY OVERRIDING OWNED OWNER PARALLEL PARAMETER PARSER PARTIAL PARTITION PASSING
	PASSWORD PATH PLACING PLAN PLANS POLICY POSITION PRECEDING PRECISION PREPARE PREPARED PRESERVE
	PRIMARY PRIOR PRIVILEGES PROCEDURAL PROCEDURE PROCEDURES PROGRAM PUBLICATION QUOTE QUOTES RANGE
	READ REAL REASSIGN RECHECK RECURSIVE REF REFERENCES REFERENCING REFRESH REINDEX RELATIVE RELEASE
	RENAME REPEATABLE REPLACE REPLICA RESET RESTART RESTRICT RETURN RETURNING RETURNS REVOKE RIGHT
	ROLE ROLLBACK ROLLUP ROUTINE ROUTINES ROW ROWS RULE SAVEPOINT SCALAR SCHEMA SCHEMAS SCROLL SEARCH
	SECOND SECURITY SELECT SEQUENCE SEQUENCES SERIALIZABLE SERVER SESSION SESSION_USER SET SETOF SETS
	SHARE SHOW SIMILAR SIMPLE SKIP SMALLINT SNAPSHOT SOME SOURCE SQL STABLE STANDALONE START STATEMENT
	STATISTICS STDIN STDOUT STORAGE STORED STRICT STRING STRIP SUBSCRIPTION SUBSTRING SUPPORT
	SYMMETRIC SYSID SYSTEM SYSTEM_USER TABLE TABLES TABLESAMPLE TABLESPACE TARGET TEMP TEMPLATE
	TEMPORARY TEXT THEN TIES TIME TIMESTAMP TO TRAILING TRANSACTION TRANSFORM TREAT TRIGGER TRIM TRUE
	TRUNCATE TRUSTED TYPE TYPES UESCAPE UNBOUNDED UNCOMMITTED UNCONDITIONAL UNENCRYPTED UNION UNIQUE
	UNKNOWN UNLISTEN UNLOGGED UNTIL UPDATE USER USING VACUUM VALID VALIDATE VALIDATOR VALUE VALUES
	VARCHAR VARIADIC VARYING VERBOSE VERSION VIEW VIEWS VOLATILE WHEN WHERE WHITESPACE WINDOW WITH
	WITHIN WITHOUT WORK WRAPPER WRITE XML XMLATTRIBUTES XMLCONCAT XMLELEMENT XMLEXISTS XMLFOREST
	XMLNAMESPACES XMLPARSE XMLPI XMLROOT XMLSERIALIZE XMLTABLE YEAR YES ZONE`)

// pgOperandWords are keywords that end an operand or are ordinary column names:
// no expression can start right after one.
var pgOperandWords = wordSet(`CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER
	DATA END FALSE LOCALTIME LOCALTIMESTAMP NAME NULL ORDINALITY ROLE SESSION_USER SYSTEM_USER TRUE USER`)

// pgSafeFuncs are PostgreSQL built-ins that do not change rows, exact names only.
// Nothing here runs SQL handed to it or changes how the session reads text:
// set_config is out for that reason. An unqualified call also needs pg_catalog
// to come first on the search path, which the session tracks.
var pgSafeFuncs = wordSet(`ABS ARRAY_AGG ARRAY_LENGTH AVG BOOL_AND BOOL_OR CEIL CEILING CHAR_LENGTH
	CHARACTER_LENGTH CONCAT CONCAT_WS COUNT CURRENT_DATABASE CURRENT_SCHEMA CURRENT_SETTING CURRVAL DATE_PART
	DATE_TRUNC DECODE DENSE_RANK ENCODE FLOOR FORMAT GEN_RANDOM_UUID GENERATE_SERIES INITCAP JSON_AGG JSONB_AGG
	LAG LASTVAL LEAD LEFT LENGTH LOWER LPAD LTRIM MAX MD5 MIN MOD NEXTVAL NOW OCTET_LENGTH PG_ADVISORY_LOCK
	PG_ADVISORY_UNLOCK PG_ADVISORY_XACT_LOCK PG_BACKEND_PID PG_SLEEP PG_TRY_ADVISORY_LOCK POWER RANDOM RANK
	REPEAT REPLACE REVERSE RIGHT ROUND ROW_NUMBER RPAD RTRIM SIGN SPLIT_PART SQRT STDDEV STRING_AGG SUBSTR SUM
	TO_CHAR TRUNC UNNEST UPPER VARIANCE VERSION
	ARRAY_TO_STRING ARRAY_UPPER COL_DESCRIPTION CURRENT_SCHEMAS FORMAT_TYPE HAS_SCHEMA_PRIVILEGE HAS_TABLE_PRIVILEGE
	JSON_BUILD_OBJECT JSONB_BUILD_OBJECT OBJ_DESCRIPTION PG_ENCODING_TO_CHAR PG_FUNCTION_IS_VISIBLE
	PG_GET_CONSTRAINTDEF PG_GET_EXPR PG_GET_FUNCTION_ARGUMENTS PG_GET_FUNCTION_RESULT PG_GET_INDEXDEF
	PG_GET_PARTKEYDEF PG_GET_RULEDEF PG_GET_SERIAL_SEQUENCE PG_GET_STATISTICSOBJDEF_COLUMNS PG_GET_TRIGGERDEF
	PG_GET_USERBYID PG_GET_VIEWDEF PG_HAS_ROLE PG_RELATION_IS_PUBLISHABLE PG_TABLE_IS_VISIBLE
	PG_TABLESPACE_LOCATION PG_TYPE_IS_VISIBLE QUOTE_IDENT QUOTE_LITERAL SHOBJ_DESCRIPTION TO_JSON TO_JSONB
	TO_REGCLASS TO_REGTYPE`)

// mySafeFuncs are MySQL built-ins that do not change rows, exact names only.
var mySafeFuncs = wordSet(`ABS ANY_VALUE AVG CAST CEIL CEILING CHAR_LENGTH CHARACTER_LENGTH COALESCE CONCAT
	CONCAT_WS CONNECTION_ID COUNT CURDATE CURTIME DATABASE DATE DATE_ADD DATE_FORMAT DATE_SUB DATEDIFF DAY
	DENSE_RANK EXTRACT FLOOR FORMAT FOUND_ROWS GET_LOCK GREATEST GROUP_CONCAT HEX HOUR IF IFNULL INSTR ISNULL
	JSON_EXTRACT LAG LAST_INSERT_ID LEAD LEAST LEFT LENGTH LOCATE LOWER LPAD LTRIM MAX MD5 MIN MINUTE MOD MONTH
	NOW NULLIF OCTET_LENGTH POSITION POWER RAND RANK RELEASE_LOCK REPEAT REPLACE REVERSE RIGHT ROUND ROW_COUNT
	ROW_NUMBER RPAD RTRIM SCHEMA SECOND SHA1 SHA2 SIGN SLEEP SQRT STDDEV SUBSTR SUBSTRING SUM SYSDATE TIME
	TIMESTAMP TRIM UCASE UNHEX UNIX_TIMESTAMP UPPER USER UTC_TIMESTAMP UUID VARIANCE VERSION WEEK YEAR
	JSON_ARRAY JSON_CONTAINS JSON_LENGTH JSON_OBJECT JSON_UNQUOTE`)

// pgOperators are built-in operators, as the server's lexer would cut them. Any
// other is user-definable, and an operator is a function call with no parenthesis.
var pgOperators = map[string]bool{"=": true, "<>": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"+": true, "-": true, "*": true, "/": true, "%": true, "^": true, "||": true, "=>": true, "->": true,
	"->>": true, "@>": true, "<@": true, "~": true, "~*": true, "!~": true, "!~*": true,
	"&": true, "|": true, "<<": true, ">>": true, "&&": true, "#>": true, "#>>": true, "#-": true,
	"?": true, "?|": true, "?&": true, "@@": true, "@?": true}

// pgTypes are built-in types. A cast to any other can run a domain's CHECK or a
// user cast's function. DOUBLE counts only with its PRECISION: see pgTypeAt.
var pgTypes = wordSet(`BIGINT BOOL BOOLEAN BYTEA CHAR CHARACTER CIDR DATE DECIMAL DOUBLE FLOAT FLOAT4 FLOAT8 INET
	INT INT2 INT4 INT8 INTEGER INTERVAL JSON JSONB MACADDR NAME NUMERIC OID REAL REGCLASS REGNAMESPACE REGOPER
	REGOPERATOR REGPROC REGPROCEDURE REGROLE REGTYPE SMALLINT TEXT TIME TIMESTAMP TIMESTAMPTZ TIMETZ TSQUERY
	TSVECTOR UUID VARCHAR`)

// pgTypeAt reports whether the word at i is a listed type. DOUBLE alone is no
// built-in, so it resolves to whatever the application calls double.
//
//subpoena:enforcement_point
func pgTypeAt(toks []token, i int) bool {
	if toks[i].kind != tokWord || !pgTypes[toks[i].up] {
		return false
	}
	if toks[i].is("DOUBLE") {
		return i+1 < len(toks) && toks[i+1].is("PRECISION") //subpoena:enforcement
	}
	return true
}

// pgCastTarget reports whether what a cast names at i is a listed type, bare or
// written pg_catalog.type.
func pgCastTarget(toks []token, i int) bool {
	if i+2 < len(toks) && toks[i].is("PG_CATALOG") && toks[i+1].punct(".") {
		i += 2
	}
	return i < len(toks) && pgTypeAt(toks, i) && !(i+1 < len(toks) && toks[i+1].punct("."))
}

// pgBeforeString are the words a string can follow without the word being a type
// name: mytype 'x' is a cast. Only words the grammar will not take as a type are
// here; a word it would is in pgStringLead, at the one position it is a keyword.
var pgBeforeString = wordSet(`ALL AND ANY AS BETWEEN BOTH CASE COLLATE DEFAULT DISTINCT ELSE FROM IN LEADING LIMIT
	NOT OFFSET ON OR RETURNING SELECT THEN TO TRAILING USING VALUES WHEN WHERE`)

// pgStringLead reports whether the string after the word at i is not typed by it.
//
//subpoena:enforcement_point
func pgStringLead(toks []token, i int) bool {
	t := toks[i]
	switch {
	case t.is("B", "E", "N", "X"):
		// X'1F'; with a gap, x is a type.
		return t.pos+len(t.text) == toks[i+1].pos //subpoena:enforcement
	case t.is("ZONE"):
		return i > 0 && toks[i-1].is("TIME")
	case t.is("BY"):
		return i > 0 && toks[i-1].is("GROUP", "ORDER", "PARTITION")
	case t.is("ESCAPE"):
		return pgAfterOperand(toks, i)
	case t.is("LIKE", "ILIKE"):
		return pgAfterOperand(toks, i) || (i > 0 && toks[i-1].is("NOT") && pgAfterOperand(toks, i-1))
	case t.is("NAMES", "SCHEMA", "ROLE", "AUTHORIZATION"):
		return toks[0].is("SET") && (i == 1 || (i == 2 && toks[1].is("SESSION", "LOCAL")))
	}
	return pgBeforeString[t.up] || pgTypeAt(toks, i)
}

// pgHidden finds what PostgreSQL resolves to a routine with no call syntax: a
// user operator, a cast to a type it does not know, and a field of an expression,
// (a).b, which is b(a) if a has no field b. A plain a.b can be b(a) too, but it is
// also every ORM's column, and failing every claim on a read is a false verdict as
// well. Only the catalog can tell them apart, so a.b stays a read, and the function
// behind it is a stated limit like a view: it has to exist already, and one created
// through the listener is opaque when it is created.
func pgHidden(toks []token) string {
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.is("CAST") && i+1 < len(toks) && toks[i+1].punct("(") {
			if why := castType(toks[i+1 : pastParens(toks, i+1)]); why != "" {
				return why
			}
		}
		if t.kind == tokWord && i+1 < len(toks) && toks[i+1].kind == tokString && !pgStringLead(toks, i) {
			return "a string typed as " + t.text + ", which may run a routine"
		}
		if t.punct("$") && i+1 < len(toks) && toks[i+1].kind == tokNumber && strings.Contains(toks[i+1].text, ".") {
			return "a field of a parameter, which may be a function"
		}
		if t.punct(":") && i+2 < len(toks) && toks[i+1].punct(":") {
			if !pgCastTarget(toks, i+2) {
				return "a cast the server may run a routine for"
			}
			continue
		}
		if op, n := operatorAt(toks, i); n > 0 {
			if !pgOperators[op] {
				return "operator " + op + ", which may be a routine"
			}
			i += n - 1
			continue
		}
		if (t.punct(")") || t.punct("]")) && i+2 < len(toks) && toks[i+1].punct(".") && (toks[i+2].kind == tokWord || toks[i+2].kind == tokQuoted) {
			return toks[i+2].text + " may be a function called on a row, not a field"
		}
	}
	return ""
}

// castType checks the type in a CAST's parenthesised group.
func castType(group []token) string {
	depth := 0
	for i, t := range group {
		switch {
		case t.punct("("):
			depth++
		case t.punct(")"):
			depth--
		case t.is("AS") && depth == 1 && i+1 < len(group):
			if !pgCastTarget(group, i+1) {
				return "a cast the server may run a routine for"
			}
			return ""
		}
	}
	return "a cast the server may run a routine for"
}

const pgOperatorChars = "+-*/<>=~!@#%^&|`?"

// operatorAt reads the operator at i, as the server's lexer cuts it, and how many
// tokens it took. An operator ends at a gap, and a long one cannot end in + or -
// unless it holds one of the characters only an operator of its own can.
func operatorAt(toks []token, i int) (string, int) {
	var b strings.Builder
	n := 0
	for j := i; j < len(toks); j++ {
		t := toks[j]
		if t.kind != tokPunct || !strings.Contains(pgOperatorChars, t.text) {
			break
		}
		if j > i && toks[j-1].pos+1 != t.pos {
			break
		}
		b.WriteString(t.text)
		n++
	}
	op := b.String()
	for len(op) > 1 && strings.ContainsAny(op[len(op)-1:], "+-") && !strings.ContainsAny(op, "~!@#%^&|`?") {
		op = op[:len(op)-1]
		n--
	}
	return op, n
}

// setStatement reads SET. It is a read, unless it changes what the witness can
// follow from here on: then the session is tainted. The rule for a setting that
// can change lexing or name lookup is that the name counts in any spelling and the
// value is never parsed for what it means: it is one of the plain forms below, or
// the session is gone.
//
//subpoena:enforcement_point
func setStatement(st statement, toks, rest []token) statement {
	if st.dialect == dialectMySQL {
		st.taint = mySetTaint(rest)
		for _, t := range rest {
			if n := settingName(t); n == "GLOBAL" || n == "PERSIST" || n == "PERSIST_ONLY" {
				o := opaqueStatement(st.text, st.verb, "SET %s reaches other connections", n)
				o.taint = st.taint
				return o //subpoena:enforcement
			}
		}
	} else {
		st.taint = pgSetTaint(rest)
	}
	q := readOnly(st, toks)
	q.taint = st.taint
	return q
}

// settingName is t as the server looks a setting up: quoted or not, without case.
// "" if t can't be a name. Postgres's login options read - as _; a SET does not, and
// counting it there costs nothing.
func settingName(t token) string {
	if t.kind != tokWord && t.kind != tokQuoted {
		return ""
	}
	return strings.ToUpper(strings.ReplaceAll(t.text, "-", "_"))
}

// settingValue reads what SET sets: "name = value", "name TO value", with SESSION
// or LOCAL in front.
func settingValue(rest []token) (name string, value []token) {
	i := skip(rest, 0, "SESSION", "LOCAL")
	if i >= len(rest) {
		return "", nil
	}
	name = settingName(rest[i])
	i++
	if i < len(rest) && (rest[i].punct("=") || rest[i].is("TO")) {
		i++
	}
	return name, rest[i:]
}

// tokenValue is the text of a word or string.
func tokenValue(t token) string {
	return strings.Trim(t.text, "'\"")
}

// plainValue reports whether t means what it spells: a word, a quoted name, or a
// string with no escape or doubled quote in it. An E string, a dollar quote, a
// typed or hex literal or an expression is not one token of these kinds.
//
//subpoena:enforcement_point
func plainValue(t token) bool {
	switch t.kind {
	case tokWord, tokQuoted:
		return true
	case tokString:
		return len(t.text) >= 2 && t.text[0] != '$' && !strings.ContainsAny(t.text[1:len(t.text)-1], `\'"`) //subpoena:enforcement
	}
	return false
}

// pgSessionSettings are the settings that change how the witness must read text,
// by the names only they have. NAMES and SCHEMA are SET's spellings of two of them.
var pgSessionSettings = wordSet("SEARCH_PATH STANDARD_CONFORMING_STRINGS CLIENT_ENCODING")

// pgSetTaint says why a PostgreSQL SET leaves the session unreadable, or "". The
// server reports two of these by ParameterStatus too, but not until the next
// Sync, and a pipelined Parse can get there first. The search path it reports only
// from version 18.
//
//subpoena:enforcement_point
func pgSetTaint(rest []token) string {
	name, value := settingValue(rest)
	switch name {
	case "STANDARD_CONFORMING_STRINGS":
		if len(value) != 1 || (!plainValue(value[0]) && value[0].kind != tokNumber) || !pgOn(tokenValue(value[0])) {
			return "standard_conforming_strings may be off" //subpoena:enforcement
		}
	case "CLIENT_ENCODING", "NAMES":
		if len(value) != 1 || !plainValue(value[0]) || !pgReadableEncoding(tokenValue(value[0])) {
			return "the client encoding may hide quotes in multibyte characters" //subpoena:enforcement
		}
	case "SEARCH_PATH", "SCHEMA":
		return pgSetPathTaint(value)
	default:
		for _, t := range rest {
			if n := settingName(t); pgSessionSettings[n] {
				return "a SET naming " + strings.ToLower(n) + " in a form it cannot read" //subpoena:enforcement
			}
		}
	}
	return ""
}

// pgSetPathTaint is pgPathTaint for a SET's value, which has to be a plain list.
//
//subpoena:enforcement_point
func pgSetPathTaint(value []token) string {
	var parts []string
	for i, t := range value {
		switch {
		case i%2 == 1 && t.punct(","):
		case i%2 == 0 && plainValue(t):
			parts = append(parts, tokenValue(t))
		default:
			return "a search path it cannot read" //subpoena:enforcement
		}
	}
	if len(value)%2 == 0 {
		return "a search path it cannot read" //subpoena:enforcement
	}
	return pgPathTaint(strings.Join(parts, ","))
}

// pgConfigTaint is the taint of a call to set_config, which is a SET by another
// name. It is opaque anyway; the taint matters to what follows a Mark. Only a plain
// first argument naming some other setting is left alone.
//
//subpoena:enforcement_point
func pgConfigTaint(toks []token) string {
	for i, t := range toks {
		if settingName(t) != "SET_CONFIG" {
			continue
		}
		if i+2 < len(toks) && toks[i+1].punct("(") && toks[i+2].kind == tokString && plainValue(toks[i+2]) &&
			!pgSessionSettings[strings.ToUpper(strings.ReplaceAll(tokenValue(toks[i+2]), "-", "_"))] {
			continue
		}
		return "set_config of a setting it cannot rule out" //subpoena:enforcement
	}
	return ""
}

// pgLoginTaint says why a setting given at login leaves the session unreadable, or
// "", as pgSetTaint does. name is as the client spelled it; the server compares
// without case, and its login options read - as _.
//
//subpoena:enforcement_point
func pgLoginTaint(name, value string) string {
	switch strings.ToUpper(strings.ReplaceAll(name, "-", "_")) {
	case "SEARCH_PATH":
		for _, c := range []byte(value) {
			if !isWordByte(c) && c != ',' && c != ' ' && c != '"' {
				return "a login search path it cannot read" //subpoena:enforcement
			}
		}
		return pgPathTaint(value)
	case "STANDARD_CONFORMING_STRINGS":
		if !pgOn(value) {
			return "standard_conforming_strings may be off at login" //subpoena:enforcement
		}
	case "CLIENT_ENCODING":
		if !pgReadableEncoding(value) {
			return "the login client encoding may hide quotes in multibyte characters" //subpoena:enforcement
		}
	}
	return ""
}

// pgOptionsTaint reads the startup packet's options as the server does: split on
// spaces, a backslash taking the next byte literally. Any switch but -c name=value
// and --name=value is not read for what it does.
//
//subpoena:enforcement_point
func pgOptionsTaint(options string) string {
	args := pgSplitOptions(options)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" && i+1 < len(args):
			i++
			a = args[i]
		case strings.HasPrefix(a, "--"):
			a = a[2:]
		case strings.HasPrefix(a, "-c"):
			a = a[2:]
		default:
			return "login options it cannot read" //subpoena:enforcement
		}
		name, value, ok := strings.Cut(a, "=")
		if !ok {
			return "login options it cannot read" //subpoena:enforcement
		}
		if why := pgLoginTaint(name, value); why != "" {
			return why //subpoena:enforcement
		}
	}
	return ""
}

// pgSplitOptions is the server's pg_split_opts.
func pgSplitOptions(s string) []string {
	var args []string
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isSpace(c):
			if in {
				args, in = append(args, b.String()), false
				b.Reset()
			}
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
			in = true
		default:
			b.WriteByte(c)
			in = true
		}
	}
	if in {
		args = append(args, b.String())
	}
	return args
}

func pgOn(v string) bool {
	switch strings.ToLower(v) {
	case "on", "true", "yes", "1":
		return true
	}
	return false
}

// pgReadableEncoding reports whether v is an encoding whose multibyte characters
// hold no ASCII bytes, so that a byte-wise lexer sees the quotes the server sees.
func pgReadableEncoding(v string) bool {
	v = strings.ToUpper(strings.NewReplacer("-", "", "_", "").Replace(v))
	if v == "UTF8" || v == "UNICODE" || v == "SQLASCII" {
		return true
	}
	for _, p := range []string{"LATIN", "WIN125", "ISO8859", "KOI8", "EUC"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// pgPathTaint says why a search path can shadow the built-ins, or "". pg_catalog
// is searched first unless the path names it somewhere else.
//
//subpoena:enforcement_point
func pgPathTaint(path string) string {
	parts := strings.Split(strings.ToLower(path), ",")
	for i, p := range parts {
		if i > 0 && strings.Contains(p, "pg_catalog") {
			return "the search path puts a schema ahead of pg_catalog" //subpoena:enforcement
		}
	}
	return ""
}

// mySessionSettings are the settings that change how MySQL lexes what follows.
// character_set_connection and the collations do not: the lexer goes by the
// client's charset.
var mySessionSettings = wordSet("SQL_MODE NAMES CHARSET CHARACTER CHARACTER_SET_CLIENT")

// mySetTaint says why a MySQL SET leaves the session unreadable, or "". Nothing
// on the wire reports these, except NO_BACKSLASH_ESCAPES in the status flags. Each
// assignment counts by the name on its left, in any spelling and with any scope in
// front; a value that only reads @@sql_mode assigns nothing.
//
//subpoena:enforcement_point
func mySetTaint(rest []token) string {
	for len(rest) > 0 {
		end := 0
		for end < len(rest) && !rest[end].punct(",") {
			if rest[end].punct("(") {
				end = pastParens(rest, end)
				continue
			}
			end++
		}
		if why := myAssignTaint(rest[:end]); why != "" {
			return why //subpoena:enforcement
		}
		rest = rest[min(end+1, len(rest)):]
	}
	return ""
}

// myAssignTaint is mySetTaint for one assignment.
//
//subpoena:enforcement_point
func myAssignTaint(part []token) string {
	for i, t := range part {
		if t.punct("=") {
			return ""
		}
		n := settingName(t)
		if !mySessionSettings[n] || (n == "CHARACTER" && !(i+1 < len(part) && part[i+1].is("SET"))) {
			continue
		}
		value := part[i+1:]
		if n == "CHARACTER" {
			value = value[1:]
		}
		for len(value) > 0 && (value[0].punct(":") || value[0].punct("=")) {
			value = value[1:]
		}
		if n == "SQL_MODE" {
			if !mySafeMode(value) {
				return "sql_mode may change how strings and names are quoted" //subpoena:enforcement
			}
		} else if !mySafeCharset(value) {
			return "the client charset may hide quotes in multibyte characters" //subpoena:enforcement
		}
		return ""
	}
	return ""
}

// mySafeModes are the sql_mode values that leave quoting alone. It is an
// allow-list: ANSI, ANSI_QUOTES and NO_BACKSLASH_ESCAPES are out, and so is any
// spelling that is not one of these.
var mySafeModes = wordSet(`ALLOW_INVALID_DATES ERROR_FOR_DIVISION_BY_ZERO HIGH_NOT_PRECEDENCE IGNORE_SPACE
	NO_AUTO_VALUE_ON_ZERO NO_DIR_IN_CREATE NO_ENGINE_SUBSTITUTION NO_UNSIGNED_SUBTRACTION NO_ZERO_DATE NO_ZERO_IN_DATE
	ONLY_FULL_GROUP_BY PAD_CHAR_TO_FULL_LENGTH PIPES_AS_CONCAT REAL_AS_FLOAT STRICT_ALL_TABLES STRICT_TRANS_TABLES
	TIME_TRUNCATE_FRACTIONAL TRADITIONAL`)

// mySafeModeList reports whether t is a plain list of mySafeModes.
//
//subpoena:enforcement_point
func mySafeModeList(t token) bool {
	if t.kind == tokQuoted || !plainValue(t) {
		return false
	}
	for _, m := range strings.Split(strings.ToUpper(tokenValue(t)), ",") {
		if m != "" && !mySafeModes[m] {
			return false //subpoena:enforcement
		}
	}
	return true
}

// mySafeMode reports whether a sql_mode value is plainly safe: a literal list of
// safe modes, or the current mode with safe modes added to it, as Rails sends:
// CONCAT(@@sql_mode, ',STRICT_ALL_TABLES').
func mySafeMode(value []token) bool {
	if len(value) == 1 {
		return mySafeModeList(value[0])
	}
	if len(value) < 6 || !value[0].is("CONCAT") || !value[1].punct("(") || !value[2].punct("@") || !value[3].punct("@") ||
		value[0].pos+len(value[0].text) != value[1].pos {
		return false
	}
	i := 4
	if i+1 < len(value) && value[i].is("SESSION", "LOCAL") && value[i+1].punct(".") {
		i += 2
	}
	if !value[i].is("SQL_MODE") {
		return false
	}
	for i++; i+1 < len(value) && value[i].punct(","); i += 2 {
		if value[i+1].kind != tokString || !mySafeModeList(value[i+1]) {
			return false
		}
	}
	return i == len(value)-1 && value[i].punct(")")
}

// mySafeCharset reports whether a charset value is plainly one the witness can
// read: name, or name COLLATE collation, which does not change the lexing.
func mySafeCharset(value []token) bool {
	if len(value) != 1 && !(len(value) == 3 && value[1].is("COLLATE") && plainValue(value[2])) {
		return false
	}
	return plainValue(value[0]) && myReadableCharset(tokenValue(value[0]))
}

// myReadableCharset is pgReadableEncoding for MySQL: single-byte charsets, and
// multibyte ones whose every byte past the first is outside ASCII. It is an
// allow-list, so a charset nobody checked taints the session.
func myReadableCharset(v string) bool {
	switch strings.ToLower(v) {
	case "utf8mb4", "utf8mb3", "utf8", "ascii", "binary", "latin1", "latin2", "latin5", "latin7",
		"cp1250", "cp1251", "cp1256", "cp1257", "koi8r", "koi8u", "greek", "hebrew",
		"ujis", "eucjpms", "euckr", "gb2312":
		return true
	}
	return false
}

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// tableName reads a possibly dotted name at i, and returns it with the index past
// it. Unquoted parts are lower case. ok is false if there is no name there.
func tableName(toks []token, i int) (name string, next int, ok bool) {
	var parts []string
	for {
		if i >= len(toks) {
			return "", 0, false
		}
		switch t := toks[i]; t.kind {
		case tokWord:
			parts = append(parts, strings.ToLower(t.text))
		case tokQuoted:
			parts = append(parts, t.text)
		default:
			return "", 0, false
		}
		i++
		if i >= len(toks) || !toks[i].punct(".") {
			return strings.Join(parts, "."), i, true
		}
		i++
	}
}

func skip(toks []token, i int, words ...string) int {
	for i < len(toks) && toks[i].is(words...) {
		i++
	}
	return i
}

func write(st statement, tables ...string) statement {
	st.class, st.tables = classWrite, tables
	return st
}

// insert reads INSERT and REPLACE. toks starts at the verb.
//
//subpoena:enforcement_point
func insert(st statement, toks []token) statement {
	i := skip(toks, 1, "LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE", "INTO")
	name, next, ok := tableName(toks, i)
	if !ok {
		return opaqueStatement(st.text, st.verb, "no table after %s", st.verb) //subpoena:enforcement
	}
	if next+1 < len(toks) && toks[next].is("AS") && (toks[next+1].kind == tokWord || toks[next+1].kind == tokQuoted) {
		next += 2 // INSERT INTO t AS alias (columns)
	}
	if next < len(toks) && toks[next].punct("(") {
		next = pastParens(toks, next)
	}
	for j := next; j < len(toks); j++ {
		if toks[j].is("INSERT", "DELETE", "MERGE", "TRUNCATE") || (toks[j].is("UPDATE") && !toks[j-1].is("DO", "KEY")) {
			return opaqueStatement(st.text, st.verb, "a second write inside an INSERT") //subpoena:enforcement
		}
	}
	return checked(write(st, name), toks[next:])
}

// pastParens returns the index past the parenthesised group opening at i.
func pastParens(toks []token, i int) int {
	depth := 0
	for ; i < len(toks); i++ {
		switch {
		case toks[i].punct("("):
			depth++
		case toks[i].punct(")"):
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return i
}

// target reads "[ONLY] name [*] [[AS] alias]" at i. stop lists the words an
// alias cannot be.
func target(toks []token, i int, stop ...string) (name string, next int, ok bool) {
	i = skip(toks, i, "ONLY")
	name, i, ok = tableName(toks, i)
	if !ok {
		return "", 0, false
	}
	if i < len(toks) && toks[i].punct("*") {
		i++
	}
	if i < len(toks) && toks[i].is("AS") {
		i++
	}
	if i < len(toks) && (toks[i].kind == tokQuoted || (toks[i].kind == tokWord && !toks[i].is(stop...))) {
		i++
	}
	return name, i, true
}

// update reads UPDATE. Only one plain target is understood: MySQL's multi-table
// form writes every table it names, and is opaque here. toks starts at the verb.
//
//subpoena:enforcement_point
func update(st statement, toks []token) statement {
	i := skip(toks, 1, "LOW_PRIORITY", "IGNORE")
	name, next, ok := target(toks, i, "SET")
	if !ok || next >= len(toks) || !toks[next].is("SET") {
		return opaqueStatement(st.text, st.verb, "not a one-table UPDATE") //subpoena:enforcement
	}
	return checked(write(st, name), toks[next:])
}

// deleteFrom reads DELETE. As with update, a form naming more than one target is
// opaque. toks starts at the verb.
//
//subpoena:enforcement_point
func deleteFrom(st statement, toks []token) statement {
	i := skip(toks, 1, "LOW_PRIORITY", "QUICK", "IGNORE")
	if i >= len(toks) || !toks[i].is("FROM") {
		return opaqueStatement(st.text, st.verb, "not a one-table DELETE") //subpoena:enforcement
	}
	stops := []string{"USING", "WHERE", "RETURNING", "ORDER", "LIMIT", "PARTITION"}
	name, next, ok := target(toks, i+1, stops...)
	if !ok || (next < len(toks) && !toks[next].is(stops...)) {
		return opaqueStatement(st.text, st.verb, "not a one-table DELETE") //subpoena:enforcement
	}
	return checked(write(st, name), toks[next:])
}

// merge reads MERGE [INTO] [ONLY] name.
//
//subpoena:enforcement_point
func merge(st statement, rest []token) statement {
	name, next, ok := tableName(rest, skip(rest, 0, "INTO", "ONLY"))
	if !ok {
		return opaqueStatement(st.text, st.verb, "no table after MERGE") //subpoena:enforcement
	}
	return checked(write(st, name), rest[next:])
}

// nameList reads "name [*] [, name [*]]..." at i.
func nameList(toks []token, i int) (names []string, next int, ok bool) {
	for {
		name, n, ok := tableName(toks, skip(toks, i, "ONLY"))
		if !ok {
			return nil, 0, false
		}
		names = append(names, name)
		i = n
		if i < len(toks) && toks[i].punct("*") {
			i++
		}
		if i >= len(toks) || !toks[i].punct(",") {
			return names, i, true
		}
		i++
	}
}

// truncate reads TRUNCATE. CASCADE empties tables it does not name.
//
//subpoena:enforcement_point
func truncate(st statement, rest []token) statement {
	names, next, ok := nameList(rest, skip(rest, 0, "TABLE"))
	if !ok {
		return opaqueStatement(st.text, st.verb, "no table after TRUNCATE") //subpoena:enforcement
	}
	for _, t := range rest[next:] {
		if t.is("CASCADE") {
			return opaqueStatement(st.text, st.verb, "CASCADE reaches tables it does not name") //subpoena:enforcement
		}
	}
	st.noCount = true
	return write(st, names...)
}

// copyStmt reads COPY. FROM writes the table; TO reads.
//
//subpoena:enforcement_point
func copyStmt(st statement, rest []token) statement {
	for _, t := range rest {
		if t.is("PROGRAM") {
			return opaqueStatement(st.text, st.verb, "COPY runs a program") //subpoena:enforcement
		}
	}
	if len(rest) > 0 && rest[0].punct("(") {
		return readOnly(st, rest)
	}
	name, next, ok := tableName(rest, 0)
	if ok && next < len(rest) && rest[next].punct("(") {
		next = pastParens(rest, next)
	}
	switch {
	case ok && next < len(rest) && rest[next].is("FROM"):
		for i := next; i < len(rest); i++ {
			if rest[i].is("WHERE") {
				return checked(write(st, name), rest[i:])
			}
		}
		return write(st, name)
	case ok && next < len(rest) && rest[next].is("TO"):
		return st
	}
	st = opaqueStatement(st.text, st.verb, "cannot read COPY's direction") //subpoena:enforcement
	return st
}

// loadData reads LOAD DATA ... INTO TABLE name. Only its SET clause holds
// expressions: they run for every row of the file.
//
//subpoena:enforcement_point
func loadData(st statement, rest []token) statement {
	if len(rest) > 0 && rest[0].is("DATA") {
		for i := 0; i+1 < len(rest); i++ {
			if rest[i].is("INTO") && rest[i+1].is("TABLE") {
				if name, next, ok := tableName(rest, i+2); ok {
					return checked(write(st, name), loadSet(rest[next:]))
				}
			}
		}
	}
	st = opaqueStatement(st.text, st.verb, "not LOAD DATA INTO TABLE") //subpoena:enforcement
	return st
}

// loadSet is the SET clause of what follows LOAD DATA's table name, or nil.
// CHARACTER SET there names the file's charset.
//
//subpoena:enforcement_point
func loadSet(toks []token) []token {
	for i := 0; i < len(toks); i++ {
		switch {
		case toks[i].punct("("):
			i = pastParens(toks, i) - 1
		case toks[i].is("SET") && (i == 0 || !toks[i-1].is("CHARACTER")):
			return toks[i:] //subpoena:enforcement
		}
	}
	return nil
}

// ddl reads CREATE, DROP and ALTER of a table. Of anything else it is opaque: a
// schema change is not a row, but it can run a body or start a trigger.
//
//subpoena:enforcement_point
func ddl(st statement, rest []token) statement {
	i := skip(rest, 0, "TEMPORARY", "TEMP", "UNLOGGED", "GLOBAL", "LOCAL")
	if i >= len(rest) || !rest[i].is("TABLE") {
		return opaqueStatement(st.text, st.verb, "a schema change other than a table's") //subpoena:enforcement
	}
	i = skip(rest, i+1, "IF", "NOT", "EXISTS")
	names, next, ok := nameList(rest, i)
	if !ok {
		return opaqueStatement(st.text, st.verb, "no table name") //subpoena:enforcement
	}
	if st.verb != "DROP" && len(names) > 1 {
		names = names[:1]
	}
	switch st.verb {
	case "CREATE":
		if st.dialect == dialectPostgres && linksTable(rest[next:]) {
			return opaqueStatement(st.text, st.verb, "rows reach a table it does not name") //subpoena:enforcement
		}
		if body := createBody(rest[next:]); body != nil {
			if !body[0].punct("(") && !body[0].is("SELECT", "VALUES", "TABLE", "WITH") {
				return opaqueStatement(st.text, st.verb, "CREATE TABLE from something other than a query") //subpoena:enforcement
			}
			if q := readOnly(st, body); q.class == classOpaque {
				return q //subpoena:enforcement
			}
		}
	case "ALTER":
		tail := rest[next:]
		for j, t := range tail {
			if t.is("RENAME", "EXCHANGE", "ATTACH") || (t.is("INHERIT") && !(j > 0 && tail[j-1].is("NO"))) ||
				(t.is("SCHEMA") && j > 0 && tail[j-1].is("SET")) {
				return opaqueStatement(st.text, st.verb, "rows reach a table it does not name") //subpoena:enforcement
			}
		}
		// A USING or DEFAULT expression is evaluated here, on the rows already there.
		if q := checked(st, rest[next:]); q.class == classOpaque {
			return q //subpoena:enforcement
		}
	}
	st.noCount = true
	return write(st, names...)
}

// linksTable reports whether what follows CREATE TABLE's name ties the new table
// to another: rows written to one then show in the other.
func linksTable(toks []token) bool {
	for i := 0; i < len(toks); i++ {
		switch {
		case toks[i].punct("("):
			i = pastParens(toks, i) - 1
		case toks[i].is("INHERITS"), toks[i].is("PARTITION") && i+1 < len(toks) && toks[i+1].is("OF"):
			return true
		}
	}
	return false
}

// createBody finds the query in what follows CREATE TABLE's name, or nil if there
// is none: only a query runs anything when a table is created. It starts past AS.
func createBody(toks []token) []token {
	if len(toks) > 1 && toks[0].punct("(") && toks[1].is("SELECT", "VALUES", "TABLE", "WITH") {
		return toks
	}
	for i := 0; i < len(toks); i++ {
		switch {
		case toks[i].punct("("):
			i = pastParens(toks, i) - 1
		case toks[i].is("AS"):
			if i+1 < len(toks) {
				return toks[i+1:]
			}
			return toks[i:]
		case toks[i].is("SELECT", "VALUES", "TABLE"),
			toks[i].is("WITH") && !(i+1 < len(toks) && toks[i+1].punct("(")):
			return toks[i:]
		}
	}
	return nil
}

// txCommand reads COMMIT, ROLLBACK, SAVEPOINT and RELEASE, in all their spellings.
// ROLLBACK PREPARED acts on a transaction already reported at PREPARE TRANSACTION,
// if this witness saw it, and undoes it either way.
//
//subpoena:enforcement_point
func txCommand(st statement, rest []token) statement {
	st.class = classTx
	if len(rest) > 0 && rest[0].is("PREPARED") {
		st.class = classRead
		if st.verb == "COMMIT" {
			// The PREPARE TRANSACTION may be on no connection this witness saw.
			return opaqueStatement(st.text, st.verb, "COMMIT PREPARED of a transaction it may not have seen") //subpoena:enforcement
		}
		return st
	}
	i := skip(rest, 0, "WORK", "TRANSACTION")
	switch st.verb {
	case "COMMIT", "END":
		st.tx = txCommit
	case "ROLLBACK", "ABORT":
		st.tx = txRollback
		if i < len(rest) && rest[i].is("TO") {
			st.tx = txRollbackTo
			st.savepoint = savepointName(rest, i+1)
		}
	case "SAVEPOINT":
		st.tx = txSavepoint
		st.savepoint = savepointName(rest, 0)
	case "RELEASE":
		st.tx = txRelease
		st.savepoint = savepointName(rest, 0)
	}
	if st.dialect == dialectMySQL {
		st.savepoint = myFoldSavepoint(st.savepoint)
	}
	return st
}

// myFoldSavepoint is name as MySQL compares it, quoted or not: without case, by a
// collation that also folds accents and pads with spaces. A name outside ASCII
// words could equal any other, so it reads as no name.
//
//subpoena:enforcement_point
func myFoldSavepoint(name string) string {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 || !isWordByte(name[i]) {
			return "" //subpoena:enforcement
		}
	}
	return strings.ToLower(name)
}

// savepointName reads "[SAVEPOINT] name" at i. "" means none could be read; the
// transaction log then keeps every pending write.
func savepointName(toks []token, i int) string {
	i = skip(toks, i, "SAVEPOINT")
	name, _, ok := tableName(toks, i)
	if !ok {
		return ""
	}
	return name
}
