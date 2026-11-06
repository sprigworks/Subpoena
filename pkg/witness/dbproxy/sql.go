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
	unread    bool            // no parser finished the text: it could hold anything
	atomic    bool            // opaque, but it cannot be a routine that commits
	taint     string          // why the session's lexing or name lookup can't be followed after this
	forget    string          // a server-side prepared name this ends or replaces; "*" is all of them
	columns   map[string]bool // lower case: columns the statement proves exist on its target
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
	return st.class == classOpaque && !st.atomic && (st.unread || !atomicVerbs[st.verb]) //subpoena:enforcement
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
		o := opaqueStatement(text, firstWord(text), "cannot tokenize: %v", err) //subpoena:enforcement
		o.unread, o.forget, o.taint = true, "*", tokenizeTaint(text)
		return []statement{o}
	}
	var out []statement
	depth, start := 0, 0
	flush := func(end int) {
		if end > start {
			out = append(out, classify(d, text, toks[start:end]))
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

// tokenizeTaint is the taint of text that did not tokenize: it may still have
// changed how the session reads what comes next.
//
//subpoena:enforcement_point
func tokenizeTaint(text string) string {
	up := strings.ToUpper(text)
	for _, w := range []string{"STANDARD_CONFORMING_STRINGS", "CLIENT_ENCODING", "SEARCH_PATH", "SQL_MODE", "NAMES", "CHARSET", "CHARACTER"} {
		if strings.Contains(up, w) {
			return "text that did not tokenize mentions " + strings.ToLower(w) //subpoena:enforcement
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
			return opaqueStatement(st.text, firstWord(st.text), "a long name the server's encoding decides how to cut") //subpoena:enforcement
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
		out[i].text = t.text[:pgMaxName] //subpoena:enforcement
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
// witnesses/README.md: an overload of a listed name that was installed before the
// capture looks the same as the built-in.
func unproven(st *statement, toks []token) string {
	if name := unknownCall(st.dialect, toks); name != "" {
		return "calls " + name + ", which may write"
	}
	if st.dialect == dialectPostgres {
		return pgHidden(st, toks)
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
		switch t.kind {
		case tokNumber, tokQuoted:
			// MySQL's names may start with a digit, and a quoted name is not
			// the keyword or built-in it spells.
			return t.text //subpoena:enforcement
		case tokWord:
		default:
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
// around it make it the keyword. Any other word is a name, whatever it looks like.
func notCall(d dialect, toks []token, i int) bool {
	t := toks[i]
	if (d == dialectPostgres && pgReserved[t.up]) || (d == dialectMySQL && myReserved[t.up]) {
		return true
	}
	if i == 0 {
		return t.is("SET", "VALUE") // the head of what follows an UPDATE or INSERT target
	}
	prev := toks[i-1]
	if d == dialectMySQL {
		return t.is("ANY", "SOME") && prev.kind == tokPunct && strings.Contains("=<>!", prev.text)
	}
	switch {
	case t.is("OVER", "FILTER", "OVERLAPS"):
		return prev.punct(")")
	case t.is("LIKE", "ILIKE"):
		return prev.punct(")") || prev.kind == tokQuoted || prev.kind == tokString || prev.kind == tokNumber
	}
	for _, w := range pgAfter[t.up] {
		if prev.is(w) {
			return true
		}
	}
	return false
}

// pgAfter are PostgreSQL words a function may be named, that are keywords when
// they follow one of these.
var pgAfter = map[string][]string{
	"BY":       {"GROUP", "ORDER", "PARTITION"},
	"CONFLICT": {"ON"},
	"CUBE":     {"BY"},
	"GROUP":    {"WITHIN"},
	"INSERT":   {"THEN"},
	"JOIN":     {"INNER", "LEFT", "RIGHT", "OUTER", "FULL", "CROSS"},
	"KEY":      {"PRIMARY", "FOREIGN"},
	"ROLLUP":   {"BY"},
	"SET":      {"UPDATE"},
	"SETS":     {"GROUPING"},
	"VARYING":  {"CHARACTER", "CHAR", "BIT"},
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
	TO_CHAR TRUNC UNNEST UPPER VARIANCE VERSION`)

// mySafeFuncs are MySQL built-ins that do not change rows, exact names only.
var mySafeFuncs = wordSet(`ABS ANY_VALUE AVG CAST CEIL CEILING CHAR_LENGTH CHARACTER_LENGTH COALESCE CONCAT
	CONCAT_WS CONNECTION_ID COUNT CURDATE CURTIME DATABASE DATE DATE_ADD DATE_FORMAT DATE_SUB DATEDIFF DAY
	DENSE_RANK EXTRACT FLOOR FORMAT FOUND_ROWS GET_LOCK GREATEST GROUP_CONCAT HEX HOUR IF IFNULL INSTR ISNULL
	JSON_EXTRACT LAG LAST_INSERT_ID LEAD LEAST LEFT LENGTH LOCATE LOWER LPAD LTRIM MAX MD5 MIN MINUTE MOD MONTH
	NOW NULLIF OCTET_LENGTH POSITION POWER RAND RANK RELEASE_LOCK REPEAT REPLACE REVERSE RIGHT ROUND ROW_COUNT
	ROW_NUMBER RPAD RTRIM SCHEMA SECOND SHA1 SHA2 SIGN SLEEP SQRT STDDEV SUBSTR SUBSTRING SUM SYSDATE TIME
	TIMESTAMP TRIM UCASE UNHEX UNIX_TIMESTAMP UPPER USER UTC_TIMESTAMP UUID VARIANCE VERSION WEEK YEAR`)

// pgOperators are built-in operators, as the server's lexer would cut them. Any
// other is user-definable, and an operator is a function call with no parenthesis.
var pgOperators = map[string]bool{"=": true, "<>": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"+": true, "-": true, "*": true, "/": true, "%": true, "^": true, "||": true, "=>": true, "->": true,
	"->>": true, "@>": true, "<@": true, "~": true, "~*": true, "!~": true, "!~*": true}

// pgTypes are built-in types. A cast to any other can run a domain's CHECK or a
// user cast's function.
var pgTypes = wordSet(`BIGINT BOOL BOOLEAN BYTEA CHAR CHARACTER DATE DECIMAL DOUBLE FLOAT FLOAT4 FLOAT8 INT
	INT2 INT4 INT8 INTEGER INTERVAL JSON JSONB NUMERIC REAL SMALLINT TEXT TIME TIMESTAMP TIMESTAMPTZ TIMETZ UUID
	VARCHAR`)

// pgBeforeString are the words a string can follow without the word being a type
// name: mytype 'x' is a cast.
var pgBeforeString = wordSet(`ALL AND ANY AS B BETWEEN BY CASE COLLATE DATE DEFAULT DISTINCT E ELSE ESCAPE FROM ILIKE
	IN INTERVAL LIKE LIMIT N NOT OFFSET ON OR RETURNING SELECT SET SIMILAR THEN TIME TIMESTAMP TO USING VALUES
	WHEN WHERE X ZONE`)

// pgClauseEnds end a FROM list at their depth.
var pgClauseEnds = wordSet(`WHERE GROUP ORDER HAVING LIMIT OFFSET WINDOW FOR UNION INTERSECT EXCEPT ON SET
	RETURNING FETCH WHEN`)

// pgHidden finds what PostgreSQL resolves to a routine with no call syntax: a
// user operator, a cast to a type it does not know, and a.b, which is b(a) if a
// has no column b. Only the catalog can tell that last one from a column, so a
// qualified column reference is unproven. A name in a FROM list is a table.
func pgHidden(st *statement, toks []token) string {
	depth := 0
	from, selects := map[int]bool{}, map[int]bool{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.punct("("):
			depth++
			from[depth], selects[depth] = false, false
		case t.punct(")"):
			depth--
		case t.is("SELECT"):
			selects[depth] = true
		case t.is("FROM"):
			// FROM is also in EXTRACT(a FROM b) and IS DISTINCT FROM.
			if (depth == 0 || selects[depth]) && !(i > 0 && toks[i-1].is("DISTINCT")) {
				from[depth] = true
			}
		case t.is("JOIN"), t.is("USING") && (st.verb == "DELETE" || st.verb == "MERGE"):
			from[depth] = true
		case t.kind == tokWord && pgClauseEnds[t.up]:
			from[depth] = false
		}
		if t.is("CAST") && i+1 < len(toks) && toks[i+1].punct("(") {
			if why := castType(toks[i+1 : pastParens(toks, i+1)]); why != "" {
				return why
			}
		}
		if t.kind == tokWord && i+1 < len(toks) && toks[i+1].kind == tokString && !pgBeforeString[t.up] {
			return "a string typed as " + t.text + ", which may run a routine"
		}
		if t.punct("$") && i+1 < len(toks) && toks[i+1].kind == tokNumber && strings.Contains(toks[i+1].text, ".") {
			return "a field of a parameter, which may be a function"
		}
		if t.punct(":") && i+2 < len(toks) && toks[i+1].punct(":") {
			if toks[i+2].kind != tokWord || !pgTypes[toks[i+2].up] || (i+3 < len(toks) && toks[i+3].punct(".")) {
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
		if why, next := dotted(st, toks, i, depth, from); why != "" {
			return why
		} else if next > i {
			i = next
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
			if group[i+1].kind != tokWord || !pgTypes[group[i+1].up] || (i+2 < len(group) && group[i+2].punct(".")) {
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

// dotted checks a.b at i. It returns why it is unproven, or the index of the last
// name of a chain it has cleared.
func dotted(st *statement, toks []token, i, depth int, from map[int]bool) (string, int) {
	t := toks[i]
	name := t.kind == tokWord || t.kind == tokQuoted
	if (!name && !t.punct(")") && !t.punct("]")) || i+2 >= len(toks) || !toks[i+1].punct(".") {
		return "", 0
	}
	last := i
	for last+2 < len(toks) && toks[last+1].punct(".") && (toks[last+2].kind == tokWord || toks[last+2].kind == tokQuoted) {
		last += 2
	}
	switch {
	case last == i: // a.* or nothing readable
		return "", 0
	case last+1 < len(toks) && toks[last+1].punct("("): // a call: unknownCall has judged it
		return "", last
	case st.verb == "SET": // a parameter's name
		return "", last
	case st.verb == "TABLE" && i == 1:
		return "", last
	case name && from[depth] && i > 0 && (toks[i-1].is("FROM", "JOIN", "ONLY", "USING") || toks[i-1].punct(",")):
		return "", last
	case t.is("EXCLUDED") && last == i+2 && st.columns[toks[last].up] && toks[last].kind == tokWord:
		return "", last // a column of the target: a column beats a function
	}
	return fmt.Sprintf("%s may be a function called on a row, not a column", toks[last].text), 0
}

// setStatement reads SET. It is a read, unless it changes what the witness can
// follow from here on: then the session is tainted.
//
//subpoena:enforcement_point
func setStatement(st statement, toks, rest []token) statement {
	if st.dialect == dialectMySQL {
		for _, t := range rest {
			if t.is("GLOBAL", "PERSIST", "PERSIST_ONLY") {
				return opaqueStatement(st.text, st.verb, "SET %s reaches other connections", t.up) //subpoena:enforcement
			}
		}
		st.taint = mySetTaint(rest)
	} else {
		st.taint = pgSetTaint(rest)
	}
	q := readOnly(st, toks)
	q.taint = st.taint
	return q
}

// settingValue reads what SET sets: "name = value", "name TO value", with SESSION
// or LOCAL in front.
func settingValue(rest []token) (name string, value []token) {
	i := skip(rest, 0, "SESSION", "LOCAL")
	if i >= len(rest) || (rest[i].kind != tokWord && rest[i].kind != tokQuoted) {
		return "", nil
	}
	name = strings.ToUpper(rest[i].text)
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

// pgSetTaint says why a PostgreSQL SET leaves the session unreadable, or "". The
// server reports the first two by ParameterStatus too, but not until the next
// Sync, and a pipelined Parse can get there first.
//
//subpoena:enforcement_point
func pgSetTaint(rest []token) string {
	name, value := settingValue(rest)
	switch name {
	case "STANDARD_CONFORMING_STRINGS":
		if len(value) != 1 || !pgOn(tokenValue(value[0])) {
			return "standard_conforming_strings may be off" //subpoena:enforcement
		}
	case "CLIENT_ENCODING", "NAMES":
		if len(value) != 1 || !pgReadableEncoding(tokenValue(value[0])) {
			return "the client encoding may hide quotes in multibyte characters" //subpoena:enforcement
		}
	case "SEARCH_PATH":
		var parts []string
		for _, t := range value {
			if !t.punct(",") {
				parts = append(parts, tokenValue(t))
			}
		}
		return pgPathTaint(strings.Join(parts, ","))
	}
	return ""
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

// mySetTaint says why a MySQL SET leaves the session unreadable, or "". Nothing
// on the wire reports these two, except NO_BACKSLASH_ESCAPES in the status flags.
//
//subpoena:enforcement_point
func mySetTaint(rest []token) string {
	for i, t := range rest {
		switch {
		case t.is("SQL_MODE"):
			if !mySafeMode(rest[i+1:]) {
				return "sql_mode may change how strings and names are quoted" //subpoena:enforcement
			}
		case t.is("NAMES", "CHARSET", "CHARACTER_SET_CLIENT"), t.is("CHARACTER") && i+1 < len(rest) && rest[i+1].is("SET"):
			j := i + 1
			if t.is("CHARACTER") {
				j++
			}
			if j < len(rest) && (rest[j].punct("=") || rest[j].punct(":")) {
				j++
			}
			if j >= len(rest) || !myReadableCharset(tokenValue(rest[j])) {
				return "the client charset may hide quotes in multibyte characters" //subpoena:enforcement
			}
		}
	}
	return ""
}

// mySafeMode reports whether a sql_mode assignment is one literal that leaves
// quoting alone.
func mySafeMode(toks []token) bool {
	i := 0
	for i < len(toks) && (toks[i].punct("=") || toks[i].punct(":")) {
		i++
	}
	if i >= len(toks) || toks[i].kind != tokString {
		return false
	}
	if i+1 < len(toks) && !toks[i+1].punct(",") {
		return false
	}
	mode := strings.ToUpper(toks[i].text)
	return !strings.Contains(mode, "ANSI") && !strings.Contains(mode, "NO_BACKSLASH_ESCAPES")
}

// myReadableCharset is pgReadableEncoding for MySQL.
func myReadableCharset(v string) bool {
	switch strings.ToLower(v) {
	case "utf8mb4", "utf8mb3", "utf8", "latin1", "ascii", "binary":
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
	if next < len(toks) && toks[next].punct("(") {
		end := pastParens(toks, next)
		st.columns = columnList(toks[next:end])
		next = end
	}
	for j := next; j < len(toks); j++ {
		if toks[j].is("INSERT", "DELETE", "MERGE", "TRUNCATE") || (toks[j].is("UPDATE") && !toks[j-1].is("DO", "KEY")) {
			return opaqueStatement(st.text, st.verb, "a second write inside an INSERT") //subpoena:enforcement
		}
	}
	return checked(write(st, name), toks[next:])
}

// columnList is the plain names in an INSERT's "(a, b)". The server has refused
// the statement if any is not a column.
func columnList(toks []token) map[string]bool {
	m := map[string]bool{}
	for _, t := range toks {
		if t.kind == tokWord {
			m[t.up] = true
		}
	}
	return m
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

// loadData reads LOAD DATA ... INTO TABLE name.
//
//subpoena:enforcement_point
func loadData(st statement, rest []token) statement {
	if len(rest) > 0 && rest[0].is("DATA") {
		for i := 0; i+1 < len(rest); i++ {
			if rest[i].is("INTO") && rest[i+1].is("TABLE") {
				if name, _, ok := tableName(rest, i+2); ok {
					return write(st, name)
				}
			}
		}
	}
	st = opaqueStatement(st.text, st.verb, "not LOAD DATA INTO TABLE") //subpoena:enforcement
	return st
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
		if body := createBody(rest[next:]); body != nil {
			if !body[0].punct("(") && !body[0].is("SELECT", "VALUES", "TABLE", "WITH") {
				return opaqueStatement(st.text, st.verb, "CREATE TABLE from something other than a query") //subpoena:enforcement
			}
			if q := readOnly(st, body); q.class == classOpaque {
				return q //subpoena:enforcement
			}
		}
	case "ALTER":
		for _, t := range rest[next:] {
			if t.is("RENAME", "EXCHANGE") {
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
	return st
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
