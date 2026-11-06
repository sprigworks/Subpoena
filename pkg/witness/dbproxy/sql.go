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
}

// opaqueStatement is a statement that counts against every table.
func opaqueStatement(text, verb, format string, a ...any) statement {
	return statement{text: text, verb: verb, class: classOpaque, reason: fmt.Sprintf(format, a...)}
}

// opaqued is st as a statement that counts against every table.
func (st *statement) opaqued(format string, a ...any) *statement {
	o := opaqueStatement(st.text, st.verb, format, a...)
	return &o
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
		return []statement{opaqueStatement(text, firstWord(text), "cannot tokenize: %v", err)} //subpoena:enforcement
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
		case c == '-' && i+1 < len(s) && s[i+1] == '-' && (d == dialectPostgres || i+2 >= len(s) || s[i+2] <= ' '):
			i = lineEnd(s, i)
		case c == '#' && d == dialectMySQL:
			i = lineEnd(s, i)
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
			end, err := quoteEnd(s, i, '\'', d == dialectMySQL || escapePrefix(s, i))
			if err != nil {
				bad = err //subpoena:enforcement
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
			for end < len(s) && (isWordByte(s[end]) || s[end] == '.') {
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

func lineEnd(s string, i int) int {
	if n := strings.IndexByte(s[i:], '\n'); n >= 0 {
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
	st := statement{text: stmtText(text, toks)}
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
	case "SELECT", "VALUES", "TABLE", "WITH", "SET", "DECLARE":
		return readOnly(st, toks)
	case "SHOW", "DESCRIBE", "DESC", "USE", "LISTEN", "UNLISTEN", "NOTIFY", "DISCARD", "DEALLOCATE",
		"FETCH", "MOVE", "CLOSE", "LOCK", "UNLOCK", "RESET", "CHECKPOINT", "VACUUM", "ANALYZE":
		return st
	case "EXPLAIN":
		for _, t := range rest {
			if t.is("ANALYZE", "ANALYSE") {
				return opaqueStatement(st.text, st.verb, "EXPLAIN ANALYZE runs the statement") //subpoena:enforcement
			}
		}
		return st
	case "PREPARE":
		if len(rest) > 0 && rest[0].is("TRANSACTION") {
			st.class, st.tx = classTx, txPrepare
		}
		return st // the statement runs at EXECUTE, which is opaque
	case "BEGIN", "START":
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
// no function that is not known to leave rows alone.
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
	if name := unknownCall(toks); name != "" {
		return opaqueStatement(st.text, st.verb, "calls %s, which may write", name) //subpoena:enforcement
	}
	return st
}

// checked finishes a write statement: a function it calls may write elsewhere.
//
//subpoena:enforcement_point
func checked(st statement, rest []token) statement {
	if name := unknownCall(rest); name != "" {
		return opaqueStatement(st.text, st.verb, "calls %s, which may write", name) //subpoena:enforcement
	}
	return st
}

// unknownCall returns the first name called in toks that is not known to leave
// rows alone, or "".
func unknownCall(toks []token) string {
	for i := 0; i+1 < len(toks); i++ {
		t := toks[i]
		if !toks[i+1].punct("(") || (t.kind != tokWord && t.kind != tokQuoted) {
			continue
		}
		name := t.up
		if t.kind == tokQuoted {
			name = strings.ToUpper(t.text)
		}
		if t.kind == tokWord && notCalls[name] {
			continue
		}
		if !safeCall(name) {
			return t.text
		}
	}
	return ""
}

func safeCall(name string) bool {
	if safeFuncs[name] {
		return true
	}
	for _, p := range safePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// notCalls are the keywords and type names that a parenthesis can follow.
var notCalls = wordSet(`ALL ANY SOME AND AS AT BETWEEN BY CASE CHAR CHARACTER CONFLICT CUBE DECIMAL DISTINCT
	ELSE EXCEPT EXISTS FILTER FROM GROUP GROUPING HAVING IN INTERSECT INTERVAL JOIN KEY LATERAL LIKE ILIKE LIMIT
	NOT NUMERIC OFFSET ON OR ORDER OVER PARTITION RETURNING ROW ROLLUP SELECT SET SETS TABLE THEN TIME TIMESTAMP
	UNION USING VALUE VALUES VARCHAR VARYING WHEN WHERE WITH BIT VARBIT DO`)

// safeFuncs are built-ins that do not change rows. Anything else in a call makes
// a statement opaque, so this list trades false alarms, not safety; a name is
// here only if the server defines it to leave tables alone.
var safeFuncs = wordSet(`ABS AVG BOOL_AND BOOL_OR CAST CEIL CEILING CHAR_LENGTH CHARACTER_LENGTH COALESCE CONCAT
	CONCAT_WS CONNECTION_ID CONVERT COUNT CURDATE CURRVAL CURTIME DATABASE DATE DATEDIFF DAY DENSE_RANK ENCODE DECODE EXTRACT
	FLOOR FORMAT FOUND_ROWS GEN_RANDOM_UUID GENERATE_SERIES GET_LOCK GREATEST GROUP_CONCAT HEX HOUR IF IFNULL
	INITCAP INSTR ISNULL LAG LAST_INSERT_ID LASTVAL LEAD LEAST LEFT LENGTH LOCATE LOWER LPAD LTRIM MAX MD5 MIN
	MINUTE MOD MONTH NEXTVAL NOW NULLIF NVL OCTET_LENGTH POSITION POWER RAND RANDOM RANK RELEASE_LOCK REPEAT
	REPLACE REVERSE RIGHT ROUND ROW_COUNT ROW_NUMBER RPAD RTRIM SCHEMA SECOND SET_CONFIG SHA1 SHA2 SIGN SIGNIFICANT
	SLEEP SPLIT_PART SQRT STDDEV STRFTIME STRING_AGG SUBSTR SUBSTRING SUM SYSDATE TRIM TRUNC UCASE UNHEX UNIX_TIMESTAMP
	UNNEST UPPER USER UTC_TIMESTAMP UUID VARIANCE VERSION WEEK YEAR ANY_VALUE ARRAY ARRAY_AGG`)

var safePrefixes = []string{"PG_", "JSON_", "JSONB_", "ARRAY_", "CURRENT_", "TO_", "DATE_", "REGEXP_"}

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
	if len(rest) > 0 && rest[0].punct("(") {
		return readOnly(st, rest)
	}
	name, next, ok := tableName(rest, 0)
	if ok && next < len(rest) && rest[next].punct("(") {
		next = pastParens(rest, next)
	}
	switch {
	case ok && next < len(rest) && rest[next].is("FROM"):
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
	names, _, ok := nameList(rest, i)
	if !ok {
		return opaqueStatement(st.text, st.verb, "no table name") //subpoena:enforcement
	}
	if st.verb != "DROP" && len(names) > 1 {
		names = names[:1]
	}
	st.noCount = true
	return write(st, names...)
}

// txCommand reads COMMIT, ROLLBACK, SAVEPOINT and RELEASE, in all their spellings.
// COMMIT PREPARED and ROLLBACK PREPARED act on a transaction the witness has
// already reported at PREPARE TRANSACTION.
func txCommand(st statement, rest []token) statement {
	st.class = classTx
	if len(rest) > 0 && rest[0].is("PREPARED") {
		st.class = classRead
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
