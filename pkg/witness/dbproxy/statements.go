// Writes, DDL and transaction commands: which tables a statement touches.

package dbproxy

import (
	"strings"
)

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
