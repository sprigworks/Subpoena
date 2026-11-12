// Classifying a statement, and the word lists that decide what a call or operator can do.

package dbproxy

import (
	"strings"
)

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
