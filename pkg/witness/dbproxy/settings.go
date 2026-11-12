// SET statements, and the session settings that taint later statements.

package dbproxy

import (
	"strings"
)

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
