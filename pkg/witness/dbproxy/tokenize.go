// Splitting SQL text into tokens, per dialect.

package dbproxy

import (
	"fmt"
	"strings"
)

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
