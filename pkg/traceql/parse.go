package traceql

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ParseError describes a syntax error or use of syntax outside the subset.
type ParseError struct {
	Query string
	Pos   int
	Msg   string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("traceql: %s at offset %d in %q", e.Msg, e.Pos, e.Query)
}

type tokKind int

const (
	tEOF tokKind = iota
	tLBrace
	tRBrace
	tLParen
	tRParen
	tAnd
	tOr
	tEq
	tNeq
	tDesc  // >>
	tChild // >
	tIdent
	tString
	tInt
)

type token struct {
	kind tokKind
	text string
	pos  int
}

type parser struct {
	src  string
	toks []token
	i    int
}

// Parse parses a query in the supported subset.
func Parse(src string) (*Query, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, toks: toks}
	q := &Query{src: src}
	if q.first, err = p.spanset(); err != nil {
		return nil, err
	}
	for p.peek().kind == tDesc || p.peek().kind == tChild {
		op := opDescendant
		if p.next().kind == tChild {
			op = opChild
		}
		rhs, err := p.spanset()
		if err != nil {
			return nil, err
		}
		q.rest = append(q.rest, structural{op: op, rhs: rhs})
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, p.errAt(t, fmt.Sprintf("unexpected %q (not in the supported subset)", t.text))
	}
	return q, nil
}

func lex(src string) ([]token, error) {
	var toks []token
	rs := []rune(src)
	bad := func(i int, msg string) error { return &ParseError{Query: src, Pos: i, Msg: msg} }
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '{':
			toks = append(toks, token{tLBrace, "{", i})
			i++
		case c == '}':
			toks = append(toks, token{tRBrace, "}", i})
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "(", i})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")", i})
			i++
		case c == '&' && i+1 < len(rs) && rs[i+1] == '&':
			toks = append(toks, token{tAnd, "&&", i})
			i += 2
		case c == '|' && i+1 < len(rs) && rs[i+1] == '|':
			toks = append(toks, token{tOr, "||", i})
			i += 2
		case c == '|':
			return nil, bad(i, "pipeline operator '|' is not in the supported subset")
		case c == '!' && i+1 < len(rs) && rs[i+1] == '=':
			toks = append(toks, token{tNeq, "!=", i})
			i += 2
		case c == '=' && i+1 < len(rs) && (rs[i+1] == '~' || rs[i+1] == '='):
			return nil, bad(i, "regex and '==' operators are not in the supported subset")
		case c == '=':
			toks = append(toks, token{tEq, "=", i})
			i++
		case c == '>' && i+1 < len(rs) && rs[i+1] == '>':
			toks = append(toks, token{tDesc, ">>", i})
			i += 2
		case c == '>' && i+1 < len(rs) && (rs[i+1] == '=' || rs[i+1] == '~'):
			return nil, bad(i, "comparison and sibling operators are not in the supported subset")
		case c == '>':
			toks = append(toks, token{tChild, ">", i})
			i++
		case c == '"':
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				if rs[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(rs) {
				return nil, bad(i, "unterminated string literal")
			}
			lit := string(rs[i : j+1])
			s, err := strconv.Unquote(lit)
			if err != nil {
				return nil, bad(i, "invalid string literal")
			}
			toks = append(toks, token{tString, s, i})
			i = j + 1
		case unicode.IsDigit(c) || (c == '-' && i+1 < len(rs) && unicode.IsDigit(rs[i+1])):
			j := i + 1
			for j < len(rs) && unicode.IsDigit(rs[j]) {
				j++
			}
			if j < len(rs) && (rs[j] == '.' || rs[j] == 'e' || unicode.IsLetter(rs[j])) {
				return nil, bad(i, "only integer literals are in the supported subset")
			}
			toks = append(toks, token{tInt, string(rs[i:j]), i})
			i = j
		case unicode.IsLetter(c) || c == '_' || c == '.':
			j := i
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_' || rs[j] == '.') {
				j++
			}
			toks = append(toks, token{tIdent, string(rs[i:j]), i})
			i = j
		default:
			return nil, bad(i, fmt.Sprintf("unexpected character %q", c))
		}
	}
	toks = append(toks, token{tEOF, "<end>", len(rs)})
	return toks, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}
func (p *parser) errAt(t token, msg string) error {
	return &ParseError{Query: p.src, Pos: t.pos, Msg: msg}
}

func (p *parser) spanset() (*spanset, error) {
	if t := p.next(); t.kind != tLBrace {
		return nil, p.errAt(t, fmt.Sprintf("expected '{', got %q", t.text))
	}
	if p.peek().kind == tRBrace {
		p.next()
		return &spanset{}, nil
	}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if t := p.next(); t.kind != tRBrace {
		return nil, p.errAt(t, fmt.Sprintf("expected '}', got %q", t.text))
	}
	return &spanset{expr: e}, nil
}

// or parses an || chain. Mixing && and || at one parenthesis level is
// rejected: Tempo gives them equal precedence and groups left to right
// (`a || b && c` is `(a || b) && c`), which most readers misread, so the subset
// requires the grouping to be written out.
func (p *parser) or() (expr, error) {
	l, andAt, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tOr {
		orTok := p.next()
		r, rAndAt, err := p.and()
		if err != nil {
			return nil, err
		}
		if andAt == nil {
			andAt = rAndAt
		}
		if andAt != nil {
			at := orTok
			if andAt.pos > at.pos {
				at = *andAt
			}
			return nil, p.errAt(at, "'&&' and '||' mixed without parentheses (Tempo groups them left to right with equal precedence); add parentheses")
		}
		l = orExpr{l, r}
	}
	return l, nil
}

// and parses an && chain and returns the first && token, if any.
func (p *parser) and() (expr, *token, error) {
	l, err := p.primary()
	if err != nil {
		return nil, nil, err
	}
	var first *token
	for p.peek().kind == tAnd {
		t := p.next()
		if first == nil {
			first = &t
		}
		r, err := p.primary()
		if err != nil {
			return nil, nil, err
		}
		l = andExpr{l, r}
	}
	return l, first, nil
}

func (p *parser) primary() (expr, error) {
	t := p.next()
	switch t.kind {
	case tLParen:
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if c := p.next(); c.kind != tRParen {
			return nil, p.errAt(c, fmt.Sprintf("expected ')', got %q", c.text))
		}
		return e, nil
	case tIdent:
		switch t.text {
		case "true":
			return litExpr{true}, nil
		case "false":
			return litExpr{false}, nil
		}
		return p.comparison(t)
	}
	return nil, p.errAt(t, fmt.Sprintf("expected a condition, got %q", t.text))
}

func (p *parser) comparison(field token) (expr, error) {
	c := cmpExpr{}
	switch {
	case field.text == "name":
		c.isName = true
	case strings.HasPrefix(field.text, "span.") && len(field.text) > len("span."):
		c.attr = strings.TrimPrefix(field.text, "span.")
	default:
		return nil, p.errAt(field, fmt.Sprintf("field %q is not in the supported subset (use name or span.<attr>)", field.text))
	}
	op := p.next()
	switch op.kind {
	case tEq:
	case tNeq:
		c.neg = true
	default:
		return nil, p.errAt(op, fmt.Sprintf("operator %q is not in the supported subset (use = or !=)", op.text))
	}
	v := p.next()
	switch v.kind {
	case tString:
		c.val = v.text
	case tInt:
		n, err := strconv.ParseInt(v.text, 10, 64)
		if err != nil {
			return nil, p.errAt(v, "integer out of range")
		}
		c.val = n
	case tIdent:
		switch v.text {
		case "true":
			c.val = true
		case "false":
			c.val = false
		default:
			return nil, p.errAt(v, fmt.Sprintf("value %q is not a string, integer or bool literal", v.text))
		}
	default:
		return nil, p.errAt(v, fmt.Sprintf("expected a literal, got %q", v.text))
	}
	if c.isName {
		if _, ok := c.val.(string); !ok {
			return nil, p.errAt(v, "name must be compared with a string")
		}
	}
	return c, nil
}
