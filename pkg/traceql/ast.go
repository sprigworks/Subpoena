package traceql

// Span is the evaluator's view of a span. It deliberately has no OpenTelemetry
// dependency so the evaluator can be tested (and later conformance-tested) on
// plain data.
type Span struct {
	ID       string
	ParentID string // empty for root spans
	Name     string
	// Attrs holds span attributes. Values are string, bool, int64 or float64.
	Attrs map[string]any
}

// Trace is a set of spans sharing a trace ID.
type Trace struct {
	ID    string
	Spans []Span
}

// Match is one trace that satisfied a query, with the spans selected by the
// final spanset of the query.
type Match struct {
	TraceID string
	Spans   []Span
}

// Query is a parsed query.
type Query struct {
	src   string
	first *spanset
	rest  []structural
}

// String returns the original query text.
func (q *Query) String() string { return q.src }

type structOp int

const (
	opDescendant structOp = iota // >>
	opChild                      // >
)

type structural struct {
	op  structOp
	rhs *spanset
}

// spanset is `{ expr }`; a nil expr selects every span.
type spanset struct{ expr expr }

type expr interface{ eval(s *Span) bool }

type andExpr struct{ l, r expr }
type orExpr struct{ l, r expr }
type litExpr struct{ v bool }

// cmpExpr compares a field to a literal. field is "name" or an attribute key.
type cmpExpr struct {
	isName bool
	attr   string
	neg    bool // true for !=
	val    any  // string, bool, int64
}

func (e andExpr) eval(s *Span) bool { return e.l.eval(s) && e.r.eval(s) }
func (e orExpr) eval(s *Span) bool  { return e.l.eval(s) || e.r.eval(s) }
func (e litExpr) eval(*Span) bool   { return e.v }

func (e cmpExpr) eval(s *Span) bool {
	var got any
	if e.isName {
		got = s.Name
	} else {
		v, ok := s.Attrs[e.attr]
		if !ok {
			// TraceQL: comparing a missing attribute is false, for = and != alike.
			return false
		}
		got = v
	}
	eq, comparable := equal(got, e.val)
	if !comparable {
		return false // type mismatch never matches
	}
	if e.neg {
		return !eq
	}
	return eq
}

func equal(got, want any) (eq, comparable bool) {
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		return ok && g == w, ok
	case bool:
		g, ok := got.(bool)
		return ok && g == w, ok
	case int64:
		switch g := got.(type) {
		case int64:
			return g == w, true
		case int:
			return int64(g) == w, true
		case float64:
			return g == float64(w), true
		}
	}
	return false, false
}
