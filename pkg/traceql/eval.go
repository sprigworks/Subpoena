package traceql

import "fmt"

// UnsupportedValueError reports that a query reads an attribute that holds an
// Unsupported value in the input: the first such span, in input order.
type UnsupportedValueError struct {
	TraceID, SpanID, Attr, Kind string
}

func (e *UnsupportedValueError) Error() string {
	return fmt.Sprintf("traceql: span.%s holds a %s value (trace %s, span %s); array and map values are outside the subset", e.Attr, e.Kind, e.TraceID, e.SpanID)
}

// Eval evaluates the query against each trace and returns the traces that
// produced a non-empty result. Order follows the input order. If any span in
// the input holds an Unsupported value under an attribute the query reads, it
// returns an *UnsupportedValueError and no matches, whether or not evaluation
// would have reached that span.
func (q *Query) Eval(traces []Trace) ([]Match, error) {
	for _, tr := range traces {
		if err := q.refuse(tr); err != nil {
			return nil, err
		}
	}
	var out []Match
	for _, tr := range traces {
		if sel := q.evalTrace(tr); len(sel) > 0 {
			m := Match{TraceID: tr.ID}
			for _, i := range sel {
				m.Spans = append(m.Spans, tr.Spans[i])
			}
			out = append(out, m)
		}
	}
	return out, nil
}

// MatchesTrace reports whether the query selects at least one span in tr. The
// error is as for Eval.
func (q *Query) MatchesTrace(tr Trace) (bool, error) {
	if err := q.refuse(tr); err != nil {
		return false, err
	}
	return len(q.evalTrace(tr)) > 0, nil
}

func (q *Query) refuse(tr Trace) error {
	attrs := q.Attributes()
	for _, s := range tr.Spans {
		for _, a := range attrs {
			if u, ok := s.Attrs[a].(Unsupported); ok {
				return &UnsupportedValueError{TraceID: tr.ID, SpanID: s.ID, Attr: a, Kind: u.Kind}
			}
		}
	}
	return nil
}

// evalTrace returns the indexes of spans selected by the final spanset.
//
// Structural operators return the right-hand spans that stand in the stated
// relationship to some span selected on the left, as in Tempo.
func (q *Query) evalTrace(tr Trace) []int {
	cur := selectSpans(q.first, tr.Spans)
	if len(q.rest) == 0 {
		return cur
	}
	byID := make(map[string]int, len(tr.Spans))
	for i, s := range tr.Spans {
		if s.ID != "" {
			byID[s.ID] = i
		}
	}
	for _, st := range q.rest {
		lhs := make(map[int]bool, len(cur))
		for _, i := range cur {
			lhs[i] = true
		}
		var next []int
		for _, j := range selectSpans(st.rhs, tr.Spans) {
			if related(st.op, j, tr.Spans, byID, lhs) {
				next = append(next, j)
			}
		}
		cur = next
		if len(cur) == 0 {
			return nil
		}
	}
	return cur
}

func selectSpans(ss *spanset, spans []Span) []int {
	var out []int
	for i := range spans {
		if ss.expr == nil || ss.expr.eval(&spans[i]) {
			out = append(out, i)
		}
	}
	return out
}

// related reports whether span j is a child (or descendant) of a span in lhs.
func related(op structOp, j int, spans []Span, byID map[string]int, lhs map[int]bool) bool {
	seen := map[int]bool{j: true}
	cur := j
	for depth := 0; ; depth++ {
		pid := spans[cur].ParentID
		if pid == "" {
			return false
		}
		p, ok := byID[pid]
		if !ok || seen[p] {
			return false // orphan or cycle
		}
		seen[p] = true
		if lhs[p] {
			return true
		}
		if op == opChild {
			return false
		}
		cur = p
	}
}
