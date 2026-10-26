package traceql

// Eval evaluates the query against each trace and returns the traces that
// produced a non-empty result. Order follows the input order.
func (q *Query) Eval(traces []Trace) []Match {
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
	return out
}

// MatchesTrace reports whether the query selects at least one span in tr.
func (q *Query) MatchesTrace(tr Trace) bool { return len(q.evalTrace(tr)) > 0 }

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
