package harness

import (
	"sort"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

// Trace is an immutable, queryable snapshot of the spans captured by a
// Harness. It knows whether the capture was complete.
type Trace struct {
	traces     []traceql.Trace
	complete   bool
	dropped    int
	unfinished []string
}

// Complete reports whether no span was dropped and none was left unfinished.
func (t *Trace) Complete() bool { return t.complete }

// TraceIDs returns the IDs of the traces in the snapshot, sorted.
func (t *Trace) TraceIDs() []string {
	ids := make([]string, 0, len(t.traces))
	for _, tr := range t.traces {
		ids = append(ids, tr.ID)
	}
	sort.Strings(ids)
	return ids
}

// SpanCount returns the number of captured spans.
func (t *Trace) SpanCount() int {
	n := 0
	for _, tr := range t.traces {
		n += len(tr.Spans)
	}
	return n
}

// Spans returns the captured spans of one trace (nil if unknown).
func (t *Trace) Spans(traceID string) []traceql.Span {
	for _, tr := range t.traces {
		if tr.ID == traceID {
			return append([]traceql.Span(nil), tr.Spans...)
		}
	}
	return nil
}

// Result is the outcome of a query.
type Result struct {
	Matches  []traceql.Match
	Complete bool
}

// Count returns the number of matching traces.
func (r *Result) Count() int { return len(r.Matches) }

// Query evaluates a TraceQL string against the snapshot. The same string can
// be used unchanged in OATS and in an alert rule. The error is non-nil if q
// does not parse, or reads an attribute that holds an array value in the
// snapshot (*traceql.UnsupportedValueError).
func (t *Trace) Query(q string) (*Result, error) {
	p, err := traceql.Parse(q)
	if err != nil {
		return nil, err
	}
	ms, err := p.Eval(t.traces)
	if err != nil {
		return nil, err
	}
	return &Result{Matches: ms, Complete: t.complete}, nil
}

func convert(spans []sdktrace.ReadOnlySpan) []traceql.Trace {
	byTrace := map[string]*traceql.Trace{}
	var order []string
	for _, s := range spans {
		tid := s.SpanContext().TraceID().String()
		tr, ok := byTrace[tid]
		if !ok {
			tr = &traceql.Trace{ID: tid}
			byTrace[tid] = tr
			order = append(order, tid)
		}
		sp := traceql.Span{
			ID:    s.SpanContext().SpanID().String(),
			Name:  s.Name(),
			Attrs: map[string]any{},
		}
		if p := s.Parent(); p.SpanID().IsValid() {
			sp.ParentID = p.SpanID().String()
		}
		for _, kv := range s.Attributes() {
			sp.Attrs[string(kv.Key)] = attrValue(kv.Value)
		}
		tr.Spans = append(tr.Spans, sp)
	}
	out := make([]traceql.Trace, 0, len(order))
	for _, id := range order {
		out = append(out, *byTrace[id])
	}
	return out
}

func attrValue(v attribute.Value) any {
	switch v.Type() {
	case attribute.BOOL:
		return v.AsBool()
	case attribute.INT64:
		return v.AsInt64()
	case attribute.FLOAT64:
		return v.AsFloat64()
	case attribute.STRING:
		return v.AsString()
	}
	// Slices: outside the subset, refused by any query that reads them.
	return traceql.Unsupported{Kind: "array"}
}
