//subpoena:spec_derived
//subpoena:pure_logic

// Array and map values, from docs/traceql-subset.md ("Why arrays are
// refused"): a query that reads an attribute holding one is an error; other
// queries evaluate as usual. Plain data in, no telemetry.
package traceql

import (
	"errors"
	"testing"
)

func withArrays() []Trace {
	return []Trace{
		{ID: "t1", Spans: []Span{
			{ID: "1", Name: "authorize", Attrs: map[string]any{"allowed": false, "tags": Unsupported{Kind: "array"}}},
			{ID: "2", ParentID: "1", Name: "exec"},
		}},
		{ID: "t2", Spans: []Span{
			{ID: "3", Name: "exec", Attrs: map[string]any{"args": Unsupported{Kind: "kvlist"}}},
		}},
	}
}

func TestQueryReadingAnArrayIsRefused(t *testing.T) {
	for q, want := range map[string]UnsupportedValueError{
		`{ span.tags = "a" }`:                         {TraceID: "t1", SpanID: "1", Attr: "tags", Kind: "array"},
		`{ span.tags != "a" }`:                        {TraceID: "t1", SpanID: "1", Attr: "tags", Kind: "array"},
		`{ name = "exec" && span.args = "rm" }`:       {TraceID: "t2", SpanID: "3", Attr: "args", Kind: "kvlist"},
		`{ name = "authorize" } >> { span.args = 1 }`: {TraceID: "t2", SpanID: "3", Attr: "args", Kind: "kvlist"},
		// Refused even where evaluation would never reach the value: the name
		// condition fails first on span 1, and Tempo would still look.
		`{ name = "nothing" && span.tags = "a" }`: {TraceID: "t1", SpanID: "1", Attr: "tags", Kind: "array"},
	} {
		p, err := Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		ms, err := p.Eval(withArrays())
		var ue *UnsupportedValueError
		if !errors.As(err, &ue) {
			t.Errorf("%s: want *UnsupportedValueError, got %v (matches %v)", q, err, ms)
			continue
		}
		if *ue != want {
			t.Errorf("%s: error %+v, want %+v", q, *ue, want)
		}
		if ms != nil {
			t.Errorf("%s: an error comes with no matches, got %v", q, ms)
		}
	}
}

func TestQueriesNotReadingTheArrayEvaluate(t *testing.T) {
	for q, want := range map[string]int{
		`{ name = "exec" }`: 2,
		`{ name = "authorize" && span.allowed = false } >> { name = "exec" }`: 1,
		`{ span.missing = "x" }`: 0,
	} {
		p, err := Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		ms, err := p.Eval(withArrays())
		if err != nil {
			t.Errorf("%s: %v", q, err)
			continue
		}
		if len(ms) != want {
			t.Errorf("%s: %d matches, want %d", q, len(ms), want)
		}
	}
}

func TestMatchesTraceRefusesToo(t *testing.T) {
	p, err := Parse(`{ span.tags = "a" }`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.MatchesTrace(withArrays()[0]); err == nil {
		t.Fatal("want an error")
	}
	if ok, err := p.MatchesTrace(withArrays()[1]); err != nil || ok {
		t.Fatalf("trace without tags: %v %v", ok, err)
	}
}
