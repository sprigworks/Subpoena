package traceql

import (
	"strings"
	"testing"
)

// fixture: root(open) -> auth(allowed=false, n=2) -> exec ; root -> exec2 ; plus deeper chain.
func fixture() Trace {
	return Trace{ID: "t1", Spans: []Span{
		{ID: "1", Name: "open", Attrs: map[string]any{"session.id": "s"}},
		{ID: "2", ParentID: "1", Name: "authorize", Attrs: map[string]any{"allowed": false, "n": int64(2), "who": "bob"}},
		{ID: "3", ParentID: "2", Name: "mid"},
		{ID: "4", ParentID: "3", Name: "exec"},
		{ID: "5", ParentID: "1", Name: "exec"},
	}}
}

func count(t *testing.T, q string) int {
	t.Helper()
	p, err := Parse(q)
	if err != nil {
		t.Fatalf("Parse(%q): %v", q, err)
	}
	ms := p.Eval([]Trace{fixture()})
	if len(ms) == 0 {
		return 0
	}
	return len(ms[0].Spans)
}

func TestSelection(t *testing.T) {
	cases := []struct {
		q    string
		want int
	}{
		{`{}`, 5},
		{`{ true }`, 5},
		{`{ false }`, 0},
		{`{ name = "exec" }`, 2},
		{`{ name != "exec" }`, 3},
		{`{ span.allowed = false }`, 1},
		{`{ span.allowed = true }`, 0},
		{`{ span.allowed != true }`, 1},
		{`{ span.n = 2 }`, 1},
		{`{ span.n != 2 }`, 0},
		{`{ span.who = "bob" && span.n = 2 }`, 1},
		{`{ span.who = "alice" || span.n = 2 }`, 1},
		{`{ name = "open" || name = "mid" }`, 2},
		{`{ (name = "open" || name = "mid") && span.session.id = "s" }`, 1},
		// Type mismatch never matches, for = and != alike.
		{`{ span.n = "2" }`, 0},
		{`{ span.n != "2" }`, 0},
		// Missing attribute: false for = and !=.
		{`{ span.nope = "x" }`, 0},
		{`{ span.nope != "x" }`, 0},
	}
	for _, c := range cases {
		if got := count(t, c.q); got != c.want {
			t.Errorf("%s: got %d spans, want %d", c.q, got, c.want)
		}
	}
}

func TestStructural(t *testing.T) {
	cases := []struct {
		q    string
		want int // spans selected (right-hand side)
	}{
		{`{ name = "authorize" } >> { name = "exec" }`, 1}, // only the deep exec (4)
		{`{ name = "open" } >> { name = "exec" }`, 2},
		{`{ name = "open" } > { name = "exec" }`, 1},      // only exec 5 is a direct child
		{`{ name = "authorize" } > { name = "exec" }`, 0}, // exec 4 is a grandchild
		{`{ name = "authorize" } > { name = "mid" }`, 1},
		{`{ name = "exec" } >> { name = "open" }`, 0}, // direction matters
		{`{ name = "open" } >> { name = "mid" } > { name = "exec" }`, 1},
		{`{ span.allowed = false } >> { name = "exec" }`, 1},
		{`{ span.allowed = true } >> { name = "exec" }`, 0},
		{`{ name = "exec" } >> { name = "exec" }`, 0}, // a span is not its own descendant
	}
	for _, c := range cases {
		if got := count(t, c.q); got != c.want {
			t.Errorf("%s: got %d, want %d", c.q, got, c.want)
		}
	}
}

func TestNoCrossTraceRelations(t *testing.T) {
	a := Trace{ID: "a", Spans: []Span{{ID: "1", Name: "authorize"}}}
	b := Trace{ID: "b", Spans: []Span{{ID: "2", ParentID: "1", Name: "exec"}}}
	q, _ := Parse(`{ name = "authorize" } >> { name = "exec" }`)
	if ms := q.Eval([]Trace{a, b}); len(ms) != 0 {
		t.Fatalf("relations must not cross traces: %v", ms)
	}
}

func TestOrphanAndCycleSafe(t *testing.T) {
	tr := Trace{ID: "x", Spans: []Span{
		{ID: "1", ParentID: "2", Name: "a"},
		{ID: "2", ParentID: "1", Name: "b"},
		{ID: "3", ParentID: "missing", Name: "c"},
	}}
	q, _ := Parse(`{ name = "a" } >> { name = "c" }`)
	if q.MatchesTrace(tr) {
		t.Fatal("orphan must not match")
	}
	q, _ = Parse(`{ name = "zzz" } >> { name = "b" }`)
	if q.MatchesTrace(tr) { // must terminate on a cycle
		t.Fatal("unexpected match")
	}
}

func TestInvariantQueryParses(t *testing.T) {
	const inv = `{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }`
	if _, err := Parse(inv); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsOutsideSubset(t *testing.T) {
	bad := map[string]string{
		`{ name =~ "a.*" }`:                 "regex",
		`{ span.x > 3 }`:                    "not in the supported subset",
		`{ span.x = 1.5 }`:                  "integer",
		`{ .foo = "x" }`:                    "not in the supported subset",
		`{ resource.service.name = "x" }`:   "not in the supported subset",
		`{ duration > 1s }`:                 "supported subset",
		`{ true } | count() > 1`:            "pipeline",
		`{ true } ~ { true }`:               "unexpected",
		`{ name = "a" `:                     "expected '}'",
		`{ name = "a" } >>`:                 "expected '{'",
		`{ name = "a" } { name = "b" }`:     "unexpected",
		`{ name = 3 }`:                      "name must be compared with a string",
		`{ name = "unterminated }`:          "unterminated",
		`{ name == "x" }`:                   "not in the supported subset",
		`{ span.x = foo }`:                  "not a string",
		`{ name = "a" } && { name = "b" }`:  "unexpected",
		`{ (name = "a" }`:                   "expected ')'",
		`{ span. = "a" }`:                   "not in the supported subset",
		`{ status = error }`:                "not in the supported subset",
		`{ name = "a" } &>> { name = "b" }`: "unexpected",
		`{ name = "a" } >>> { name = "b" }`: "expected '{'",
		`{ name != "a" && }`:                "expected a condition",
		"{ name = \"a\\q\" }":               "invalid string",
	}
	for q, want := range bad {
		_, err := Parse(q)
		if err == nil {
			t.Errorf("%s: expected error", q)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q does not contain %q", q, err, want)
		}
	}
}
