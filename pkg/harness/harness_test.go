//subpoena:impl_derived

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

const q = `{ name = "a" && span.k = false } >> { name = "b" }`

func TestCollectCompleteAndQuery(t *testing.T) {
	h := New()
	ctx, a := h.Tracer("t").Start(context.Background(), "a")
	a.SetAttributes(attribute.Bool("k", false), attribute.Int("n", 3), attribute.String("s", "x"))
	_, b := h.Tracer("t").Start(ctx, "b")
	b.End()
	a.End()

	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Complete() || tr.SpanCount() != 2 || len(tr.TraceIDs()) != 1 {
		t.Fatalf("unexpected snapshot: complete=%v spans=%d", tr.Complete(), tr.SpanCount())
	}
	r, err := tr.Query(q)
	if err != nil || r.Count() != 1 {
		t.Fatalf("query: %v %v", r, err)
	}
	if v, _ := tr.Exists(q); v != Pass {
		t.Fatalf("exists = %v", v)
	}
	if v, _ := tr.Absent(q); v != Fail {
		t.Fatalf("absent = %v", v)
	}
	if v, _ := tr.Absent(`{ name = "zzz" }`); v != Pass {
		t.Fatalf("absent of nothing = %v", v)
	}
	if r, _ := tr.Query(`{ span.n = 3 && span.s = "x" }`); r.Count() != 1 {
		t.Fatal("int/string attrs not converted")
	}
}

func TestUnfinishedSpanIsInconclusive(t *testing.T) {
	h := New()
	_, a := h.Tracer("t").Start(context.Background(), "a") // never ended
	_ = a
	tr, err := h.Collect(context.Background())
	var ie *IncompleteError
	if !errors.As(err, &ie) || len(ie.Unfinished) != 1 || ie.Unfinished[0] != "a" {
		t.Fatalf("expected IncompleteError naming span a, got %v", err)
	}
	if tr.Complete() {
		t.Fatal("must be incomplete")
	}
	if v, _ := tr.Absent(`{ name = "zzz" }`); v != Inconclusive {
		t.Fatalf("absence on incomplete capture = %v, want Inconclusive", v)
	}
	if v, _ := tr.Exists(`{ name = "zzz" }`); v != Inconclusive {
		t.Fatalf("exists-miss on incomplete capture = %v, want Inconclusive", v)
	}
}

func TestMatchOnIncompleteCaptureIsStillDefinitive(t *testing.T) {
	h := New()
	_, done := h.Tracer("t").Start(context.Background(), "seen")
	done.End()
	_, open := h.Tracer("t").Start(context.Background(), "open")
	_ = open
	tr, _ := h.Collect(context.Background())
	if v, _ := tr.Absent(`{ name = "seen" }`); v != Fail {
		t.Fatalf("a captured match must Fail absence even when incomplete, got %v", v)
	}
	if v, _ := tr.Exists(`{ name = "seen" }`); v != Pass {
		t.Fatalf("got %v", v)
	}
}

func TestDroppedSpansMakeCollectFail(t *testing.T) {
	h := NewWithCapacity(1)
	for i := 0; i < 3; i++ {
		_, s := h.Tracer("t").Start(context.Background(), "s")
		s.End()
	}
	tr, err := h.Collect(context.Background())
	var ie *IncompleteError
	if !errors.As(err, &ie) || ie.Dropped != 2 {
		t.Fatalf("expected 2 dropped, got %v", err)
	}
	if !strings.Contains(err.Error(), "2 span(s) dropped") {
		t.Fatal(err)
	}
	if v, _ := tr.Absent(`{ name = "nope" }`); v != Inconclusive {
		t.Fatalf("got %v", v)
	}
}

func TestSpansEndingAfterShutdownAreDropped(t *testing.T) {
	h := New()
	_, s := h.Tracer("t").Start(context.Background(), "late")
	_ = h.Shutdown(context.Background())
	s.End()
	// After shutdown the provider no longer invokes processors, so this is
	// observed as an unfinished span instead; either way capture is incomplete.
	tr, err := h.Collect(context.Background())
	if err == nil || tr.Complete() {
		t.Fatal("capture with a span lost to shutdown must be incomplete")
	}
}

func TestBadQuery(t *testing.T) {
	h := New()
	tr, _ := h.Collect(context.Background())
	if _, err := tr.Query(`{ name =~ "x" }`); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := tr.Absent(`nonsense`); err == nil {
		t.Fatal("expected parse error")
	}
}

type fakeTB struct {
	testing.TB
	fatal string
	logs  []string
}

func (f *fakeTB) Helper()                        {}
func (f *fakeTB) Fatalf(format string, a ...any) { f.fatal = format; panic("fatal") }
func (f *fakeTB) Logf(format string, a ...any)   { f.logs = append(f.logs, format) }

func runRequire(fn func(tb testing.TB)) (fatal string, logs []string) {
	f := &fakeTB{}
	func() {
		defer func() { _ = recover() }()
		fn(f)
	}()
	return f.fatal, f.logs
}

func TestRequireInconclusiveFailsByDefault(t *testing.T) {
	h := New()
	_, s := h.Tracer("t").Start(context.Background(), "x") // unfinished
	_ = s
	tr, _ := h.Collect(context.Background())

	fatal, _ := runRequire(func(tb testing.TB) { RequireAbsent(tb, tr, `{ name = "zzz" }`) })
	if fatal == "" {
		t.Fatal("inconclusive must fail by default")
	}
	fatal, logs := runRequire(func(tb testing.TB) {
		RequireAbsent(tb, tr, `{ name = "zzz" }`, Options{AllowInconclusive: true})
	})
	if fatal != "" || len(logs) != 1 {
		t.Fatalf("allowed inconclusive should log, not fail: %q %v", fatal, logs)
	}
}

func TestRequirePassAndFail(t *testing.T) {
	h := New()
	_, s := h.Tracer("t").Start(context.Background(), "x")
	s.End()
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fatal, _ := runRequire(func(tb testing.TB) { RequireAbsent(tb, tr, `{ name = "zzz" }`) }); fatal != "" {
		t.Fatal("should pass")
	}
	if fatal, _ := runRequire(func(tb testing.TB) { RequireAbsent(tb, tr, `{ name = "x" }`) }); fatal == "" {
		t.Fatal("should fail")
	}
	if fatal, _ := runRequire(func(tb testing.TB) { RequireExists(tb, tr, `{ name = "x" }`) }); fatal != "" {
		t.Fatal("should pass")
	}
}
