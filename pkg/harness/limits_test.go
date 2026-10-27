//subpoena:impl_derived

package harness

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const denyThenExec = `{ name = "authorize" && span.decision = "deny" } >> { name = "exec" }`

// authorizeThenExec records an authorize span whose decision attribute comes
// after filler attributes, with an exec child: a violation of denyThenExec.
func authorizeThenExec(tracer trace.Tracer, filler int) {
	ctx, a := tracer.Start(context.Background(), "authorize")
	for i := 0; i < filler; i++ {
		a.SetAttributes(attribute.Int(fmt.Sprintf("filler.%d", i), i))
	}
	a.SetAttributes(attribute.String("decision", "deny"))
	_, e := tracer.Start(ctx, "exec")
	e.End()
	a.End()
}

// The SDK's default attribute count limit is 128. A decision attribute set
// after 128 others must still be captured, or absence of the violation would
// Pass.
func TestManyAttributesAreKept(t *testing.T) {
	h := New()
	authorizeThenExec(h.Tracer("t"), 200)
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := tr.Absent(denyThenExec); v != Fail {
		t.Fatalf("absent = %v, want Fail", v)
	}
}

// The harness owns its span limits: OTEL_*_LIMIT variables in the test
// environment must not drop or truncate what the code under test recorded.
func TestEnvironmentLimitsAreIgnored(t *testing.T) {
	for _, k := range []string{
		"OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "OTEL_ATTRIBUTE_COUNT_LIMIT",
		"OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT",
		"OTEL_SPAN_EVENT_COUNT_LIMIT", "OTEL_SPAN_LINK_COUNT_LIMIT",
		"OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT", "OTEL_LINK_ATTRIBUTE_COUNT_LIMIT",
	} {
		t.Setenv(k, "1")
	}
	h := New()
	authorizeThenExec(h.Tracer("t"), 3)
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := tr.Absent(denyThenExec); v != Fail {
		t.Fatalf("absent = %v, want Fail", v)
	}
}

// withLimits returns a Harness whose provider applies the given limits, as a
// caller wiring its own provider to a Recorder might.
func withLimits(l sdktrace.SpanLimits) *Harness {
	rec := NewRecorder(0)
	tp := sdktrace.NewTracerProvider( //subpoena:own_provider tests the Recorder under a caller's own span limits
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithRawSpanLimits(l),
		sdktrace.WithSpanProcessor(rec),
	)
	return &Harness{rec: rec, tp: tp}
}

func TestSDKDroppedAttributesMakeCaptureIncomplete(t *testing.T) {
	l := spanLimits
	l.AttributeCountLimit = 1
	h := withLimits(l)
	authorizeThenExec(h.Tracer("t"), 1)
	tr, err := h.Collect(context.Background())
	var ie *IncompleteError
	if !errors.As(err, &ie) || !reflect.DeepEqual(ie.Truncated, []string{"authorize"}) {
		t.Fatalf("want IncompleteError naming authorize, got %v", err)
	}
	if !strings.Contains(err.Error(), "spans lost attributes, events or links: authorize") {
		t.Fatal(err)
	}
	if tr.Complete() {
		t.Fatal("must be incomplete")
	}
	if v, _ := tr.Absent(denyThenExec); v != Inconclusive {
		t.Fatalf("absent = %v, want Inconclusive", v)
	}
}

func TestSDKDroppedEventsAndLinksMakeCaptureIncomplete(t *testing.T) {
	cases := []struct {
		name   string
		limit  func(*sdktrace.SpanLimits)
		record func(trace.Tracer)
	}{
		{"events", func(l *sdktrace.SpanLimits) { l.EventCountLimit = 1 }, func(tr trace.Tracer) {
			_, s := tr.Start(context.Background(), "s")
			s.AddEvent("one")
			s.AddEvent("two")
			s.End()
		}},
		{"event attributes", func(l *sdktrace.SpanLimits) { l.AttributePerEventCountLimit = 1 }, func(tr trace.Tracer) {
			_, s := tr.Start(context.Background(), "s")
			s.AddEvent("e", trace.WithAttributes(attribute.Int("a", 1), attribute.Int("b", 2)))
			s.End()
		}},
		{"links", func(l *sdktrace.SpanLimits) { l.LinkCountLimit = 1 }, func(tr trace.Tracer) {
			_, other := tr.Start(context.Background(), "other")
			other.End()
			link := trace.Link{SpanContext: other.SpanContext()}
			_, s := tr.Start(context.Background(), "s", trace.WithLinks(link, link))
			s.End()
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := spanLimits
			c.limit(&l)
			h := withLimits(l)
			c.record(h.Tracer("t"))
			_, err := h.Collect(context.Background())
			var ie *IncompleteError
			if !errors.As(err, &ie) || !reflect.DeepEqual(ie.Truncated, []string{"s"}) {
				t.Fatalf("want IncompleteError naming s, got %v", err)
			}
		})
	}
}
