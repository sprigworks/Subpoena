// Package harness is the tier-1 test harness: an in-memory OpenTelemetry
// exporter with completeness tracking, and TraceQL queries over what it saw.
//
// Typical use:
//
//	h := harness.New()
//	tracer := h.Tracer("my-app")
//	... run the code under test with tracer ...
//	tr, err := h.Collect(ctx)       // required before asserting
//	harness.RequireAbsent(t, tr, `{ ... } >> { ... }`)
package harness

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Harness owns a TracerProvider wired to a Recorder.
type Harness struct {
	rec *Recorder
	tp  *sdktrace.TracerProvider
}

// New returns a Harness with DefaultCapacity.
func New() *Harness { return NewWithCapacity(DefaultCapacity) }

// spanLimits are the harness's own and are unlimited: the SDK neither drops
// nor truncates attributes, events or links, whatever the OTEL_*_LIMIT
// environment variables say. A truncated attribute changes what a query
// matches, and the SDK does not count truncation as a drop.
var spanLimits = sdktrace.SpanLimits{
	AttributeValueLengthLimit:   -1,
	AttributeCountLimit:         -1,
	EventCountLimit:             -1,
	LinkCountLimit:              -1,
	AttributePerEventCountLimit: -1,
	AttributePerLinkCountLimit:  -1,
}

// NewWithCapacity returns a Harness that records at most capacity finished
// spans; further spans are counted as dropped and make Collect fail.
func NewWithCapacity(capacity int) *Harness {
	rec := NewRecorder(capacity)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(resource.Empty()),
		sdktrace.WithRawSpanLimits(spanLimits),
		sdktrace.WithSpanProcessor(rec),
	)
	return &Harness{rec: rec, tp: tp}
}

// TracerProvider returns the provider to inject into the code under test.
func (h *Harness) TracerProvider() trace.TracerProvider { return h.tp }

// Tracer is shorthand for TracerProvider().Tracer(name).
func (h *Harness) Tracer(name string) trace.Tracer { return h.tp.Tracer(name) }

// IncompleteError is returned by Collect when the capture cannot be trusted.
type IncompleteError struct {
	Dropped    int
	Unfinished []string // names of spans started but never ended
	Truncated  []string // distinct names of spans that lost attributes, events or links
}

func (e *IncompleteError) Error() string {
	var parts []string
	if e.Dropped > 0 {
		parts = append(parts, fmt.Sprintf("%d span(s) dropped", e.Dropped))
	}
	if len(e.Unfinished) > 0 {
		parts = append(parts, fmt.Sprintf("%d span(s) never ended: %s", len(e.Unfinished), strings.Join(e.Unfinished, ", ")))
	}
	if len(e.Truncated) > 0 {
		parts = append(parts, "spans lost attributes, events or links: "+strings.Join(e.Truncated, ", "))
	}
	return "harness: capture incomplete: " + strings.Join(parts, "; ")
}

// Collect force-flushes the provider and returns a queryable snapshot.
//
// If any span was dropped, any started span has not ended, or the SDK dropped
// any attribute, event or link of a recorded span, it returns the
// snapshot together with an *IncompleteError. The snapshot is marked
// incomplete, so absence assertions on it return Inconclusive rather than
// Pass. Callers should treat the error as a test failure unless they are
// deliberately testing that behaviour.
//
//subpoena:enforcement_point
func (h *Harness) Collect(ctx context.Context) (*Trace, error) {
	if err := h.tp.ForceFlush(ctx); err != nil {
		return nil, fmt.Errorf("harness: force flush: %w", err)
	}
	s := h.rec.snapshot()
	sort.Strings(s.unfinished)
	sort.Strings(s.truncated)
	t := &Trace{
		traces:     convert(s.spans),
		complete:   s.dropped == 0 && len(s.unfinished) == 0 && len(s.truncated) == 0,
		dropped:    s.dropped,
		unfinished: s.unfinished,
	}
	if !t.complete {
		return t, &IncompleteError{Dropped: s.dropped, Unfinished: s.unfinished, Truncated: s.truncated} //subpoena:enforcement
	}
	return t, nil
}

// Shutdown releases the provider. Spans ending afterwards count as dropped.
func (h *Harness) Shutdown(ctx context.Context) error { return h.tp.Shutdown(ctx) }
