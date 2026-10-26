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

// NewWithCapacity returns a Harness that records at most capacity finished
// spans; further spans are counted as dropped and make Collect fail.
func NewWithCapacity(capacity int) *Harness {
	rec := NewRecorder(capacity)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(resource.Empty()),
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
}

func (e *IncompleteError) Error() string {
	var parts []string
	if e.Dropped > 0 {
		parts = append(parts, fmt.Sprintf("%d span(s) dropped", e.Dropped))
	}
	if len(e.Unfinished) > 0 {
		parts = append(parts, fmt.Sprintf("%d span(s) never ended: %s", len(e.Unfinished), strings.Join(e.Unfinished, ", ")))
	}
	return "harness: capture incomplete: " + strings.Join(parts, "; ")
}

// Collect force-flushes the provider and returns a queryable snapshot.
//
// If any span was dropped, or any started span has not ended, it returns the
// snapshot together with an *IncompleteError. The snapshot is marked
// incomplete, so absence assertions on it return Inconclusive rather than
// Pass. Callers should treat the error as a test failure unless they are
// deliberately testing that behaviour.
func (h *Harness) Collect(ctx context.Context) (*Trace, error) {
	if err := h.tp.ForceFlush(ctx); err != nil {
		return nil, fmt.Errorf("harness: force flush: %w", err)
	}
	s := h.rec.snapshot()
	sort.Strings(s.unfinished)
	t := &Trace{
		traces:     convert(s.spans),
		complete:   s.dropped == 0 && len(s.unfinished) == 0,
		dropped:    s.dropped,
		unfinished: s.unfinished,
	}
	if !t.complete {
		return t, &IncompleteError{Dropped: s.dropped, Unfinished: s.unfinished}
	}
	return t, nil
}

// Shutdown releases the provider. Spans ending afterwards count as dropped.
func (h *Harness) Shutdown(ctx context.Context) error { return h.tp.Shutdown(ctx) }
