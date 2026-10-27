package harness

import (
	"context"
	"sync"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// DefaultCapacity is the number of finished spans a Recorder keeps before it
// starts counting drops.
const DefaultCapacity = 10000

// Recorder is an in-memory span processor with completeness tracking.
//
// It records finished spans synchronously (no batching queue that could
// overflow) and remembers which spans were started but never ended, how many
// finished spans it had to drop for lack of capacity, and which spans the SDK
// recorded with attributes, events or links dropped by its span limits. Collect uses this to
// decide whether the capture can support absence claims.
type Recorder struct {
	mu       sync.Mutex
	capacity int
	started  map[string]string // span ID -> name, for spans not yet ended
	ended    []sdktrace.ReadOnlySpan
	dropped  int
	lateEnds int
	lossy    map[string]bool // names of spans with SDK-dropped attributes, events or links
	closed   bool
}

// NewRecorder returns a Recorder. capacity <= 0 means DefaultCapacity.
func NewRecorder(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Recorder{capacity: capacity, started: map[string]string{}, lossy: map[string]bool{}}
}

// OnStart implements sdktrace.SpanProcessor.
func (r *Recorder) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started[s.SpanContext().SpanID().String()] = s.Name()
}

// OnEnd implements sdktrace.SpanProcessor.
func (r *Recorder) OnEnd(s sdktrace.ReadOnlySpan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.started, s.SpanContext().SpanID().String())
	if r.closed {
		r.lateEnds++
		return
	}
	if len(r.ended) >= r.capacity {
		r.dropped++
		return
	}
	if lossy(s) {
		r.lossy[s.Name()] = true
	}
	r.ended = append(r.ended, s)
}

// lossy reports whether the SDK's span limits dropped any attribute, event or
// link of s, or any attribute of one of its events or links.
func lossy(s sdktrace.ReadOnlySpan) bool {
	if s.DroppedAttributes() > 0 || s.DroppedEvents() > 0 || s.DroppedLinks() > 0 {
		return true
	}
	for _, e := range s.Events() {
		if e.DroppedAttributeCount > 0 {
			return true
		}
	}
	for _, l := range s.Links() {
		if l.DroppedAttributeCount > 0 {
			return true
		}
	}
	return false
}

// Shutdown implements sdktrace.SpanProcessor. Spans ending afterwards are
// counted as dropped.
func (r *Recorder) Shutdown(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// ForceFlush implements sdktrace.SpanProcessor. Recording is synchronous, so
// there is nothing buffered to flush.
func (r *Recorder) ForceFlush(context.Context) error { return nil }

type snapshot struct {
	spans      []sdktrace.ReadOnlySpan
	dropped    int
	unfinished []string
	truncated  []string
}

func (r *Recorder) snapshot() snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := snapshot{
		spans:   append([]sdktrace.ReadOnlySpan(nil), r.ended...),
		dropped: r.dropped + r.lateEnds,
	}
	for _, name := range r.started {
		s.unfinished = append(s.unfinished, name)
	}
	for name := range r.lossy {
		s.truncated = append(s.truncated, name)
	}
	return s
}
