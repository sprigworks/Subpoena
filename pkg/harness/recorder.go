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
// overflow) and remembers which spans were started but never ended, and how
// many finished spans it had to drop for lack of capacity. Collect uses this to
// decide whether the capture can support absence claims.
type Recorder struct {
	mu       sync.Mutex
	capacity int
	started  map[string]string // span ID -> name, for spans not yet ended
	ended    []sdktrace.ReadOnlySpan
	dropped  int
	lateEnds int
	closed   bool
}

// NewRecorder returns a Recorder. capacity <= 0 means DefaultCapacity.
func NewRecorder(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Recorder{capacity: capacity, started: map[string]string{}}
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
	r.ended = append(r.ended, s)
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
	return s
}
