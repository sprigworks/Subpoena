// Package production keeps test-tier attributes out of production telemetry.
//
// Every registry attribute carries a `tier` annotation: `test` (high
// cardinality or diagnostic, never exported in production, such as
// session.id) or `all`. Weaver generates the map, semconv.AttributeTiers in
// each service's generated package. Tier 1 and tier 2 need the test-tier
// attributes (the invariants and the witness cross-checks read them); tier 3
// must not ship them.
//
// Two ways to apply it, from the same map:
//   - Exporter wraps a Go SpanExporter in the service.
//   - CollectorConfig emits an OpenTelemetry Collector transform processor, for
//     services in other languages or a collector in front of everything.
//
// The registry's own tiers are in examples/gateway/production, as a collector
// config generated from them (a test keeps it in step).
package production

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// TestTier is the tier annotation value of attributes never exported in
// production.
const TestTier = "test"

// TestTierKeys returns the keys whose tier is TestTier, sorted. T is the Tier
// type of a generated semconv package.
func TestTierKeys[T ~string](tiers map[string]T) []string {
	var keys []string
	for k, t := range tiers {
		if string(t) == TestTier {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// Exporter wraps next so that test-tier attributes are removed from every
// span, span event and link before export. Attributes not in tiers (upstream
// semantic conventions, resource attributes) pass through unchanged.
func Exporter[T ~string](next sdktrace.SpanExporter, tiers map[string]T) sdktrace.SpanExporter {
	drop := map[attribute.Key]bool{}
	for _, k := range TestTierKeys(tiers) {
		drop[attribute.Key(k)] = true
	}
	return &exporter{next: next, drop: drop}
}

type exporter struct {
	next sdktrace.SpanExporter
	drop map[attribute.Key]bool
}

func (e *exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = e.filter(s)
	}
	return e.next.ExportSpans(ctx, out)
}

func (e *exporter) Shutdown(ctx context.Context) error { return e.next.Shutdown(ctx) }

func (e *exporter) filter(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	f := &filtered{ReadOnlySpan: s, attrs: e.keep(s.Attributes())}
	for _, ev := range s.Events() {
		ev.Attributes = e.keep(ev.Attributes)
		f.events = append(f.events, ev)
	}
	for _, l := range s.Links() {
		l.Attributes = e.keep(l.Attributes)
		f.links = append(f.links, l)
	}
	return f
}

func (e *exporter) keep(in []attribute.KeyValue) []attribute.KeyValue {
	var out []attribute.KeyValue
	for _, kv := range in {
		if !e.drop[kv.Key] {
			out = append(out, kv)
		}
	}
	return out
}

// filtered is a span with its attributes, events and links replaced; every
// other method is the original span's. Embedding the interface is how a
// ReadOnlySpan is wrapped outside the SDK.
type filtered struct {
	sdktrace.ReadOnlySpan
	attrs  []attribute.KeyValue
	events []sdktrace.Event
	links  []sdktrace.Link
}

func (f *filtered) Attributes() []attribute.KeyValue { return f.attrs }
func (f *filtered) Events() []sdktrace.Event         { return f.events }
func (f *filtered) Links() []sdktrace.Link           { return f.links }

// CollectorConfig returns an OpenTelemetry Collector `processors:` block
// holding one transform processor, transform/<name>, that deletes the
// test-tier attributes from spans and span events. Add it to the production
// traces pipeline. (OTTL has no span-link context; links keep their
// attributes, which is the one difference from Exporter.) It returns "" when
// no attribute is test-tier.
func CollectorConfig[T ~string](name string, tiers map[string]T) string {
	keys := TestTierKeys(tiers)
	if len(keys) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "processors:\n  transform/%s:\n    error_mode: ignore\n    trace_statements:\n", name)
	for _, ctx := range []string{"span", "spanevent"} {
		fmt.Fprintf(&b, "      - context: %s\n        statements:\n", ctx)
		for _, k := range keys {
			fmt.Fprintf(&b, "          - delete_key(attributes, %q)\n", k)
		}
	}
	return b.String()
}
