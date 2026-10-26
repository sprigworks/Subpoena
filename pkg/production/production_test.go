//subpoena:impl_derived

package production

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/sprigworks/subpoena/generated/go/semconv"
)

// upstream is an attribute outside the registry (an upstream semantic
// convention); it is not this package's to drop.
const upstream = attribute.Key("http.request.method")

func keys(kvs []attribute.KeyValue) []string {
	var out []string
	for _, kv := range kvs {
		out = append(out, string(kv.Key))
	}
	return out
}

func TestExporterDropsTestTierEverywhere(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(Exporter(mem, semconv.AttributeTiers)))
	tr := tp.Tracer("t")

	_, linked := tr.Start(context.Background(), semconv.SpanAgentSessionOpen)
	linked.End()
	_, s := tr.Start(context.Background(), semconv.SpanAgentSessionAuthorize,
		trace.WithLinks(trace.Link{
			SpanContext: linked.SpanContext(),
			Attributes:  []attribute.KeyValue{attribute.String(semconv.AttrSessionId, "s"), upstream.String("GET")},
		}),
		trace.WithAttributes(
			attribute.String(semconv.AttrSessionId, "sess-1"),
			attribute.Bool(semconv.AttrAuthorizationAllowed, false),
			attribute.String(semconv.AttrAuthorizationPolicyId, "p"),
			upstream.String("POST"),
		))
	s.AddEvent("e", trace.WithAttributes(
		attribute.String(semconv.AttrProcessCommandLine, "sleep 1"),
		attribute.Bool(semconv.AttrAuthorizationAllowed, false),
	))
	s.End()

	got := mem.GetSpans()
	if len(got) != 2 {
		t.Fatalf("want 2 spans, got %d", len(got))
	}
	sp := got[1]
	if want := []string{semconv.AttrAuthorizationAllowed, semconv.AttrAuthorizationPolicyId, string(upstream)}; !reflect.DeepEqual(keys(sp.Attributes), want) {
		t.Errorf("span attributes %v, want %v", keys(sp.Attributes), want)
	}
	if want := []string{semconv.AttrAuthorizationAllowed}; !reflect.DeepEqual(keys(sp.Events[0].Attributes), want) {
		t.Errorf("event attributes %v, want %v", keys(sp.Events[0].Attributes), want)
	}
	if want := []string{string(upstream)}; !reflect.DeepEqual(keys(sp.Links[0].Attributes), want) {
		t.Errorf("link attributes %v, want %v", keys(sp.Links[0].Attributes), want)
	}
	// Everything else is the original span.
	if sp.Name != semconv.SpanAgentSessionAuthorize || !sp.SpanContext.Equal(s.SpanContext()) {
		t.Errorf("span identity changed: %s %v", sp.Name, sp.SpanContext)
	}
}

func TestEveryTestTierKeyIsDropped(t *testing.T) {
	// The registry's test-tier set, so a new test-tier attribute is covered
	// without editing this test, and the set is never empty by accident.
	ks := TestTierKeys(semconv.AttributeTiers)
	if len(ks) == 0 {
		t.Fatal("no test-tier attributes in the registry")
	}
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(Exporter(mem, semconv.AttributeTiers)))
	var attrs []attribute.KeyValue
	for _, k := range ks {
		attrs = append(attrs, attribute.String(k, "x"))
	}
	_, s := tp.Tracer("t").Start(context.Background(), semconv.SpanAgentSessionExec, trace.WithAttributes(attrs...))
	s.End()
	if got := mem.GetSpans()[0].Attributes; len(got) != 0 {
		t.Errorf("test-tier attributes exported: %v", keys(got))
	}
}

func TestCollectorConfigMatchesTheExample(t *testing.T) {
	cfg := CollectorConfig("subpoena-drop-test-tier", semconv.AttributeTiers)
	for _, k := range TestTierKeys(semconv.AttributeTiers) {
		if !strings.Contains(cfg, `delete_key(attributes, "`+k+`")`) {
			t.Errorf("collector config does not delete %s", k)
		}
	}
	const path = "../../examples/gateway/production/otelcol.yaml"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), cfg) {
		t.Errorf("%s is out of step with the registry tiers; it must contain:\n%s", path, cfg)
	}
}
