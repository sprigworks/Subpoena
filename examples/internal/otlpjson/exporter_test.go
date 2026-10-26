//subpoena:impl_derived

package otlpjson

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestExportShape(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var path, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		path, ctype = r.URL.Path, r.Header.Get("Content-Type")
		bodies = append(bodies, string(b))
	}))
	defer srv.Close()

	// A syncer exports each span as it ends, so the child and parent arrive
	// in separate requests.
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(New(srv.URL, "svc")))
	ctx, parent := tp.Tracer("t").Start(context.Background(), "parent")
	_, child := tp.Tracer("t").Start(ctx, "child")
	child.SetAttributes(attribute.Bool("b", false), attribute.Int("n", 7), attribute.String("s", "x"))
	child.SetStatus(codes.Error, "boom")
	child.End()
	parent.End()

	mu.Lock()
	defer mu.Unlock()
	if path != "/v1/traces" || ctype != "application/json" {
		t.Fatalf("path=%q content-type=%q", path, ctype)
	}
	all := strings.Join(bodies, "\n")
	for _, want := range []string{
		`"name":"child"`, `"parentSpanId":"`, `{"key":"b","value":{"boolValue":false}}`,
		`{"key":"n","value":{"intValue":"7"}}`, `{"key":"s","value":{"stringValue":"x"}}`,
		`"status":{"code":2,"message":"boom"}`, `"stringValue":"svc"`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("payload missing %s\n%s", want, all)
		}
	}
}

func TestCollectorErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	e := New(srv.URL, "svc")

	var captured []sdktrace.ReadOnlySpan
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanCapture{&captured}))
	_, s := tp.Tracer("t").Start(context.Background(), "x")
	s.End()

	if err := e.ExportSpans(context.Background(), captured); err == nil {
		t.Fatal("a 500 from the collector must be an error")
	}
	if err := e.ExportSpans(context.Background(), nil); err != nil {
		t.Fatal("empty export must be a no-op")
	}
}

type spanCapture struct{ out *[]sdktrace.ReadOnlySpan }

func (c spanCapture) ExportSpans(_ context.Context, s []sdktrace.ReadOnlySpan) error {
	*c.out = append(*c.out, s...)
	return nil
}
func (spanCapture) Shutdown(context.Context) error { return nil }
