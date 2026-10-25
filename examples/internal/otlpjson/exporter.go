// Package otlpjson is a minimal OTLP/HTTP JSON trace exporter built on the
// standard library only.
//
// It exists because the standard otlptracehttp exporter drags in protobuf and
// gRPC, whose module hosts were unreachable in the environment this scaffold
// was built in. In a normal environment, replace it with
// go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp; nothing
// else in the example changes.
package otlpjson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Exporter posts spans to {endpoint}/v1/traces as OTLP JSON.
type Exporter struct {
	url     string
	service string
	client  *http.Client
}

// New returns an Exporter. endpoint is a base URL such as http://collector:4318.
func New(endpoint, serviceName string) *Exporter {
	return &Exporter{
		url:     strings.TrimRight(endpoint, "/") + "/v1/traces",
		service: serviceName,
		client:  http.DefaultClient,
	}
}

type kv struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

type span struct {
	TraceID      string         `json:"traceId"`
	SpanID       string         `json:"spanId"`
	ParentSpanID string         `json:"parentSpanId,omitempty"`
	Name         string         `json:"name"`
	Kind         int            `json:"kind"`
	Start        string         `json:"startTimeUnixNano"`
	End          string         `json:"endTimeUnixNano"`
	Attributes   []kv           `json:"attributes,omitempty"`
	Status       map[string]any `json:"status,omitempty"`
}

// ExportSpans implements sdktrace.SpanExporter.
func (e *Exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	out := make([]span, 0, len(spans))
	for _, s := range spans {
		js := span{
			TraceID: s.SpanContext().TraceID().String(),
			SpanID:  s.SpanContext().SpanID().String(),
			Name:    s.Name(),
			Kind:    int(s.SpanKind()), // OTel Go and OTLP share values: 1 internal, 2 server, ...
			Start:   strconv.FormatInt(s.StartTime().UnixNano(), 10),
			End:     strconv.FormatInt(s.EndTime().UnixNano(), 10),
		}
		if p := s.Parent(); p.SpanID().IsValid() {
			js.ParentSpanID = p.SpanID().String()
		}
		for _, a := range s.Attributes() {
			js.Attributes = append(js.Attributes, kv{Key: string(a.Key), Value: anyValue(a.Value)})
		}
		if st := s.Status(); st.Code != 0 {
			// OTel Go: Unset=0 Error=1 Ok=2. OTLP: UNSET=0 OK=1 ERROR=2.
			code := 2
			if st.Code == 2 {
				code = 1
			}
			js.Status = map[string]any{"code": code, "message": st.Description}
		}
		out = append(out, js)
	}
	body := map[string]any{"resourceSpans": []any{map[string]any{
		"resource": map[string]any{"attributes": []kv{{Key: "service.name", Value: map[string]any{"stringValue": e.service}}}},
		"scopeSpans": []any{map[string]any{
			"scope": map[string]any{"name": "subpoena/examples/gateway"},
			"spans": out,
		}},
	}}}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("otlpjson: collector returned %s", resp.Status)
	}
	return nil
}

// Shutdown implements sdktrace.SpanExporter.
func (e *Exporter) Shutdown(context.Context) error { return nil }

func anyValue(v attribute.Value) map[string]any {
	switch v.Type() {
	case attribute.BOOL:
		return map[string]any{"boolValue": v.AsBool()}
	case attribute.INT64:
		return map[string]any{"intValue": strconv.FormatInt(v.AsInt64(), 10)} // int64 is a JSON string in OTLP
	case attribute.FLOAT64:
		return map[string]any{"doubleValue": v.AsFloat64()}
	}
	return map[string]any{"stringValue": v.Emit()}
}
