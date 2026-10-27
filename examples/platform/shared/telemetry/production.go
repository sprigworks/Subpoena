// Package telemetry owns platform-wide production export policy.
package telemetry

import (
	"example.com/platform/contract/generated/go/semconv"
	"github.com/sprigworks/subpoena/pkg/production"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// ProductionExporter wraps the service's exporter before it leaves the process.
func ProductionExporter(next sdktrace.SpanExporter) sdktrace.SpanExporter {
	return production.Exporter(next, semconv.AttributeTiers)
}
