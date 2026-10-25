// Command gateway runs the toy agent gateway as an HTTP service exporting
// OTLP/JSON traces. Used by the OATS stack in ../../oats.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/sprigworks/subpoena/examples/gateway"
	"github.com/sprigworks/subpoena/examples/internal/otlpjson"
	"github.com/sprigworks/subpoena/generated/go/semconv"
)

func main() {
	addr := env("GATEWAY_ADDR", ":8080")
	endpoint := env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")

	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(
		otlpjson.New(endpoint, env("OTEL_SERVICE_NAME", "gateway")),
		sdktrace.WithBatchTimeout(500*time.Millisecond),
	))
	// Session cgroups are configured by SUBPOENA_CGROUP_ROOT (read by gateway.New).
	// SUBPOENA_CORRELATION_FALLBACK says what exec spans record when no cgroup
	// could be used: lineage (default) or argument.
	var opts []gateway.Option
	switch fb := env("SUBPOENA_CORRELATION_FALLBACK", semconv.ValSubpoenaWitnessCorrelationLineage); fb {
	case semconv.ValSubpoenaWitnessCorrelationLineage, semconv.ValSubpoenaWitnessCorrelationArgument:
		opts = append(opts, gateway.WithFallbackCorrelation(fb))
	default:
		log.Fatalf("SUBPOENA_CORRELATION_FALLBACK=%q: want %q or %q", fb,
			semconv.ValSubpoenaWitnessCorrelationLineage, semconv.ValSubpoenaWitnessCorrelationArgument)
	}
	srv := &http.Server{Addr: addr, Handler: gateway.New(tp.Tracer("gateway"), opts...).Handler()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		_ = tp.Shutdown(shutdown) // flush remaining spans
	}()

	log.Printf("gateway listening on %s, exporting to %s", addr, endpoint)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
