//subpoena:impl_derived
// Initial denial/control tests preceded implementation; expanded after implementation review.

package deploy_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"example.com/platform/contract/generated/go/semconv"
	"example.com/platform/contract/invariants"
	"example.com/platform/contract/telemetry"
	service "example.com/platform/deploy"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestAuthorization(t *testing.T) {
	for _, tc := range []struct{ production, approved, allowed bool }{{false, false, true}, {false, true, true}, {true, false, false}, {true, true, true}} {
		production, approved, allowed := tc.production, tc.approved, tc.allowed
		t.Run(fmt.Sprintf("production=%t/approved=%t", production, approved), func(t *testing.T) {
			h := harness.New()
			mem := tracetest.NewInMemoryExporter()
			h.TracerProvider().(*sdktrace.TracerProvider).RegisterSpanProcessor(sdktrace.NewSimpleSpanProcessor(telemetry.ProductionExporter(mem)))
			t.Cleanup(func() { _ = h.Shutdown(context.Background()) })
			// A parent context gives the cleanup witness its ID before the action
			// starts, without emitting synthetic application spans.
			parent := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled})
			ctx := trace.ContextWithRemoteSpanContext(context.Background(), parent)
			id := parent.TraceID().String()
			w := witness.NewProcWitness(os.Getpid())
			if err := w.Start(); err != nil {
				t.Fatal(err)
			}
			rule := harness.SpawnRule{Allowed: []string{}}
			if allowed {
				rule.Allowed = []string{"sleep 0.2"}
			}
			harness.WatchSpawns(t, w, id, rule)
			req := service.Request{ID: "action-42", Production: production, Approved: approved, Command: "sleep", Args: []string{"0.2"}}
			runErr := service.New(h.Tracer("deploy-test")).Run(ctx, req)
			w.Stop()
			tr, err := h.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if allowed {
				if err := w.Health(); err != nil {
					t.Fatal(err)
				}
				if len(w.Spawned(id)) == 0 {
					t.Fatal("witness: allowed control did not run")
				}
			} else {
				harness.RequireNoSpawn(t, w, id)
			}
			harness.RequireExists(t, tr, fmt.Sprintf(`{ name = %q && span.%s = %t }`, semconv.SpanPlatformActionAuthorize, semconv.AttrPlatformAuthorizationAllowed, allowed))
			harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
			// The raw test capture retains the ID; the production export drops it.
			harness.RequireExists(t, tr, fmt.Sprintf(`{ name = %q && span.%s = "action-42" }`, semconv.SpanPlatformActionAuthorize, semconv.AttrPlatformActionId))
			foundDecision := false
			for _, exported := range mem.GetSpans() {
				for _, attr := range exported.Attributes {
					if string(attr.Key) == semconv.AttrPlatformActionId {
						t.Fatal("production leaked action ID")
					}
					if string(attr.Key) == semconv.AttrPlatformAuthorizationAllowed {
						foundDecision = true
					}
				}
			}
			if !foundDecision {
				t.Fatal("production lost authorization decision")
			}
			if allowed {
				if runErr != nil {
					t.Fatal(runErr)
				}
				harness.RequireExists(t, tr, fmt.Sprintf(`{ name = %q }`, semconv.SpanPlatformActionExec))
			} else if !errors.Is(runErr, service.ErrDenied) {
				t.Fatalf("want ErrDenied, got %v", runErr)
			}
		})
	}
}
