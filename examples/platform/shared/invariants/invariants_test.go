//subpoena:impl_derived

package invariants_test

import (
	"context"
	"testing"

	"example.com/platform/contract/generated/go/semconv"
	"example.com/platform/contract/invariants"
	"github.com/sprigworks/subpoena/pkg/harness"
	"go.opentelemetry.io/otel/attribute"
)

// Deliberately violating testimony must match, so a typo in a shared invariant
// cannot be hidden by service tests that also check a return value or witness.
func TestInvariantRecognizesViolation(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		h := harness.New()
		ctx, decision := h.Tracer("fixture").Start(context.Background(), semconv.SpanPlatformActionAuthorize)
		decision.SetAttributes(attribute.Bool(semconv.AttrPlatformAuthorizationAllowed, allowed))
		_, effect := h.Tracer("fixture").Start(ctx, semconv.SpanPlatformActionExec)
		effect.End()
		decision.End()
		tr, err := h.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
		} else {
			harness.RequireExists(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
		}
		if err := h.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
