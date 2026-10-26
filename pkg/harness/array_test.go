//subpoena:spec_derived

// docs/ports.md H6: array attribute values are kept as unsupported, and a
// query that reads one is an error, never a verdict.
package harness

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func TestArrayAttributeIsRefusedNotStringified(t *testing.T) {
	h := New()
	_, s := h.Tracer("t").Start(context.Background(), "exec")
	s.SetAttributes(attribute.StringSlice("args", []string{"rm", "-rf"}), attribute.Int("n", 3))
	s.End()
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`{ span.args = "rm" }`, `{ span.args = "[rm -rf]" }`, `{ span.args != "x" }`} {
		if v, err := tr.Absent(q); err == nil {
			t.Errorf("absent %s: want an error, got %v", q, v)
		} else if !strings.Contains(err.Error(), "args") {
			t.Errorf("absent %s: error %q does not name the attribute", q, err)
		}
		if v, err := tr.Exists(q); err == nil {
			t.Errorf("exists %s: want an error, got %v", q, v)
		}
	}
	if v, err := tr.Exists(`{ span.n = 3 }`); err != nil || v != Pass {
		t.Fatalf("a query not reading the array: %v %v", v, err)
	}
}
