//subpoena:impl_derived

package invariants

import (
	"os"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

func TestEveryInvariantParses(t *testing.T) {
	entries, err := files.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if len(e.Name()) < 8 || e.Name()[len(e.Name())-8:] != ".traceql" {
			continue
		}
		n++
		name := e.Name()[:len(e.Name())-8]
		q, err := Load(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := traceql.Parse(q); err != nil {
			t.Errorf("%s does not parse in the supported subset: %v", e.Name(), err)
		}
	}
	if n == 0 {
		t.Fatal("no invariants found")
	}
}

func TestFirstInvariantText(t *testing.T) {
	want := `{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }`
	if got := MustLoad(NoExecAfterDeny); got != want {
		t.Fatalf("invariant text drifted:\n got %s\nwant %s", got, want)
	}
}

// TestPromotionIsCopyPaste checks the tier-1 invariant string appears verbatim
// in the tier-2 OATS case and the tier-3 alert rule, so promotion cannot drift.
func TestPromotionIsCopyPaste(t *testing.T) {
	inv := MustLoad(NoExecAfterDeny)
	for _, path := range []string{
		"../examples/gateway/oats/oats-case.yaml",
		"../examples/gateway/alerts/no_exec_after_deny.yaml",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), inv) {
			t.Errorf("%s does not contain the invariant verbatim:\n%s", path, inv)
		}
	}
}
