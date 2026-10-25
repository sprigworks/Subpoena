//subpoena:impl_derived

package invariants

import (
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
