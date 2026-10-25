//subpoena:impl_derived

package invariants

import (
	"os"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/internal/invgen"
	"github.com/sprigworks/subpoena/pkg/traceql"
)

func TestEveryInvariantParses(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no invariants found")
	}
	for _, name := range names {
		q, err := Load(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := traceql.Parse(q); err != nil {
			t.Errorf("%s.traceql does not parse in the supported subset: %v", name, err)
		}
	}
}

// TestNamesAreGenerated fails when names.go is stale relative to *.traceql:
// a new invariant file needs `go generate ./invariants`, so tests can refer to
// it as invariants.<Name> instead of pasting TraceQL.
func TestNamesAreGenerated(t *testing.T) {
	want, err := invgen.Generate(".")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("names.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("invariants/names.go is stale: run `go generate ./invariants` and commit")
	}
	// Names() agrees with the embedded files, not just with the generator.
	entries, err := files.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		onDisk = append(onDisk, strings.TrimSuffix(e.Name(), ".traceql"))
	}
	if strings.Join(onDisk, ",") != strings.Join(Names(), ",") {
		t.Fatalf("Names() = %v, embedded files = %v", Names(), onDisk)
	}
}

func TestFirstInvariantText(t *testing.T) {
	want := `{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }`
	if got := MustLoad(NoExecAfterDeny); got != want {
		t.Fatalf("invariant text drifted:\n got %s\nwant %s", got, want)
	}
}

// promotions maps an invariant to the tier-2 and tier-3 files that must carry
// its text verbatim. A new invariant that is promoted adds a row here.
var promotions = map[string][]string{
	NoExecAfterDeny: {
		"../examples/gateway/oats/oats-case.yaml",
		"../examples/gateway/alerts/no_exec_after_deny.yaml",
	},
}

// TestPromotionIsCopyPaste checks the tier-1 invariant string appears verbatim
// in the tier-2 OATS case and the tier-3 alert rule, so promotion cannot drift.
func TestPromotionIsCopyPaste(t *testing.T) {
	for name, paths := range promotions {
		inv, err := Load(name)
		if err != nil {
			t.Fatalf("promotions names unknown invariant: %v", err)
		}
		for _, path := range paths {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), inv) {
				t.Errorf("%s does not contain invariant %s verbatim:\n%s", path, name, inv)
			}
		}
	}
}
