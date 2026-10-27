//subpoena:impl_derived

package lint

import (
	"strings"
	"testing"
)

// ---- provider-override ----

func TestProviderOverride(t *testing.T) {
	head := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; %s)\n"
	cases := []struct {
		name, imp, body string
		want            int
	}{
		{"global swap", `"go.opentelemetry.io/otel"`, "otel.SetTracerProvider(tp)", 1},
		{"own SDK provider", `sdktrace "go.opentelemetry.io/otel/sdk/trace"`, "sdktrace.NewTracerProvider()", 1},
		{"aliased import", `sdk "go.opentelemetry.io/otel/sdk/trace"`, "sdk.NewTracerProvider()", 1},
		{"noop provider", `"go.opentelemetry.io/otel/trace/noop"`, "noop.NewTracerProvider()", 1},
		{"same name, other package", `trace "example.com/trace"`, "trace.NewTracerProvider()", 0},
		{"marker with reason on the line above", `"go.opentelemetry.io/otel/trace/noop"`, "\n\t//subpoena:own_provider the noop tracer is the case under test\n\tnoop.NewTracerProvider()", 0},
		{"marker without a reason", `"go.opentelemetry.io/otel/trace/noop"`, "\n\t//subpoena:own_provider\n\tnoop.NewTracerProvider()", 1},
		{"marker two lines up does not count", `"go.opentelemetry.io/otel/trace/noop"`, "\n\t//subpoena:own_provider reason\n\n\tnoop.NewTracerProvider()", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := strings.Replace(head, "%s", c.imp, 1) + "func TestA(t *testing.T) { h.Collect(ctx); " + c.body + " }\n"
			fs := lintTree(t, map[string]string{"a_test.go": src})
			if c.want == 0 {
				if len(fs) != 0 {
					t.Fatalf("unexpected: %v", fs)
				}
				return
			}
			only(t, fs, RuleProviderOverride, c.want)
		})
	}
}

func TestProviderOverrideAllowsMainPackages(t *testing.T) {
	main := "package main\nimport sdktrace \"go.opentelemetry.io/otel/sdk/trace\"\nfunc main() { _ = sdktrace.NewTracerProvider() }\n"
	if fs := lintTree(t, map[string]string{"cmd/svc/main.go": main}); len(fs) != 0 {
		t.Fatalf("a service's main may set up its provider: %v", fs)
	}
	// Library code may not.
	lib := "package svc\nimport sdktrace \"go.opentelemetry.io/otel/sdk/trace\"\nfunc Setup() { _ = sdktrace.NewTracerProvider() }\n"
	only(t, lintTree(t, map[string]string{"svc.go": lib}), RuleProviderOverride, 1)
}

// ---- name matching gated on imports ----

func TestCollectCountsOnlyWithTheHarnessImported(t *testing.T) {
	src := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"example.com/metrics\")\nfunc TestA(t *testing.T) { m.Collect(ctx) }\n"
	only(t, lintTree(t, map[string]string{"a_test.go": src}), RuleNoTraceAssertion, 1)
}

func TestSpawnedCountsOnlyWithAWitnessImported(t *testing.T) {
	test := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; %s)\nfunc TestA(t *testing.T) { h.Collect(ctx); w.Spawned(id) }\n"
	only(t, lintTree(t, map[string]string{
		"auth.go": enforced, "a_test.go": strings.Replace(test, "%s", `"example.com/pool"`, 1),
	}), RuleUnwitnessedEnforcement, 1)
	// A witness implementation below pkg/witness counts.
	if fs := lintTree(t, map[string]string{
		"auth.go": enforced, "a_test.go": strings.Replace(test, "%s", `"github.com/sprigworks/subpoena/pkg/witness/execbpf"`, 1),
	}); len(fs) != 0 {
		t.Fatalf("unexpected: %v", fs)
	}
}

// The harness absence checks ask the witness and check its health, so a test
// that uses only them is witnessed; they count only with the harness imported.
func TestHarnessAbsenceChecksCountAsWitnessed(t *testing.T) {
	for _, call := range []string{"harness.RequireNoSpawn(t, w, id)", "harness.NoSpawn(w, id)",
		"harness.RequireNoDial(t, w, id, nil)", "harness.NoDial(w, id, nil)", "w.Dialed(id)"} {
		imp := `"x/pkg/harness"`
		if strings.HasPrefix(call, "w.") {
			imp = `"x/pkg/harness"; "x/pkg/witness"`
		}
		src := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; " + imp + ")\nfunc TestA(t *testing.T) { h.Collect(ctx); " + call + " }\n"
		if fs := lintTree(t, map[string]string{"auth.go": enforced, "a_test.go": src}); len(fs) != 0 {
			t.Errorf("%s: unexpected: %v", call, fs)
		}
	}
	// Without the harness import, a RequireNoSpawn of some other package does not count.
	src := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\")\nfunc TestA(t *testing.T) { h.Collect(ctx) }\n"
	other := "//subpoena:impl_derived\n//subpoena:pure_logic\npackage p\nimport (\"testing\"; \"example.com/checks\")\nfunc TestB(t *testing.T) { checks.RequireNoSpawn(t) }\n"
	only(t, lintTree(t, map[string]string{"auth.go": enforced, "a_test.go": src, "b_test.go": other}), RuleUnwitnessedEnforcement, 1)
}

// ---- dead-telemetry ----

// emitAllBut is a non-test file emitting every registry entry except skip,
// half through semconv constants and the rest as equal literals.
func emitAllBut(reg *Registry, skip string) string {
	var b strings.Builder
	b.WriteString("package p\nimport sc \"example.com/svc/generated/go/semconv\"\nvar _ = []string{\n")
	i := 0
	for val, name := range reg.ByValue {
		if val == skip {
			continue
		}
		if i%2 == 0 {
			b.WriteString("\tsc." + name + ",\n")
		} else {
			b.WriteString("\t\"" + val + "\",\n")
		}
		i++
	}
	b.WriteString("}\n")
	return b.String()
}

func TestDeadTelemetry(t *testing.T) {
	reg := registry(t)
	run := func(files map[string]string, dead bool) []Finding {
		t.Helper()
		dir := writeTree(t, files, t.TempDir())
		fs, err := RunWith([]string{dir}, reg, Options{DeadTelemetry: dead})
		if err != nil {
			t.Fatal(err)
		}
		return fs
	}
	if fs := run(map[string]string{"emit.go": emitAllBut(reg, "")}, true); len(fs) != 0 {
		t.Fatalf("every entry emitted, still flagged: %v", fs)
	}
	fs := run(map[string]string{"emit.go": emitAllBut(reg, "session.id")}, true)
	only(t, fs, RuleDeadTelemetry, 1)
	if !strings.Contains(fs[0].Msg, "session.id") || !strings.HasSuffix(fs[0].Pos.Filename, "semconv.go") {
		t.Errorf("finding should name the entry at its registry declaration: %v", fs[0])
	}
	// A use in a test file is not an emitter.
	testUse := "//subpoena:impl_derived\npackage p\nimport (\"testing\"; \"x/pkg/harness\"; sc \"example.com/svc/generated/go/semconv\")\nfunc TestA(t *testing.T) { h.Collect(ctx); _ = sc.AttrSessionId }\n"
	only(t, run(map[string]string{"emit.go": emitAllBut(reg, "session.id"), "a_test.go": testUse}, true), RuleDeadTelemetry, 1)
	// Off unless asked: a partial tree is not the whole service.
	if fs := run(map[string]string{"emit.go": emitAllBut(reg, "session.id")}, false); len(fs) != 0 {
		t.Fatalf("dead-telemetry ran without being enabled: %v", fs)
	}
}

func TestTypedRegistryConstantsAreNotTelemetry(t *testing.T) {
	// semconv.TierTest = "test" is a value of type Tier, not a span name.
	src := "package p\nfunc f() { tr.Start(ctx, \"test\") }\n"
	only(t, lintTree(t, map[string]string{"a.go": src}), RuleUnknownTelemetry, 1)
}
