//subpoena:spec_derived

package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/examples/gateway"
	"github.com/sprigworks/subpoena/generated/go/semconv"
	"github.com/sprigworks/subpoena/invariants"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

// TestMain points the default session-cgroup root at a stand-in directory, so no
// test in this package touches the machine's real cgroup hierarchy unless it
// asks to (see cgroup_test.go).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "subpoena-gateway-cgroup-")
	if err != nil {
		panic(err)
	}
	root := filepath.Join(dir, "subpoena")
	if err := os.Mkdir(root, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
		panic(err)
	}
	os.Setenv("SUBPOENA_CGROUP_ROOT", root)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// sleepArg: the spawned process must outlive the witness polling interval.
const sleepArg = "0.15"

type rig struct {
	h  *harness.Harness
	gw *gateway.Gateway
	w  *witness.ProcWitness
}

func newRig(t *testing.T) *rig {
	t.Helper()
	h := harness.New()
	w := witness.NewProcWitness(os.Getpid())
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	harness.WatchSpawns(t, w, "", harness.SpawnRule{Allowed: []string{"sleep " + sleepArg}})
	return &rig{h: h, gw: gateway.New(h.Tracer("gateway-test")), w: w}
}

// queries are built from registry constants, not literals.
var (
	authorizeDenied = fmt.Sprintf(`{ name = %q && span.%s = false }`,
		semconv.SpanAgentSessionAuthorize, semconv.AttrAuthorizationAllowed)
	authorizeAllowed = fmt.Sprintf(`{ name = %q && span.%s = true }`,
		semconv.SpanAgentSessionAuthorize, semconv.AttrAuthorizationAllowed)
	anyExec = fmt.Sprintf(`{ name = %q }`, semconv.SpanAgentSessionExec)
)

func TestDeniedSessionNeverExecs(t *testing.T) {
	r := newRig(t)
	ctx, sess := r.gw.Open(context.Background(), gateway.User{Name: "mallory"})
	harness.WatchSpawns(t, r.w, traceOf(ctx), harness.SpawnRule{Allowed: []string{}})

	// (a) open a denied session: a non-admin asks to act on a prod host.
	_, runErr := r.gw.Run(ctx, sess, "prod-db1", "sleep", sleepArg)
	r.w.Stop() // final poll before asking the witness
	if err := r.w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}

	// (b) Collect.
	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Ask the independent witness before return values or telemetry can fail.
	harness.RequireNoSpawn(t, r.w, traceOf(ctx))
	if ids := tr.TraceIDs(); len(ids) != 1 {
		t.Fatalf("expected one trace, got %v", ids)
	}
	if !errors.Is(runErr, gateway.ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", runErr)
	}
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
	harness.RequireExists(t, tr, authorizeDenied)
	harness.RequireExists(t, tr, fmt.Sprintf(`{ span.%s = %q }`,
		semconv.AttrAuthorizationPolicyId, gateway.PolicyDenyProdNonAdmin))
	harness.RequireAbsent(t, tr, anyExec)
}

func TestAllowedSessionExecsExactlyOnce(t *testing.T) {
	r := newRig(t)
	ctx, sess := r.gw.Open(context.Background(), gateway.User{Name: "alice"})

	if _, err := r.gw.Run(ctx, sess, "dev-1", "sleep", sleepArg); err != nil {
		t.Fatal(err)
	}
	r.w.Stop()
	if err := r.w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}

	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	harness.RequireExists(t, tr, authorizeAllowed)
	harness.RequireExists(t, tr, fmt.Sprintf(`{ name = %q && span.%s = %q }`,
		semconv.SpanAgentSessionExec, semconv.AttrProcessCommandLine, "sleep "+sleepArg))
	// The invariant concerns denials only; an allowed session must not trip it.
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))

	ids := tr.TraceIDs()
	if len(ids) != 1 {
		t.Fatalf("expected one trace, got %v", ids)
	}
	spawned := r.w.Spawned(ids[0])
	if len(spawned) != 1 {
		t.Fatalf("witness must see exactly one process, got %d: %+v", len(spawned), spawned)
	}
	if !strings.HasSuffix(spawned[0].Command, "sleep "+sleepArg) {
		t.Fatalf("unexpected process %q", spawned[0].Command)
	}
}

func TestAdminMayActOnProd(t *testing.T) {
	r := newRig(t)
	ctx, sess := r.gw.Open(context.Background(), gateway.User{Name: "root", Admin: true})
	if _, err := r.gw.Run(ctx, sess, "prod-db1", "sleep", sleepArg); err != nil {
		t.Fatal(err)
	}
	r.w.Stop()
	if err := r.w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}
	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, fmt.Sprintf(`{ span.%s = %q }`,
		semconv.AttrAuthorizationPolicyId, gateway.PolicyAllowAdmin))
	if n := len(r.w.Spawned(tr.TraceIDs()[0])); n != 1 {
		t.Fatalf("witness saw %d processes, want 1", n)
	}
}

func TestExecRefusesCommandsOutsideAllowlist(t *testing.T) {
	r := newRig(t)
	ctx, sess := r.gw.Open(context.Background(), gateway.User{Name: "alice"})
	if _, err := r.gw.Run(ctx, sess, "dev-1", "printf", "allowlist-probe"); err == nil {
		t.Fatal("printf must not be runnable")
	}
	r.w.Stop()
	if err := r.w.Health(); err != nil {
		t.Fatalf("witness capture incomplete: %v", err)
	}
	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireAbsent(t, tr, anyExec)
	harness.RequireNoSpawn(t, r.w, tr.TraceIDs()[0])
}
