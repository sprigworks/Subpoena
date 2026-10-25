//subpoena:spec_derived

package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/examples/gateway"
	"github.com/sprigworks/subpoena/generated/go/semconv"
	"github.com/sprigworks/subpoena/invariants"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

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

	// (a) open a denied session: a non-admin asks to act on a prod host.
	_, err := r.gw.Run(ctx, sess, "prod-db1", "sleep", sleepArg)
	if !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
	r.w.Stop() // final poll before asking the witness

	// (b) Collect.
	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// (c) the invariant returns zero traces.
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))

	// (d) the authorize span says the decision was false, and names its policy.
	harness.RequireExists(t, tr, authorizeDenied)
	harness.RequireExists(t, tr, fmt.Sprintf(`{ span.%s = %q }`,
		semconv.AttrAuthorizationPolicyId, gateway.PolicyDenyProdNonAdmin))
	// Testimony that is consistent with the invariant: no exec span either.
	harness.RequireAbsent(t, tr, anyExec)

	// (e) the independent witness saw zero spawned processes for this trace.
	ids := tr.TraceIDs()
	if len(ids) != 1 {
		t.Fatalf("expected one trace, got %v", ids)
	}
	if spawned := r.w.Spawned(ids[0]); len(spawned) != 0 {
		t.Fatalf("witness saw processes after a denial: %+v", spawned)
	}
}

func TestAllowedSessionExecsExactlyOnce(t *testing.T) {
	r := newRig(t)
	ctx, sess := r.gw.Open(context.Background(), gateway.User{Name: "alice"})

	if _, err := r.gw.Run(ctx, sess, "dev-1", "sleep", sleepArg); err != nil {
		t.Fatal(err)
	}
	r.w.Stop()

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
	if _, err := r.gw.Run(ctx, sess, "dev-1", "rm", "-rf", "/"); err == nil {
		t.Fatal("rm must not be runnable")
	}
	r.w.Stop()
	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireAbsent(t, tr, anyExec)
	if n := len(r.w.Spawned(tr.TraceIDs()[0])); n != 0 {
		t.Fatalf("witness saw %d processes", n)
	}
}

func TestPolicy(t *testing.T) {
	cases := []struct {
		user    gateway.User
		host    string
		allowed bool
		policy  string
	}{
		{gateway.User{}, "prod-1", false, gateway.PolicyDenyProdNonAdmin},
		{gateway.User{Admin: true}, "prod-1", true, gateway.PolicyAllowAdmin},
		{gateway.User{}, "staging-1", true, gateway.PolicyAllowDefault},
		{gateway.User{}, "production", true, gateway.PolicyAllowDefault}, // "prod-*" needs the dash
	}
	for _, c := range cases {
		got := gateway.Evaluate(c.user, c.host)
		if got.Allowed != c.allowed || got.PolicyID != c.policy {
			t.Errorf("%+v on %s: got %+v", c.user, c.host, got)
		}
	}
}
