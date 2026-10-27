//subpoena:impl_derived

package gateway_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sprigworks/subpoena/examples/gateway"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

// fetchRig points the "prod-api" upstream at a sinkhole: a listener the
// gateway does not control, which records every connection that reaches it.
func fetchRig(t *testing.T) (*harness.Harness, *gateway.Gateway, *witness.Sinkhole) {
	t.Helper()
	sink, err := witness.NewSinkhole()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Stop() })
	h := harness.New()
	gw := gateway.New(h.Tracer("gateway-test"),
		gateway.WithUpstreams(map[string]string{"prod-api": sink.Addr().String()}))
	return h, gw, sink
}

// A denied fetch sends nothing to the host: the authorize span says denied,
// and the sinkhole standing in for the host saw no connection. The span alone
// is testimony; the sinkhole is the witness.
func TestDeniedFetchNeverReachesTheHost(t *testing.T) {
	h, gw, sink := fetchRig(t)
	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "mallory"})

	_, fetchErr := gw.Fetch(ctx, sess, "prod-api")
	if err := sink.Stop(); err != nil {
		t.Fatalf("sinkhole capture incomplete: %v", err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, authorizeDenied)

	ids := tr.TraceIDs()
	if len(ids) != 1 {
		t.Fatalf("expected one trace, got %v", ids)
	}
	// Ask the witness before trusting the return value.
	harness.RequireNoDial(t, sink, ids[0], harness.DialTo(sink.Addr()))
	if !errors.Is(fetchErr, gateway.ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", fetchErr)
	}
}

// The positive control: an admin may fetch from prod, and the sinkhole sees
// exactly that one connection. Without it, a sinkhole nobody could reach would
// pass the test above for the wrong reason.
func TestAdminFetchReachesTheHost(t *testing.T) {
	h, gw, sink := fetchRig(t)
	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "root", Admin: true})

	gw.Fetch(ctx, sess, "prod-api") // the sinkhole hangs up; the error is not the point
	if err := sink.Stop(); err != nil {
		t.Fatalf("sinkhole capture incomplete: %v", err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, authorizeAllowed)
	id := tr.TraceIDs()[0]
	if v, _ := harness.NoDial(sink, id, harness.DialTo(sink.Addr())); v != harness.Fail {
		t.Fatalf("NoDial = %v; the admin's fetch must reach the sinkhole", v)
	}
	if n := len(sink.Dialed(id)); n != 1 {
		t.Fatalf("sinkhole saw %d connections, want 1", n)
	}
}

func TestFetchRefusesUnknownUpstream(t *testing.T) {
	h, gw, _ := fetchRig(t)
	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "alice"})
	if _, err := gw.Fetch(ctx, sess, "dev-api"); !errors.Is(err, gateway.ErrUnknownUpstream) {
		t.Fatalf("expected ErrUnknownUpstream, got %v", err)
	}
	if _, err := h.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
}
