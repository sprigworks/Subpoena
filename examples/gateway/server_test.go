//subpoena:impl_derived

package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/examples/gateway"
	"github.com/sprigworks/subpoena/invariants"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

func post(t *testing.T, srv *httptest.Server, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(srv.URL+"/sessions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestHTTPDenyIs403AndSpawnsNothing(t *testing.T) {
	h := harness.New()
	w := witness.NewProcWitness(osPID())
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	srv := httptest.NewServer(gateway.New(h.Tracer("http-test")).Handler())
	defer srv.Close()

	resp := post(t, srv, `{"user":"mallory","host":"prod-db1","command":"sleep","args":["0.15"]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	traceID := resp.Header.Get("X-Trace-Id")
	w.Stop()

	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
	if len(tr.Spans(traceID)) == 0 {
		t.Fatalf("X-Trace-Id %q not found among %v", traceID, tr.TraceIDs())
	}
	if n := len(w.Spawned(traceID)); n != 0 {
		t.Fatalf("witness saw %d processes", n)
	}
}

func TestHTTPBadBody(t *testing.T) {
	h := harness.New()
	srv := httptest.NewServer(gateway.New(h.Tracer("http-test")).Handler())
	defer srv.Close()
	if resp := post(t, srv, `not json`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	if _, err := h.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func osPID() int { return os.Getpid() }
