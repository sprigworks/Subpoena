//subpoena:spec_derived

package saidno_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/generated/go/semconv"
	"github.com/sprigworks/subpoena/pkg/harness"

	"github.com/sprigworks/subpoena/examples/saidno"
)

// tool is an executable copy of testdata/tool. It outlives the witness's
// polling gap. subpoena-cross copies the tree without file modes, so the copy
// is made here.
var tool string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "saidno")
	if err != nil {
		panic(err)
	}
	body, err := os.ReadFile("testdata/tool")
	if err != nil {
		panic(err)
	}
	tool = filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, body, 0o755); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var (
	denied     = fmt.Sprintf(`{ name = %q && span.%s = false }`, semconv.SpanAgentSessionAuthorize, semconv.AttrAuthorizationAllowed)
	anyExec    = fmt.Sprintf(`{ name = %q }`, semconv.SpanAgentSessionExec)
	execDenied = denied + ` >> ` + anyExec
)

func request(agent string) saidno.Request {
	return saidno.Request{Agent: agent, Command: tool, Args: []string{"run"}}
}

// The ordinary suite checks everything the gateway reports about itself: the
// status, the body, the log line and the spans.
func TestOrdinaryDeniedRequest(t *testing.T) {
	h := harness.New()
	var log bytes.Buffer
	g := saidno.New(h.Tracer("saidno-test"), slog.New(slog.NewTextHandler(&log, nil)))

	resp := g.Run(context.Background(), request("intern"))

	if resp.Status != http.StatusForbidden || resp.Body != "denied" {
		t.Fatalf("want 403 denied, got %d %q", resp.Status, resp.Body)
	}
	if !strings.Contains(log.String(), "request denied") {
		t.Fatalf("no denial in the log: %q", log.String())
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, denied)
	harness.RequireAbsent(t, tr, execDenied)
	harness.RequireAbsent(t, tr, anyExec)
}

func TestOrdinaryAllowedRequest(t *testing.T) {
	h := harness.New()
	g := saidno.New(h.Tracer("saidno-test"), slog.New(slog.DiscardHandler))

	resp := g.Run(context.Background(), request(saidno.Operator))

	if resp.Status != http.StatusOK {
		t.Fatalf("want 200, got %d %q", resp.Status, resp.Body)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, anyExec)
}
