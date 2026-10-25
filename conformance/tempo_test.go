//subpoena:impl_derived

// The Tempo half of the conformance suite. TestTempoAgreesWithSubset needs a
// running Tempo (see README.md) and is opt-in: it never probes the network
// unless asked to. The other tests drive
// the same client code against an in-process fake that answers /api/search
// with pkg/traceql itself, so the push/poll/search/compare machinery is tested
// everywhere, including its ability to notice a disagreement.
package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

// TestTempoAgreesWithSubset pushes the fixtures to a real Tempo and requires
// Tempo and pkg/traceql to return the same trace IDs for every query.
//
// It runs only when SUBPOENA_CONFORMANCE_REQUIRE=1 (make conformance) or
// SUBPOENA_TEMPO_URL is set. Probing a default port unasked would make
// `make test` depend on, and push fixture spans into, whatever Tempo happens
// to be listening on the machine.
func TestTempoAgreesWithSubset(t *testing.T) {
	require := os.Getenv("SUBPOENA_CONFORMANCE_REQUIRE") == "1"
	if !require && os.Getenv("SUBPOENA_TEMPO_URL") == "" {
		t.Skip("Tempo comparison is opt-in: run `make conformance`, or set SUBPOENA_TEMPO_URL (and SUBPOENA_OTLP_URL) to a Tempo you are willing to push fixtures into")
	}
	c := ClientFromEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if !c.Reachable(ctx) {
		msg := "no Tempo at " + c.TempoURL + " (set SUBPOENA_TEMPO_URL, and SUBPOENA_OTLP_URL for the OTLP/HTTP port; start one with `make conformance` or `docker compose -f conformance/docker-compose.yml up -d`)"
		if require {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	if err := c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	fx, qs := loadAll(t)
	divs, err := Run(ctx, c, fx, qs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range divs {
		t.Errorf("Tempo and pkg/traceql disagree on %s", d)
	}
	t.Logf("%d queries over %d fixtures: %d divergence(s)", len(qs), len(fx), len(divs))
}

// fakeTempo stands in for Tempo: OTLP/HTTP receiver plus /api/search backed by
// pkg/traceql. mutate lets a test make it wrong.
type fakeTempo struct {
	mu         sync.Mutex
	traces     []traceql.Trace
	pushes     int
	searches   int
	emptyFirst int                                          // answer this many searches with nothing (ingestion lag)
	mutate     func(q string, ids []string) ([]string, int) // return ids and an HTTP status (0 = 200)
}

func (f *fakeTempo) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ready")) })
	mux.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "want POST application/json", http.StatusUnsupportedMediaType)
			return
		}
		var e Export
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fx := &Fixture{Name: "push", Export: e}
		trs, err := fx.Traces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.traces = append(f.traces, trs...)
		f.pushes++
		f.mu.Unlock()
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.searches++
		q := r.URL.Query().Get("q")
		if r.URL.Query().Get("start") == "" || r.URL.Query().Get("end") == "" {
			http.Error(w, "start and end required", http.StatusBadRequest)
			return
		}
		p, err := traceql.Parse(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var ids []string
		if f.searches > f.emptyFirst {
			for _, m := range p.Eval(f.traces) {
				// Tempo may trim leading zeros; NormID must cope.
				ids = append(ids, strings.TrimLeft(m.TraceID, "0"))
			}
		}
		if f.mutate != nil && q != "{ true }" {
			var code int
			ids, code = f.mutate(q, ids)
			if code != 0 {
				http.Error(w, "mutated failure", code)
				return
			}
		}
		type tr struct {
			TraceID string `json:"traceID"`
		}
		out := struct {
			Traces []tr `json:"traces"`
		}{}
		for _, id := range ids {
			out.Traces = append(out.Traces, tr{id})
		}
		json.NewEncoder(w).Encode(out)
	})
	return mux
}

func fakeClient(t *testing.T, f *fakeTempo) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return &Client{TempoURL: srv.URL, OTLPURL: srv.URL, HTTP: srv.Client()}
}

func TestRunAgainstFakeTempoAgrees(t *testing.T) {
	f := &fakeTempo{emptyFirst: 1}
	c := fakeClient(t, f)
	fx, qs := loadAll(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !c.Reachable(ctx) {
		t.Fatal("fake not reachable")
	}
	if err := c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	divs, err := Run(ctx, c, fx, qs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range divs {
		t.Errorf("unexpected divergence: %s", d)
	}
	if f.pushes != len(fx) {
		t.Errorf("pushed %d exports, want one per fixture (%d)", f.pushes, len(fx))
	}
	if f.searches < 2+len(qs) {
		t.Errorf("only %d searches; ingestion polling and one search per query are expected", f.searches)
	}
}

func TestRunReportsDisagreementWithFixtureAndTrace(t *testing.T) {
	const victim = "invariants/no_exec_after_deny"
	var invariant string
	_, qs := loadAll(t)
	for _, q := range qs {
		if q.Name == victim {
			invariant = q.Text
		}
	}
	f := &fakeTempo{mutate: func(q string, ids []string) ([]string, int) {
		switch q {
		case invariant:
			return ids[1:], 0 // Tempo "forgets" one violating trace
		case "{ name = \"agent.session.exec\" }":
			return append(ids, "ffff", "c0de0000000000000000000200000001"), 0 // a stray ID, and a trace Tempo should not match
		case "{ span.retry.count != 3 }":
			return nil, http.StatusBadRequest // Tempo rejects the query
		}
		return ids, 0
	}}
	c := fakeClient(t, f)
	fx, qs := loadAll(t)
	divs, err := Run(context.Background(), c, fx, qs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Divergence{}
	for _, d := range divs {
		by[d.Query.Name] = d
	}
	if len(divs) != 3 {
		t.Fatalf("want exactly 3 divergent queries, got %d:\n%v", len(divs), divs)
	}
	if d := by[victim]; len(d.OnlySubset) != 1 || len(d.OnlyTempo) != 0 || !strings.Contains(d.OnlySubset[0], "/c0de") {
		t.Errorf("dropped trace not reported with its fixture: %+v", d)
	}
	if d := by["queries/any_exec"]; len(d.OnlyTempo) != 1 || !strings.HasPrefix(d.OnlyTempo[0], "deny_without_exec/") {
		t.Errorf("extra trace not attributed to its fixture (and the stray ID must be ignored): %+v", d)
	}
	if d := by["queries/int_attr_ne_int_literal"]; !strings.Contains(d.Err, "Tempo rejected") {
		t.Errorf("rejected query should be reported as an error: %+v", d)
	}
	if s := by[victim].String(); !strings.Contains(s, "subset only") || !strings.Contains(s, invariant) {
		t.Errorf("String() should show the query and the side: %s", s)
	}
}

func TestRunFailsWhenIngestionNeverCompletes(t *testing.T) {
	f := &fakeTempo{emptyFirst: 1 << 30}
	c := fakeClient(t, f)
	fx, qs := loadAll(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, c, fx, qs, time.Now())
	if err == nil || !strings.Contains(err.Error(), "not searchable") {
		t.Fatalf("want a not-searchable error, got %v", err)
	}
}

func TestPushSurfacesReceiverErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()
	c := &Client{TempoURL: srv.URL, OTLPURL: srv.URL}
	fx, _ := loadAll(t)
	err := c.Push(context.Background(), &fx[0].Export)
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("got %v", err)
	}
}

func TestUnreachableTempoIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	c := &Client{TempoURL: url, HTTP: &http.Client{Timeout: time.Second}}
	if c.Reachable(context.Background()) {
		t.Fatal("closed port reported reachable")
	}
}

func TestClientFromEnvDefaultsAndOverrides(t *testing.T) {
	t.Setenv("SUBPOENA_TEMPO_URL", "")
	t.Setenv("SUBPOENA_OTLP_URL", "")
	c := ClientFromEnv()
	if c.TempoURL != "http://localhost:13200" || c.OTLPURL != "http://localhost:14318" {
		t.Fatalf("defaults wrong: %+v", c)
	}
	t.Setenv("SUBPOENA_TEMPO_URL", "http://tempo:3200/")
	t.Setenv("SUBPOENA_OTLP_URL", "http://collector:4318")
	c = ClientFromEnv()
	if c.TempoURL != "http://tempo:3200" || c.OTLPURL != "http://collector:4318" {
		t.Fatalf("overrides wrong: %+v", c)
	}
}
