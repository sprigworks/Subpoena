//subpoena:impl_derived

package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/sprigworks/subpoena/examples/gateway"
	"github.com/sprigworks/subpoena/generated/go/semconv"
	"github.com/sprigworks/subpoena/invariants"
	"github.com/sprigworks/subpoena/pkg/cgroup"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

// standInRoot makes a directory that mimics a cgroup v2 root (cgroup.controllers
// present), the way cgroup_test.go in pkg/cgroup does.
func standInRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "subpoena")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func correlationQuery(mode string) string {
	return fmt.Sprintf(`{ name = %q && span.%s = %q }`,
		semconv.SpanAgentSessionExec, semconv.AttrSubpoenaWitnessCorrelation, mode)
}

func traceOf(ctx context.Context) string {
	return trace.SpanContextFromContext(ctx).TraceID().String()
}

func procsOf(t *testing.T, root, traceID string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, traceID, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// Session open creates <root>/<trace id>; the exec is written into its
// cgroup.procs; the span says so; the independent witness agrees about which
// process it was; Close removes the cgroup.
func TestSessionCgroupHoldsTheExecAndTheSpanSaysSo(t *testing.T) {
	root := standInRoot(t)
	t.Setenv(cgroup.EnvRoot, root) // the documented knob, read by New
	r := newRig(t)

	ctx, sess := r.gw.Open(context.Background(), gateway.User{Name: "alice"})
	traceID := traceOf(ctx)
	if _, err := os.Stat(filepath.Join(root, traceID, "cgroup.procs")); err != nil {
		t.Fatalf("Open must create the session cgroup %s/%s: %v", root, traceID, err)
	}
	if _, err := r.gw.Run(ctx, sess, "dev-1", "sleep", sleepArg); err != nil {
		t.Fatal(err)
	}
	r.w.Stop()

	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, correlationQuery(semconv.ValSubpoenaWitnessCorrelationCgroup))
	harness.RequireAbsent(t, tr, correlationQuery(semconv.ValSubpoenaWitnessCorrelationLineage))

	spawned := r.w.Spawned(traceID)
	if len(spawned) != 1 {
		t.Fatalf("witness must see exactly one process, got %+v", spawned)
	}
	procs := procsOf(t, root, traceID)
	if len(procs) != 1 || procs[0] != fmt.Sprint(spawned[0].PID) {
		t.Fatalf("cgroup.procs %v must hold the pid the witness saw (%d)", procs, spawned[0].PID)
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, traceID)); !os.IsNotExist(err) {
		t.Fatal("Close must remove the session cgroup")
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close twice: %v", err)
	}
}

// A denied session still gets a cgroup (it exists from Open), and it stays empty:
// the witness and cgroup.procs agree that nothing ran.
func TestDeniedSessionCgroupStaysEmpty(t *testing.T) {
	root := standInRoot(t)
	r := newRig(t)
	gw := gateway.New(r.h.Tracer("denied"), gateway.WithCgroups(&cgroup.Manager{Root: root}))

	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "mallory"})
	defer sess.Close()
	if _, err := gw.Run(ctx, sess, "prod-db1", "sleep", sleepArg); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	r.w.Stop()
	tr, err := r.h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
	if procs := procsOf(t, root, traceOf(ctx)); len(procs) != 0 {
		t.Fatalf("cgroup.procs of a denied session = %v", procs)
	}
	if n := len(r.w.Spawned(traceOf(ctx))); n != 0 {
		t.Fatalf("witness saw %d processes", n)
	}
}

type captured struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *captured) Enabled(context.Context, slog.Level) bool { return true }
func (c *captured) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
	return nil
}
func (c *captured) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *captured) WithGroup(string) slog.Handler      { return c }

// No usable cgroup: the gateway still works, says "lineage" (or the configured
// fallback) on the exec span, and logs the reason once, at debug level.
func TestFallsBackWhenNoCgroupAndLogsOnceAtDebug(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "subpoena") // exists, but no cgroup.controllers
	if err := os.Mkdir(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		opt  []gateway.Option
		want string
	}{
		{"default is lineage", nil, semconv.ValSubpoenaWitnessCorrelationLineage},
		{"argument fallback", []gateway.Option{gateway.WithFallbackCorrelation(semconv.ValSubpoenaWitnessCorrelationArgument)}, semconv.ValSubpoenaWitnessCorrelationArgument},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := harness.New()
			logs := &captured{}
			opts := append([]gateway.Option{
				gateway.WithCgroups(&cgroup.Manager{Root: plain}),
				gateway.WithLogger(slog.New(logs)),
			}, c.opt...)
			gw := gateway.New(h.Tracer("fallback"), opts...)
			for i := 0; i < 3; i++ {
				ctx, sess := gw.Open(context.Background(), gateway.User{Name: "alice"})
				if _, err := gw.Run(ctx, sess, "dev-1", "true"); err != nil {
					t.Fatalf("exec must still work without a cgroup: %v", err)
				}
				sess.Close()
			}
			tr, err := h.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			harness.RequireExists(t, tr, correlationQuery(c.want))
			for _, other := range []string{semconv.ValSubpoenaWitnessCorrelationCgroup, semconv.ValSubpoenaWitnessCorrelationLineage, semconv.ValSubpoenaWitnessCorrelationArgument} {
				if other != c.want {
					harness.RequireAbsent(t, tr, correlationQuery(other))
				}
			}
			if len(logs.recs) != 1 || logs.recs[0].Level != slog.LevelDebug {
				t.Fatalf("want exactly one debug record across three sessions, got %d: %+v", len(logs.recs), logs.recs)
			}
			if _, err := os.Stat(filepath.Join(plain, "cgroup.controllers")); err == nil {
				t.Fatal("the gateway must not fake a cgroup in a plain directory")
			}
			if ents, _ := os.ReadDir(plain); len(ents) != 0 {
				t.Fatalf("failed session cgroup left entries behind: %v", ents)
			}
		})
	}
}

func TestInvalidFallbackPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("cgroup is not a fallback mode")
		}
	}()
	gateway.WithFallbackCorrelation(semconv.ValSubpoenaWitnessCorrelationCgroup)
}

// If the process cannot be moved into the cgroup the span must not claim it was.
func TestPlacementFailureIsNotReportedAsCgroup(t *testing.T) {
	root := standInRoot(t)
	h := harness.New()
	gw := gateway.New(h.Tracer("placement"), gateway.WithCgroups(&cgroup.Manager{Root: root}), gateway.WithLogger(slog.New(&captured{})))
	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "alice"})
	defer sess.Close()
	procs := filepath.Join(root, traceOf(ctx), "cgroup.procs")
	if err := os.Remove(procs); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(procs, 0o755); err != nil { // cannot be opened for writing
		t.Fatal(err)
	}
	if _, err := gw.Run(ctx, sess, "dev-1", "true"); err != nil {
		t.Fatalf("a placement failure must not fail the exec: %v", err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, correlationQuery(semconv.ValSubpoenaWitnessCorrelationLineage))
	harness.RequireAbsent(t, tr, correlationQuery(semconv.ValSubpoenaWitnessCorrelationCgroup))
}

func TestNoopTracerAndDisabledCgroups(t *testing.T) {
	// A tracer with no valid trace ID cannot name a cgroup; nothing is created.
	root := standInRoot(t)
	gw := gateway.New(noop.NewTracerProvider().Tracer("noop"), gateway.WithCgroups(&cgroup.Manager{Root: root}))
	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "alice"})
	if _, err := gw.Run(ctx, sess, "dev-1", "true"); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 1 {
		t.Fatalf("a session without a trace ID must not create a cgroup: %v", ents)
	}
	// nil disables cgroups explicitly.
	h := harness.New()
	gw = gateway.New(h.Tracer("off"), gateway.WithCgroups(nil))
	ctx, sess = gw.Open(context.Background(), gateway.User{Name: "alice"})
	if _, err := gw.Run(ctx, sess, "dev-1", "true"); err != nil {
		t.Fatal(err)
	}
	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, correlationQuery(semconv.ValSubpoenaWitnessCorrelationLineage))
}

// realRoot finds a cgroup v2 directory this process may create cgroups in, or
// skips (fails when SUBPOENA_CGROUP_REQUIRE=1).
func realRoot(t *testing.T) string {
	t.Helper()
	uniq := fmt.Sprintf("subpoena-gateway-test-%d", os.Getpid())
	var cands []string
	if r := os.Getenv("SUBPOENA_CGROUP_REAL_ROOT"); r != "" {
		cands = append(cands, r)
	}
	cands = append(cands, "/sys/fs/cgroup/unified/"+uniq, "/sys/fs/cgroup/"+uniq)
	var errs []string
	for _, c := range cands {
		m := &cgroup.Manager{Root: c}
		g, err := m.Create(strings.Repeat("ab", 16))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		real := g.Real()
		_ = g.Remove()
		if !real {
			_ = os.Remove(c)
			errs = append(errs, c+" is not on cgroup2")
			continue
		}
		t.Cleanup(func() { _ = os.Remove(c) })
		return c
	}
	msg := "no writable cgroup v2 hierarchy (set SUBPOENA_CGROUP_REAL_ROOT to one): " + strings.Join(errs, "; ")
	if os.Getenv("SUBPOENA_CGROUP_REQUIRE") == "1" {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return ""
}

// End to end on a real cgroup: the gateway puts the exec in the session cgroup,
// and the witness, reading /proc/<pid>/cgroup, attributes it by cgroup to
// exactly this trace.
func TestRealCgroupSessionIsWitnessedByCgroup(t *testing.T) {
	root := realRoot(t)
	h := harness.New()
	w := witness.NewProcWitness(os.Getpid())
	w.CgroupRoot = root
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	gw := gateway.New(h.Tracer("real"), gateway.WithCgroups(&cgroup.Manager{Root: root}))

	ctx, sess := gw.Open(context.Background(), gateway.User{Name: "alice"})
	defer sess.Close()
	if _, err := gw.Run(ctx, sess, "dev-1", "sleep", sleepArg); err != nil {
		t.Fatal(err)
	}
	// A second, denied session in flight at the same time.
	ctx2, sess2 := gw.Open(context.Background(), gateway.User{Name: "mallory"})
	defer sess2.Close()
	if _, err := gw.Run(ctx2, sess2, "prod-db1", "sleep", sleepArg); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	w.Stop()

	tr, err := h.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, correlationQuery(semconv.ValSubpoenaWitnessCorrelationCgroup))
	harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))

	evs := w.Spawned(traceOf(ctx))
	if len(evs) != 1 || evs[0].Attribution != witness.ByCgroup || evs[0].TraceID != traceOf(ctx) {
		t.Fatalf("want one process attributed by cgroup to the allowed trace, got %+v", evs)
	}
	if !bytes.Contains([]byte(evs[0].Cgroup), []byte(traceOf(ctx))) {
		t.Fatalf("event cgroup %q should name the trace", evs[0].Cgroup)
	}
	// The denied trace: the witness has nothing for it, and does not borrow the other's process.
	if n := len(w.Spawned(traceOf(ctx2))); n != 0 {
		t.Fatalf("denied trace has %d witnessed processes", n)
	}
}

// The HTTP handler closes the session, so a request leaves no cgroup behind.
func TestHTTPSessionCgroupIsRemovedAfterTheRequest(t *testing.T) {
	root := standInRoot(t)
	t.Setenv(cgroup.EnvRoot, root)
	h := harness.New()
	srv := httptest.NewServer(gateway.New(h.Tracer("http-cgroup")).Handler())
	defer srv.Close()

	resp := post(t, srv, `{"user":"alice","host":"dev-1","command":"true"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := h.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 1 { // cgroup.controllers only
		t.Fatalf("session cgroup left behind: %v", ents)
	}
}
