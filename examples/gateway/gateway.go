// Package gateway is a toy agent gateway used to demonstrate trace-native
// testing. It has three operations: open a session, authorize an action, and
// exec a command. Authorize is the enforcement point: when it denies, exec must
// never run.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/sprigworks/subpoena/generated/go/semconv"
	"github.com/sprigworks/subpoena/pkg/cgroup"
)

// ErrDenied is returned by Authorize when policy denies the action.
var ErrDenied = errors.New("gateway: authorization denied")

// Gateway wires the three operations to a tracer.
type Gateway struct {
	tracer   trace.Tracer
	cgroups  *cgroup.Manager // nil: never create session cgroups
	fallback string          // correlation recorded when no cgroup is available
	log      *slog.Logger
	logOnce  sync.Once
}

// Option configures a Gateway.
type Option func(*Gateway)

// WithCgroups sets where per-session cgroups are created. The default is
// cgroup.FromEnv(): $SUBPOENA_CGROUP_ROOT, else /sys/fs/cgroup/subpoena. Pass
// nil to disable cgroups.
func WithCgroups(m *cgroup.Manager) Option { return func(g *Gateway) { g.cgroups = m } }

// WithFallbackCorrelation sets the correlation mode recorded on exec spans when
// no session cgroup is available: semconv.ValSubpoenaWitnessCorrelationLineage
// (the default; a witness follows parent-process lineage, as ProcWitness does)
// or ...Argument (the witness is told apart by a distinguishing command-line
// argument, as the OATS case does). Any other value panics.
func WithFallbackCorrelation(mode string) Option {
	if mode != semconv.ValSubpoenaWitnessCorrelationLineage && mode != semconv.ValSubpoenaWitnessCorrelationArgument {
		panic(fmt.Sprintf("gateway: fallback correlation %q must be %q or %q", mode,
			semconv.ValSubpoenaWitnessCorrelationLineage, semconv.ValSubpoenaWitnessCorrelationArgument))
	}
	return func(g *Gateway) { g.fallback = mode }
}

// WithLogger sets the logger for cgroup diagnostics, which are logged at debug
// level and at most once per Gateway.
func WithLogger(l *slog.Logger) Option { return func(g *Gateway) { g.log = l } }

// New returns a Gateway that emits spans with tracer.
func New(tracer trace.Tracer, opts ...Option) *Gateway {
	g := &Gateway{
		tracer:   tracer,
		cgroups:  cgroup.FromEnv(),
		fallback: semconv.ValSubpoenaWitnessCorrelationLineage,
		log:      slog.Default(),
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// debugOnce logs the first cgroup problem at debug level and stays quiet after,
// so a host without cgroup v2 does not log on every session.
func (g *Gateway) debugOnce(msg string, err error) {
	g.logOnce.Do(func() {
		g.log.Debug("gateway: "+msg+"; correlating by "+g.fallback, "error", err)
	})
}

// Session is an opened agent session.
type Session struct {
	ID   string
	User User

	group *cgroup.Group // nil when no session cgroup could be created
}

// Close releases the session's cgroup, if it has one. Call it when the session
// is over; a cgroup can only be removed once its processes have exited.
func (s *Session) Close() error {
	if s.group == nil {
		return nil
	}
	g := s.group
	s.group = nil
	return g.Remove()
}

// Open starts a session. The returned context carries the open span, so
// authorize and exec spans become its descendants.
func (g *Gateway) Open(ctx context.Context, u User) (context.Context, *Session) {
	s := &Session{ID: newSessionID(), User: u}
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionOpen)
	defer span.End()
	span.SetAttributes(attribute.String(semconv.AttrSessionId, s.ID))
	// One cgroup per session, named with the trace ID, so a witness outside this
	// process can tie every process the session spawns to its trace. Any failure
	// falls back to lineage correlation.
	if g.cgroups != nil {
		if sc := span.SpanContext(); sc.HasTraceID() {
			grp, err := g.cgroups.Create(sc.TraceID().String())
			if err != nil {
				g.debugOnce("session cgroup unavailable", err)
			} else {
				s.group = grp
			}
		}
	}
	return ctx, s
}

// Authorize evaluates policy for running something on host.
//
// The returned context carries the authorize span; exec must be issued with it
// so the trace records that exec happened downstream of this decision.
//
//subpoena:enforcement_point
func (g *Gateway) Authorize(ctx context.Context, s *Session, host string) (context.Context, error) {
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionAuthorize)
	defer span.End()
	decision := Evaluate(s.User, host)
	span.SetAttributes(
		attribute.String(semconv.AttrSessionId, s.ID),
		attribute.Bool(semconv.AttrAuthorizationAllowed, decision.Allowed),
		attribute.String(semconv.AttrAuthorizationPolicyId, decision.PolicyID),
	)
	if !decision.Allowed {
		span.SetStatus(codes.Error, "denied by "+decision.PolicyID)
		return ctx, fmt.Errorf("%w: %s on %s", ErrDenied, decision.PolicyID, host) //subpoena:enforcement
	}
	return ctx, nil
}

// allowed lists the only commands Exec will run. The gateway is a demo that
// may be exposed over HTTP in the OATS stack, so it must not run arbitrary
// commands.
var allowed = map[string]bool{"true": true, "echo": true, "sleep": true}

// Exec spawns a harmless process on behalf of the session and returns its
// combined output. The process is started inside the session's cgroup when it
// has one, and the exec span records how a witness can correlate it
// (semconv.AttrSubpoenaWitnessCorrelation).
func (g *Gateway) Exec(ctx context.Context, s *Session, command string, args ...string) ([]byte, error) {
	if !allowed[command] {
		return nil, fmt.Errorf("gateway: command %q not allowed", command)
	}
	line := strings.TrimSpace(command + " " + strings.Join(args, " "))
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionExec)
	defer span.End()
	span.SetAttributes(
		attribute.String(semconv.AttrSessionId, s.ID),
		attribute.String(semconv.AttrProcessCommandLine, line),
	)
	var out bytes.Buffer
	newCmd := func() *exec.Cmd {
		out.Reset()
		cmd := exec.CommandContext(ctx, command, args...)
		cmd.Stdout, cmd.Stderr = &out, &out
		return cmd
	}
	cmd, mode, err := g.start(s, newCmd)
	if err != nil {
		span.SetAttributes(attribute.String(semconv.AttrSubpoenaWitnessCorrelation, g.fallback))
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	span.SetAttributes(attribute.String(semconv.AttrSubpoenaWitnessCorrelation, mode))
	if err := cmd.Wait(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

// start launches the command in the session's cgroup if there is one, and says
// which correlation a witness can rely on for the result.
func (g *Gateway) start(s *Session, newCmd func() *exec.Cmd) (*exec.Cmd, string, error) {
	if s.group == nil {
		cmd := newCmd()
		return cmd, g.fallback, cmd.Start()
	}
	cmd, placeErr, err := s.group.Start(newCmd)
	if err != nil {
		return nil, g.fallback, err
	}
	if placeErr != nil {
		g.debugOnce("could not place process in session cgroup", placeErr)
		return cmd, g.fallback, nil
	}
	return cmd, semconv.ValSubpoenaWitnessCorrelationCgroup, nil
}

// Run is the full request path: authorize, then exec only if authorized.
func (g *Gateway) Run(ctx context.Context, s *Session, host, command string, args ...string) ([]byte, error) {
	ctx, err := g.Authorize(ctx, s, host)
	if err != nil {
		return nil, err
	}
	return g.Exec(ctx, s, command, args...)
}

func newSessionID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "sess-" + hex.EncodeToString(b[:])
}

func traceIDFrom(ctx context.Context) string {
	return trace.SpanContextFromContext(ctx).TraceID().String()
}
