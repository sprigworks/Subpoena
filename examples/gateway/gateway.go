// Package gateway is a toy agent gateway used to demonstrate trace-native
// testing. It has three operations: open a session, authorize an action, and
// exec a command. Authorize is the enforcement point: when it denies, exec must
// never run.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/sprigworks/subpoena/generated/go/semconv"
)

// ErrDenied is returned by Authorize when policy denies the action.
var ErrDenied = errors.New("gateway: authorization denied")

// Gateway wires the three operations to a tracer.
type Gateway struct {
	tracer trace.Tracer
}

// New returns a Gateway that emits spans with tracer.
func New(tracer trace.Tracer) *Gateway { return &Gateway{tracer: tracer} }

// Session is an opened agent session.
type Session struct {
	ID   string
	User User
}

// Open starts a session. The returned context carries the open span, so
// authorize and exec spans become its descendants.
func (g *Gateway) Open(ctx context.Context, u User) (context.Context, *Session) {
	s := &Session{ID: newSessionID(), User: u}
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionOpen)
	defer span.End()
	span.SetAttributes(attribute.String(semconv.AttrSessionId, s.ID))
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
// combined output.
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
	out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	return out, err
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
