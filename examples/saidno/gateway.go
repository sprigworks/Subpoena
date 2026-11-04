// Package saidno is a toy agent gateway with a bug its ordinary suite doesn't catch.
//
// The rule: a request from an agent other than the operator is refused, and
// its tool never runs. The file run_original.go keeps that rule. The file
// run_refactored.go, built with the refactored tag, checks the command works
// before it authorizes the request. It still answers 403, logs the denial and
// records a denial span, and the tool has already run. demo.sh shows both.
//
// This is a constructed example, written to be small. See README.md.
package saidno

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/sprigworks/subpoena/generated/go/semconv"
)

// Operator is the only agent the policy allows to run commands.
const Operator = "operator"

// ErrDenied is returned by Authorize when policy refuses a request.
var ErrDenied = errors.New("saidno: denied")

// Request asks the gateway to run a command for an agent.
type Request struct {
	Agent   string
	Command string
	Args    []string
}

// Response is what the caller gets back.
type Response struct {
	Status int
	Body   string
}

// Gateway runs commands for agents that policy allows.
type Gateway struct {
	tracer trace.Tracer
	log    *slog.Logger
}

// New returns a Gateway that traces with t and logs to l.
func New(t trace.Tracer, l *slog.Logger) *Gateway { return &Gateway{tracer: t, log: l} }

// Authorize decides whether r may run. Only the operator may run commands.
//
//subpoena:enforcement_point
func (g *Gateway) Authorize(ctx context.Context, r Request) (context.Context, error) {
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionAuthorize)
	defer span.End()
	allowed := r.Agent == Operator
	span.SetAttributes(
		attribute.Bool(semconv.AttrAuthorizationAllowed, allowed),
		attribute.String(semconv.AttrAuthorizationPolicyId, "operator-only"),
	)
	if !allowed {
		span.SetStatus(codes.Error, "denied by policy")
		return ctx, fmt.Errorf("%w: agent %s", ErrDenied, r.Agent) //subpoena:enforcement
	}
	return ctx, nil
}

// exec runs an authorized command and records it.
func (g *Gateway) exec(ctx context.Context, r Request) Response {
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionExec)
	defer span.End()
	c := exec.CommandContext(ctx, r.Command, r.Args...)
	span.SetAttributes(attribute.String(semconv.AttrProcessCommandLine, strings.Join(c.Args, " ")))
	if err := c.Run(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return Response{Status: http.StatusInternalServerError, Body: "command failed"}
	}
	return Response{Status: http.StatusOK, Body: "done"}
}

// refuse answers a denied request.
func (g *Gateway) refuse(r Request, err error) Response {
	g.log.Warn("request denied", "agent", r.Agent, "error", err)
	return Response{Status: http.StatusForbidden, Body: "denied"}
}
