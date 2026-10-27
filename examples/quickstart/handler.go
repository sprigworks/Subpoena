// Package quickstart is the smallest honest adoption of Subpoena: one rule,
// one enforcement point, no registry.
//
// The rule: a delete-account request from a non-admin is refused and never
// runs the purge process.
package quickstart

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Span names and attribute keys. Plain constants: nothing checks them against
// a registry at this level.
const (
	SpanDeleteReceive = "account.delete.receive"
	SpanDeleteAuth    = "account.delete.authorize"
	SpanDeletePurge   = "account.delete.purge"
	AttrAccountID     = "account.id"
	AttrAllowed       = "account.delete.allowed"
)

// ErrRefused is returned for a request that was not authorized.
var ErrRefused = errors.New("quickstart: delete refused")

// Request asks to delete an account.
type Request struct {
	AccountID string
	IsAdmin   bool
	Command   string // the purge process; a real service would not take this from a caller
	Args      []string
}

// Handler deletes accounts.
type Handler struct{ tracer trace.Tracer }

// New returns a Handler that traces with t.
func New(t trace.Tracer) *Handler { return &Handler{tracer: t} }

// Delete authorizes the request, then runs the purge process if allowed.
func (h *Handler) Delete(ctx context.Context, r Request) error {
	ctx, span := h.tracer.Start(ctx, SpanDeleteReceive, trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	span.SetAttributes(attribute.String(AttrAccountID, r.AccountID))
	ctx, err := h.Authorize(ctx, r)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return h.purge(ctx, r)
}

// Authorize decides whether r may run. Only an admin may delete an account.
//
//subpoena:enforcement_point
func (h *Handler) Authorize(ctx context.Context, r Request) (context.Context, error) {
	ctx, span := h.tracer.Start(ctx, SpanDeleteAuth)
	defer span.End()
	span.SetAttributes(
		attribute.String(AttrAccountID, r.AccountID),
		attribute.Bool(AttrAllowed, r.IsAdmin),
	)
	if !r.IsAdmin {
		span.SetStatus(codes.Error, "non-admin delete")
		return ctx, fmt.Errorf("%w: %s", ErrRefused, r.AccountID) //subpoena:enforcement
	}
	return ctx, nil
}

func (h *Handler) purge(ctx context.Context, r Request) error {
	ctx, span := h.tracer.Start(ctx, SpanDeletePurge)
	defer span.End()
	span.SetAttributes(attribute.String(AttrAccountID, r.AccountID))
	if err := exec.CommandContext(ctx, r.Command, r.Args...).Run(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}
