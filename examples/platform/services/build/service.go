// Package build applies a service-owned policy using the platform contract.
package build

import (
	"context"
	"errors"
	"os/exec"

	"example.com/platform/contract/generated/go/semconv"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var ErrDenied = errors.New("build: action denied")

type Request struct {
	ID                    string
	Trusted, WantsSecrets bool
	Command               string
	Args                  []string
}
type Service struct{ tracer trace.Tracer }

func New(t trace.Tracer) *Service { return &Service{tracer: t} }
func (s *Service) Run(ctx context.Context, r Request) error {
	ctx, err := s.Authorize(ctx, r)
	if err != nil {
		return err
	}
	ctx, span := s.tracer.Start(ctx, semconv.SpanPlatformActionExec)
	defer span.End()
	span.SetAttributes(attribute.String(semconv.AttrPlatformActionId, r.ID))
	return exec.CommandContext(ctx, r.Command, r.Args...).Run()
}

// Authorize is this service's policy boundary.
//
//subpoena:enforcement_point
func (s *Service) Authorize(ctx context.Context, r Request) (context.Context, error) {
	ctx, span := s.tracer.Start(ctx, semconv.SpanPlatformActionAuthorize)
	defer span.End()
	allowed := r.Trusted || !r.WantsSecrets
	span.SetAttributes(attribute.String(semconv.AttrPlatformActionId, r.ID), attribute.Bool(semconv.AttrPlatformAuthorizationAllowed, allowed))
	if !allowed {
		span.SetStatus(codes.Error, "denied")
		return ctx, ErrDenied //subpoena:enforcement
	}
	return ctx, nil
}
