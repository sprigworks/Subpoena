// Package jobrunner is a toy CI job runner, written as a separate module that
// adopts Subpoena from outside: its own registry, generated names, invariants,
// tests, lint and gate, using only Subpoena's public packages and commands.
//
// The rule it enforces: a job from an untrusted source (a fork) that asks for
// secrets is rejected and never runs.
package jobrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"example.com/jobrunner/generated/go/semconv"
)

// ErrRejected is returned for a job that was not admitted.
var ErrRejected = errors.New("jobrunner: job rejected")

// Job is a submitted job.
type Job struct {
	ID           string
	Trusted      bool // from the main repository, not a fork
	WantsSecrets bool
	Command      string
	Args         []string
}

// Runner admits and runs jobs.
type Runner struct{ tracer trace.Tracer }

// New returns a Runner that traces with t.
func New(t trace.Tracer) *Runner { return &Runner{tracer: t} }

// Submit receives a job, admits it, and runs it if admitted.
func (r *Runner) Submit(ctx context.Context, j Job) ([]byte, error) {
	ctx, span := r.tracer.Start(ctx, semconv.SpanCiJobReceive, trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	span.SetAttributes(
		attribute.String(semconv.AttrCiJobId, j.ID),
		attribute.Bool(semconv.AttrCiJobTrusted, j.Trusted),
		attribute.Bool(semconv.AttrCiJobSecretsRequested, j.WantsSecrets),
	)
	ctx, err := r.Admit(ctx, j)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return r.exec(ctx, j)
}

// Admit decides whether j may run. An untrusted job that wants secrets may not.
//
//subpoena:enforcement_point
func (r *Runner) Admit(ctx context.Context, j Job) (context.Context, error) {
	ctx, span := r.tracer.Start(ctx, semconv.SpanCiJobAdmit)
	defer span.End()
	allowed := j.Trusted || !j.WantsSecrets
	span.SetAttributes(
		attribute.String(semconv.AttrCiJobId, j.ID),
		attribute.Bool(semconv.AttrCiAdmissionAllowed, allowed),
	)
	if !allowed {
		span.SetStatus(codes.Error, "untrusted job requested secrets")
		return ctx, fmt.Errorf("%w: %s is untrusted and requested secrets", ErrRejected, j.ID) //subpoena:enforcement
	}
	return ctx, nil
}

func (r *Runner) exec(ctx context.Context, j Job) ([]byte, error) {
	ctx, span := r.tracer.Start(ctx, semconv.SpanCiJobExec)
	defer span.End()
	span.SetAttributes(attribute.String(semconv.AttrCiJobId, j.ID))
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, j.Command, j.Args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}
