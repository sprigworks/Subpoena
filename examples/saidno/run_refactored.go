//go:build refactored

package saidno

import (
	"context"
	"net/http"
	"os/exec"

	"github.com/sprigworks/subpoena/generated/go/semconv"
)

// Run checks the command works, authorizes the request, then runs the command.
func (g *Gateway) Run(ctx context.Context, r Request) Response {
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionOpen)
	defer span.End()
	// Fail fast with a clear error on a missing or broken tool.
	if err := exec.CommandContext(ctx, r.Command, "--version").Run(); err != nil {
		return Response{Status: http.StatusBadRequest, Body: "tool not usable"}
	}
	ctx, err := g.Authorize(ctx, r)
	if err != nil {
		return g.refuse(r, err)
	}
	return g.exec(ctx, r)
}
