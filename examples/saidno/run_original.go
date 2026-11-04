//go:build !refactored

package saidno

import (
	"context"

	"github.com/sprigworks/subpoena/generated/go/semconv"
)

// Run authorizes the request, then runs the command.
func (g *Gateway) Run(ctx context.Context, r Request) Response {
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionOpen)
	defer span.End()
	ctx, err := g.Authorize(ctx, r)
	if err != nil {
		return g.refuse(r, err)
	}
	return g.exec(ctx, r)
}
