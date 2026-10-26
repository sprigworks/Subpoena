// Package invariants embeds the repository's TraceQL invariants so tests load
// the exact string that OATS and the alert rules use.
//
// Semantics of every invariant file: any matching trace is a violation.
package invariants

import (
	"embed"
	"fmt"
	"strings"
)

//go:generate go run gen.go

//go:embed *.traceql
var files embed.FS

// Load returns the query text of invariants/<name>.traceql.
func Load(name string) (string, error) {
	b, err := files.ReadFile(name + ".traceql")
	if err != nil {
		return "", fmt.Errorf("invariants: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// MustLoad is Load that panics, for use in tests and package vars.
func MustLoad(name string) string {
	q, err := Load(name)
	if err != nil {
		panic(err)
	}
	return q
}
