// Package invariants embeds jobrunner's TraceQL invariants, so tests load the
// exact string that integration checks and alert rules use. Every match of an
// invariant is a violation.
package invariants

import (
	"embed"
	"fmt"
	"strings"
)

//go:generate go run github.com/sprigworks/subpoena/cmd/subpoena-invgen

//go:embed *.traceql
var files embed.FS

// Load returns the query text of <name>.traceql.
func Load(name string) (string, error) {
	b, err := files.ReadFile(name + ".traceql")
	if err != nil {
		return "", fmt.Errorf("invariants: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// MustLoad is Load that panics, for tests and package vars.
func MustLoad(name string) string {
	q, err := Load(name)
	if err != nil {
		panic(err)
	}
	return q
}
