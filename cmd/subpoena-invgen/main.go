// Command subpoena-invgen writes names.go into an invariants directory: one
// string constant per *.traceql file, so tests load an invariant by name
// (invariants.NoExecAfterDeny) instead of pasting its TraceQL, and
// subpoena-lint's orphan-invariant rule can hold them to it.
//
//	subpoena-invgen [dir]   # default "."
//
// From another module, next to its invariants package:
//
//	//go:generate go run github.com/sprigworks/subpoena/cmd/subpoena-invgen
package main

import (
	"fmt"
	"os"

	"github.com/sprigworks/subpoena/internal/invgen"
)

func main() {
	dir := "."
	switch len(os.Args) {
	case 1:
	case 2:
		dir = os.Args[1]
	default:
		fmt.Fprintln(os.Stderr, "usage: subpoena-invgen [dir]")
		os.Exit(2)
	}
	if err := invgen.Write(dir); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-invgen:", err)
		os.Exit(1)
	}
}
