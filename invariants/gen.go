//go:build ignore

// gen.go writes names.go. Run with `go generate ./invariants` (or `make generate-invariants`).
package main

import (
	"fmt"
	"os"

	"github.com/sprigworks/subpoena/internal/invgen"
)

func main() {
	if err := invgen.Write("."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
