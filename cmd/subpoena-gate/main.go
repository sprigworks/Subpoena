// Command subpoena-gate is the fault gate: it removes each enforcement
// statement in a temp copy of the module and requires the test suite to fail.
//
//	subpoena-gate <dir>
//
// Exit status: 0 every mutant killed, 1 a mutant survived or was invalid,
// 2 usage or setup error (including a red baseline).
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sprigworks/subpoena/internal/gate"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: subpoena-gate <dir>")
		os.Exit(2)
	}
	rep, err := gate.Run(context.Background(), gate.Options{Target: os.Args[1], Log: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-gate:", err)
		os.Exit(2)
	}
	for _, r := range rep.Results {
		fmt.Printf("%s %s\n", r.Outcome, r.Mutant.Func)
		fmt.Printf("  at %s:%d, removed: %s\n", r.Mutant.File, r.Mutant.Line, strings.Join(strings.Fields(r.Mutant.Removed), " "))
		switch r.Outcome {
		case gate.Killed:
			fmt.Printf("  suite went red; failing: %s\n", strings.Join(r.Failing, ", "))
		case gate.Survived:
			fmt.Println("  suite stayed green with enforcement removed: the tests cannot tell enforced from unenforced")
		case gate.Invalid:
			fmt.Println("  mutant did not compile, so it proves nothing; fix the marker placement:")
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		}
	}
	if rep.Failed() {
		os.Exit(1)
	}
}
