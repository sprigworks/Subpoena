// Command subpoena-cross cross-examines a test suite: it removes each enforcement
// statement in a temp copy of the module and requires the test suite to fail.
//
//	subpoena-cross [-timeout 5m] <dir>
//
// -timeout bounds each go command, so each mutant's test run. A mutant whose
// run times out is reported as enforcement-mutant-timeout, not killed.
//
// Exit status: 0 every mutant killed, 1 a mutant survived or was invalid,
// 2 usage or setup error (including a red baseline).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sprigworks/subpoena/internal/cross"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Minute, "bound on each go command, and so on each mutant's test run")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, "usage: subpoena-cross [-timeout 5m] <dir>") }
	flag.Parse()
	if flag.NArg() != 1 || *timeout <= 0 {
		flag.Usage()
		os.Exit(2)
	}
	rep, err := cross.Run(context.Background(), cross.Options{Target: flag.Arg(0), Timeout: *timeout, Log: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-cross:", err)
		os.Exit(2)
	}
	fmt.Printf("%d enforcement point(s), %d mutant(s)\n", rep.EnforcementPoints, len(rep.Results))
	for _, file := range rep.Snapshot {
		fmt.Printf("snapshot %s %s\n", file.SHA256, file.Path)
	}
	for _, r := range rep.Results {
		fmt.Printf("%s %s\n", r.Outcome, r.Mutant.Func)
		fmt.Printf("  at %s:%d, removed: %s\n", r.Mutant.File, r.Mutant.Line, strings.Join(strings.Fields(r.Mutant.Removed), " "))
		switch r.Outcome {
		case cross.Killed:
			fmt.Printf("  suite went red; failing: %s\n", strings.Join(r.Failing, ", "))
		case cross.Survived:
			fmt.Println("  suite stayed green with enforcement removed: the tests cannot tell enforced from unenforced")
		case cross.TimedOut:
			fmt.Println("  suite did not finish within -timeout; a hang is not a kill. Make the test fail fast instead:")
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		case cross.Invalid:
			fmt.Println("  mutant did not compile, so it proves nothing; fix the marker placement:")
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		}
	}
	if rep.Failed() {
		os.Exit(1)
	}
}
