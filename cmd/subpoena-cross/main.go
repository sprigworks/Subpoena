// Command subpoena-cross cross-examines a test suite: it removes each enforcement
// statement in a temp copy of the module and requires the test suite to fail.
//
//	subpoena-cross [-timeout 5m] <dir>
//
// -timeout bounds each go command, so each mutant's test run. A mutant whose
// run times out is reported as enforcement-mutant-timeout, not killed.
//
// A layer that survives alone while its group is killed is reported as
// enforcement-layer-masked, naming the masking layer. It fails the run unless
// it is listed, with a reason, in cross-masked.txt in the target directory.
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
	evidenceDir := flag.String("evidence-dir", "", "keep each mutant run's full go test -json output in this directory")
	jobs := flag.Int("j", 1, "single mutants to run at once, each in its own copy of the module")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subpoena-cross [-timeout 5m] [-j 1] [-evidence-dir dir] <dir>")
	}
	flag.Parse()
	if flag.NArg() != 1 || *timeout <= 0 || *jobs < 1 {
		flag.Usage()
		os.Exit(2)
	}
	rep, err := cross.Run(context.Background(), cross.Options{Target: flag.Arg(0), Timeout: *timeout, Log: os.Stderr, EvidenceDir: *evidenceDir, Jobs: *jobs})
	if err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-cross:", err)
		os.Exit(2)
	}
	fmt.Printf("%d enforcement point(s), %d mutant(s)\n", rep.EnforcementPoints, len(rep.Results))
	for _, file := range rep.Snapshot {
		fmt.Printf("snapshot %s %s\n", file.SHA256, file.Path)
	}
	for _, r := range rep.Results {
		if r.Group != "" {
			fmt.Printf("%s group=%s, %d layers together\n", r.Outcome, r.Group, 1+len(r.With))
		} else {
			fmt.Printf("%s %s\n", r.Outcome, r.Mutant.Func)
		}
		for _, m := range append([]cross.Mutant{r.Mutant}, r.With...) {
			if m.Bypass != "" {
				fmt.Printf("  at %s:%d, forced to %s: %s\n", m.File, m.Line, m.Bypass, strings.Join(strings.Fields(m.Removed), " "))
			} else {
				fmt.Printf("  at %s:%d, removed: %s\n", m.File, m.Line, strings.Join(strings.Fields(m.Removed), " "))
			}
		}
		switch r.Outcome {
		case cross.Killed:
			fmt.Printf("  suite went red; failing: %s\n", strings.Join(r.Failing, ", "))
			fmt.Printf("  first evidence (%s): %s\n", r.Evidence, r.FirstFailure)
		case cross.Survived:
			fmt.Println("  suite stayed green with enforcement removed: the tests cannot tell enforced from unenforced")
		case cross.Masked:
			if len(r.MaskedBy) > 0 {
				fmt.Printf("  stayed green alone; red with group=%s. Masked by: %s\n", r.Mutant.Group, strings.Join(r.MaskedBy, ", "))
			} else {
				fmt.Printf("  stayed green alone and with any one other layer; red only with the group's other surviving layers together\n")
			}
			if r.Accepted != "" {
				fmt.Printf("  accepted in %s: %s\n", cross.MaskedFile, r.Accepted)
			} else {
				fmt.Printf("  not listed in %s, so this fails the run. Prefer a test that catches this layer alone.\n", cross.MaskedFile)
			}
		case cross.Crashed:
			fmt.Println("  suite went red by a crash, with no clean failure message; a crash is not a kill:")
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		case cross.TimedOut:
			fmt.Println("  suite did not finish within -timeout; a hang is not a kill. Make the test fail fast instead:")
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		case cross.Invalid:
			fmt.Println("  mutant did not compile, so it proves nothing; fix the marker placement:")
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		}
	}
	for _, e := range rep.StaleAccepted {
		fmt.Printf("stale %s entry, no masked layer matches: %s\n", cross.MaskedFile, e)
	}
	if rep.Failed() {
		os.Exit(1)
	}
}
