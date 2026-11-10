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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sprigworks/subpoena/internal/cross"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Minute, "bound on each go command, and so on each mutant's test run")
	evidenceDir := flag.String("evidence-dir", "", "keep each mutant run's full go test -json output in this directory")
	jobs := flag.Int("j", 1, "single mutants to run at once, each in its own copy of the module")
	requireWitness := flag.Bool("require-witness", false, "accept a kill only when its first failure is independent witness evidence")
	sel := flag.Bool("select", false, "run each mutant against only the tests that executed its line (per-test coverage pass first)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subpoena-cross [-timeout 5m] [-j 1] [-select] [-require-witness] [-evidence-dir dir] <dir>")
	}
	flag.Parse()
	if flag.NArg() != 1 || *timeout <= 0 || *jobs < 1 {
		flag.Usage()
		os.Exit(2)
	}
	// Mutant runs have their own process groups, so a terminal's Ctrl-C reaches
	// only this process: cancel the run, which kills them and removes the
	// copies. A second Ctrl-C during that cleanup quits at once.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); stop() }()
	rep, err := cross.Run(ctx, cross.Options{Target: flag.Arg(0), Timeout: *timeout, Log: os.Stderr, EvidenceDir: *evidenceDir, Jobs: *jobs, Select: *sel, RequireWitness: *requireWitness})
	if err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-cross:", err)
		os.Exit(2)
	}
	fmt.Printf("%d enforcement point(s), %d marker(s), %d mutant(s)\n", rep.EnforcementPoints, rep.Markers, len(rep.Results))
	for _, at := range rep.Unplaced {
		fmt.Printf("marker made no mutant: %s\n", at)
	}
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
				fmt.Printf("  at %s, forced to %s: %s\n", where(m), m.Bypass, strings.Join(strings.Fields(m.Removed), " "))
			} else {
				fmt.Printf("  at %s, removed: %s\n", where(m), strings.Join(strings.Fields(m.Removed), " "))
			}
		}
		for _, z := range r.ZeroReturns {
			fmt.Printf("  the function cannot end without a return, so this mutant has: %s\n", z)
		}
		switch r.Outcome {
		case cross.Killed, cross.KilledBySelfReport:
			fmt.Printf("  suite went red; failing: %s\n", strings.Join(r.Failing, ", "))
			fmt.Printf("  first evidence (%s): %s\n", r.Evidence, r.FirstFailure)
			if r.Outcome == cross.KilledBySelfReport {
				fmt.Println("  require-witness: the first failure was not witness evidence; ask the witness before return values or telemetry")
				if r.Why != "" {
					fmt.Println("  " + r.Why)
				}
				if r.Output != "" {
					fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
				}
			}
			if r.Evidence != cross.EvidenceWitness && strings.HasPrefix(r.FirstFailure, "witness:") {
				fmt.Println("  this witness: tag is not the harness's: a tag counts only through the harness, or harness.WitnessErrorf in a test, on a *testing.T, B or F")
			}
			if r.LaterWitness != "" {
				fmt.Printf("  a witness failure came later: %s\n", r.LaterWitness)
				fmt.Println("  if the line above is a t.Log, not an assertion, move it after the witness check: go test prints both alike")
			}
		case cross.Unconfirmed:
			fmt.Printf("  suite went red, but the kill did not hold: %s\n", r.Why)
			fmt.Printf("  failing: %s\n", strings.Join(r.Failing, ", "))
			for _, line := range unconfirmedAdvice(r) {
				fmt.Println("  " + line)
			}
		case cross.Survived:
			fmt.Println("  suite stayed green with enforcement removed: the tests cannot tell enforced from unenforced")
			if len(r.ZeroReturns) > 0 {
				fmt.Println("  unless the marked return gave those same values (a constant that is zero): then mark the guard instead")
			}
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
			fmt.Printf("  suite did not finish within -timeout %s; a hang is not a kill. Make the test fail fast instead.\n", *timeout)
			if len(r.Unfinished) > 0 {
				fmt.Printf("  still running: %s\n", strings.Join(r.Unfinished, ", "))
			}
			fmt.Println("  " + strings.ReplaceAll(r.Output, "\n", "\n  "))
		case cross.Invalid:
			if r.Hint != "" {
				fmt.Println("  mutant did not compile, so it proves nothing: " + r.Hint)
			} else {
				fmt.Println("  mutant did not compile, so it proves nothing; fix the marker placement:")
			}
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

// unconfirmedAdvice is what to do about an unconfirmed kill. A repeat that hung
// can leave no output, so the output says nothing of which case this is.
func unconfirmedAdvice(r cross.Result) []string {
	if r.Hint != "" {
		return []string{r.Hint}
	}
	advice := []string{"the red run proves nothing: look for a flake, or state outside the copy"}
	if r.Hung {
		advice = []string{"the repeats hung, even with each failed package alone, so nothing shows the red was a flake or the mutant's: find what hangs in the failed package with the mutant, or raise -timeout if it is only slow"}
	}
	if r.Output != "" {
		advice = append(advice, strings.Split(r.Output, "\n")...)
	}
	return advice
}

// where is a mutant's file and line, with the unmarked line when markers moved it.
func where(m cross.Mutant) string {
	if m.Upstream != m.Line {
		return fmt.Sprintf("%s:%d (upstream line %d)", m.File, m.Line, m.Upstream)
	}
	return fmt.Sprintf("%s:%d", m.File, m.Line)
}
