// Command subpoena-lint checks a package tree for trace-native testing
// violations. See lint/README.md for the rules.
//
//	subpoena-lint [-registry dir] [-invariants dir] [-dead-telemetry] <dir>...
//	subpoena-lint registry-drift [--base ref] [repo]
//
// Exit status: 0 clean, 1 findings, 2 usage or load error.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sprigworks/subpoena/internal/lint"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "registry-drift" {
		os.Exit(registryDrift(os.Args[2:]))
	}
	registry := flag.String("registry", "", "directory of the generated semconv package (default: found above the target)")
	invariants := flag.String("invariants", "", "directory of *.traceql invariants (default: invariants/ found above the target)")
	dead := flag.Bool("dead-telemetry", false, "also report registry entries no target emits (the targets must be the whole service)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subpoena-lint [-registry dir] [-invariants dir] [-dead-telemetry] <dir>...")
		fmt.Fprintln(os.Stderr, "       subpoena-lint registry-drift [--base ref] [repo]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	dir := *registry
	if dir == "" {
		d, err := lint.FindRegistryDir(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		dir = d
	}
	reg, err := lint.LoadRegistry(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	findings, err := lint.RunWith(flag.Args(), reg, lint.Options{InvariantsDir: *invariants, DeadTelemetry: *dead, Warn: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Println(f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "subpoena-lint: %d finding(s)\n", len(findings))
		os.Exit(1)
	}
	fmt.Println("subpoena-lint: clean")
}

// registryDrift runs the registry-drift rule over a git repository.
func registryDrift(args []string) int {
	fs := flag.NewFlagSet("registry-drift", flag.ExitOnError)
	base := fs.String("base", "", "revision to compare against (default HEAD: working tree vs HEAD); a branch ref is resolved to its merge-base with HEAD")
	_ = fs.Parse(args)
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: subpoena-lint registry-drift [--base ref] [repo]")
		return 2
	}
	repo := "."
	if fs.NArg() == 1 {
		repo = fs.Arg(0)
	}
	findings, err := lint.CheckRegistryDrift(lint.DriftOptions{Repo: repo, Base: *base})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	for _, f := range findings {
		fmt.Println(f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "subpoena-lint registry-drift: %d finding(s)\n", len(findings))
		return 1
	}
	fmt.Println("subpoena-lint registry-drift: clean")
	return 0
}
