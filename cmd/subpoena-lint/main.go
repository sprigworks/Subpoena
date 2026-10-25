// Command subpoena-lint checks a package tree for trace-native testing
// violations. See lint/README.md for the rules.
//
//	subpoena-lint [-registry dir] <dir>...
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
	registry := flag.String("registry", "", "directory of the generated semconv package (default: found above the target)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subpoena-lint [-registry dir] <dir>...")
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
	findings, err := lint.Run(flag.Args(), reg)
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
