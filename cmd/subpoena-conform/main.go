// Command subpoena-conform checks a TraceQL evaluator, in any language,
// against the conformance corpus: every query over every fixture must give
// the trace IDs in conformance/expected.yaml, and every query in
// conformance/rejected.traceql must be rejected. The evaluator speaks the
// protocol in docs/ports.md, the one subpoena-traceql implements.
//
//	subpoena-conform [-root dir] -- COMMAND [ARGS...]
//
// The root is the Subpoena checkout holding the corpus (default: the nearest
// directory at or above the working directory that has one). It exits 0 only
// if every case agrees.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sprigworks/subpoena/conformance"
)

func main() {
	root := flag.String("root", "", "Subpoena checkout holding the corpus")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subpoena-conform [-root dir] -- COMMAND [ARGS...]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*root, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-conform:", err)
		os.Exit(1)
	}
}

func run(root string, argv []string) error {
	if root == "" {
		var err error
		if root, err = findRoot(); err != nil {
			return err
		}
	}
	c, err := conformance.LoadCorpus(root)
	if err != nil {
		return err
	}
	r, err := conformance.RunEvaluator(context.Background(), c, argv)
	if err != nil {
		return err
	}
	for _, m := range r.Mismatches {
		fmt.Println(m)
	}
	fmt.Printf("%d queries x %d fixtures + %d rejected: %d cases, %d mismatches\n",
		len(c.Queries), len(c.Fixtures), len(c.Rejected), r.Runs, len(r.Mismatches))
	if len(r.Mismatches) > 0 {
		return fmt.Errorf("%d mismatches", len(r.Mismatches))
	}
	return nil
}

func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "conformance", "rejected.traceql")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no conformance corpus here or above; pass -root")
		}
		dir = parent
	}
}
