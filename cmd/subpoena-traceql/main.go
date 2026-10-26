// Command subpoena-traceql evaluates one query of the TraceQL subset
// (docs/traceql-subset.md) over OTLP/JSON traces, with pkg/traceql. It is the
// reference for the evaluator protocol in docs/ports.md, and lets a harness in
// another language use the Go evaluator until it has its own.
//
//	subpoena-traceql QUERY_FILE TRACES_FILE
//
// It prints the matching trace IDs, one per line, sorted, and exits 0. It exits
// 2 if the query is outside the subset, 3 if it reads an attribute holding an
// array or map value (the reason on stderr in both cases), and 1 on any other
// error.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sprigworks/subpoena/conformance"
	"github.com/sprigworks/subpoena/pkg/traceql"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: subpoena-traceql QUERY_FILE TRACES_FILE")
		return 1
	}
	src, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "subpoena-traceql:", err)
		return 1
	}
	f, err := conformance.LoadFixture(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "subpoena-traceql:", err)
		return 1
	}
	traces, err := f.Traces()
	if err != nil {
		fmt.Fprintln(stderr, "subpoena-traceql:", err)
		return 1
	}
	q, err := traceql.Parse(strings.TrimSpace(string(src)))
	if err != nil {
		fmt.Fprintln(stderr, "subpoena-traceql:", err)
		return 2
	}
	ms, err := q.Eval(traces)
	var unsupported *traceql.UnsupportedValueError
	if errors.As(err, &unsupported) {
		fmt.Fprintln(stderr, "subpoena-traceql:", err)
		return 3
	}
	if err != nil {
		fmt.Fprintln(stderr, "subpoena-traceql:", err)
		return 1
	}
	var ids []string
	for _, m := range ms {
		ids = append(ids, m.TraceID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintln(stdout, id)
	}
	return 0
}
