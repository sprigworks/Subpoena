//subpoena:spec_derived
//subpoena:pure_logic

// The evaluator protocol from docs/ports.md (Q): QUERY_FILE TRACES_FILE in,
// sorted matching trace IDs out; exit 2 for a query outside the subset, 3 for
// a query reading an array or map value, 1 for anything else. Plain files in
// and text out; no telemetry.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const fixtures = "../../conformance/fixtures/"

func query(t *testing.T, q string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "q.traceql")
	if err := os.WriteFile(p, []byte(q+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrintsMatchingTraceIDsSorted(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{query(t, `{ name = "agent.session.exec" }`), fixtures + "multiple_traces_one_push.json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	want := "c0de0000000000000000000600000001\nc0de0000000000000000000600000002\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestNoMatchPrintsNothing(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{query(t, `{ name = "no.such.span" }`), fixtures + "allow_then_exec.json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("want no output, got %q", out.String())
	}
}

func TestQueryOutsideTheSubsetExits2(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{query(t, `{ true } | count() > 1`), fixtures + "allow_then_exec.json"}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out.Len() != 0 || errOut.Len() == 0 {
		t.Fatalf("want the reason on stderr only: out %q err %q", out.String(), errOut.String())
	}
}

func TestQueryReadingAnArrayExits3(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{query(t, `{ span.process.command_args = "sleep" }`), fixtures + "array_attributes.json"}, &out, &errOut); code != 3 {
		t.Fatalf("exit %d, want 3: %s", code, errOut.String())
	}
	if out.Len() != 0 || !bytes.Contains(errOut.Bytes(), []byte("process.command_args")) {
		t.Fatalf("want the attribute named on stderr only: out %q err %q", out.String(), errOut.String())
	}
	// The same fixture, a query that does not read the array: evaluated.
	out.Reset()
	if code := run([]string{query(t, `{ name = "agent.session.exec" }`), fixtures + "array_attributes.json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if out.String() != "c0de0000000000000000000900000001\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestOtherErrorsExit1(t *testing.T) {
	q := query(t, `{ true }`)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no arguments":    nil,
		"one argument":    {q},
		"missing query":   {filepath.Join(t.TempDir(), "none.traceql"), fixtures + "allow_then_exec.json"},
		"missing traces":  {q, filepath.Join(t.TempDir(), "none.json")},
		"malformed OTLP":  {q, bad},
		"three arguments": {q, fixtures + "allow_then_exec.json", q},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
	}
}
