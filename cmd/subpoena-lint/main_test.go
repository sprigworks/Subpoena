//subpoena:impl_derived
//subpoena:pure_logic

package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaleExemptionCLI(t *testing.T) {
	if os.Getenv("SUBPOENA_LINT_CHILD") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{"subpoena-lint"}, os.Args[i+1:]...)
				break
			}
		}
		flag.CommandLine = flag.NewFlagSet("subpoena-lint", flag.ExitOnError)
		main()
		return
	}
	dir := t.TempDir()
	registry := filepath.Join(dir, "registry")
	target := filepath.Join(dir, "service")
	for _, path := range []string{registry, target} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(registry, "names.go"): "package semconv\nconst SpanA = \"a\"\n",
		filepath.Join(target, "service.go"): "package service\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range []string{"unknown-telemetry", "orphan-invariant"} {
		t.Run(rule, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStaleExemptionCLI$", "--", "-registry", registry, "-exempt", rule+"=obsolete waiver", target)
			cmd.Env = append(os.Environ(), "SUBPOENA_LINT_CHILD=1")
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 || !strings.Contains(string(out), "stale exemption") {
				t.Fatalf("want exit 2 for stale exemption, got %v:\n%s", err, out)
			}
		})
	}
}
