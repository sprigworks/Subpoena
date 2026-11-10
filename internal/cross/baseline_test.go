//subpoena:impl_derived

package cross

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A timeout used to give an empty reason: plain go test buffers a package's
// output, so nothing had reached cross when it was stopped.
func TestBaselineTimeoutSaysSo(t *testing.T) {
	const hanging = `package mini

import "testing"

func TestHang(t *testing.T) { select {} }
`
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": hanging})
	_, err := Run(context.Background(), Options{Target: dir, Timeout: 8 * time.Second})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"baseline suite is not green", "timed out", "-timeout"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in:\n%v", want, err)
		}
	}
}

func TestBaselineRedTestIsNamed(t *testing.T) {
	failing := strongTest + "\nfunc TestBroken(t *testing.T) { t.Fatal(\"the reason\") }\n"
	const noisy = `package noisy

import "testing"

func TestChatter(t *testing.T) { t.Log("passing chatter") }
`
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": failing, "noisy/n_test.go": noisy})
	_, err := run(t, dir)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"TestBroken", "the reason", "exit status 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "passing chatter") {
		t.Errorf("a passing test's log is noise:\n%v", err)
	}
}

func TestBaselineBuildFailureIsShown(t *testing.T) {
	dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": strongTest + "\nvar broken = undefinedName\n"})
	_, err := run(t, dir)
	if err == nil || !strings.Contains(err.Error(), "undefinedName") {
		t.Fatalf("want the compiler's line, got %v", err)
	}
}

func TestBaselineReason(t *testing.T) {
	timeoutErr := fmt.Errorf("go test: %w after 5m0s", errTimeout)
	running := `{"Action":"start","Package":"p"}
{"Action":"run","Package":"p","Test":"TestSlow"}
{"Action":"output","Package":"p","Test":"TestSlow","Output":"=== RUN   TestSlow\n"}
`
	binaryTimeout := running + `{"Action":"output","Package":"p","Test":"TestSlow","Output":"panic: test timed out after 10m0s\n"}
{"Action":"output","Package":"p","Test":"TestSlow","Output":"\trunning tests:\n"}
{"Action":"output","Package":"p","Test":"TestSlow","Output":"\t\tTestSlow (10m0s)\n"}
` + strings.Repeat(`{"Action":"output","Package":"p","Test":"TestSlow","Output":"goroutine dump\n"}
`, 60) + `{"Action":"fail","Package":"p","Test":"TestSlow"}
{"Action":"fail","Package":"p"}
`
	var manyPassed strings.Builder
	manyPassed.WriteString(`{"Action":"output","Package":"bad","Test":"TestX","Output":"    a_test.go:1: the real reason\n"}
{"Action":"fail","Package":"bad","Test":"TestX"}
{"Action":"fail","Package":"bad"}
`)
	for i := range 60 {
		fmt.Fprintf(&manyPassed, `{"Action":"output","Package":"ok%d","Output":"ok  \tok%d\t0.1s\n"}
{"Action":"pass","Package":"ok%d"}
`, i, i, i)
	}
	cases := []struct {
		name string
		raw  string
		err  error
		want []string
	}{
		{"cross's timeout, with what was running", running, timeoutErr, []string{"timed out", "-timeout", "p TestSlow", "not a red test"}},
		{"nothing printed at all", "", timeoutErr, []string{"timed out", "-timeout"}},
		{"the test binary's own timeout", binaryTimeout, errors.New("exit status 1"), []string{"timed out", "TestSlow (10m0s)", "go test's own"}},
		{"killed, no output", "", errors.New("signal: killed"), []string{"signal: killed", "printed nothing"}},
		{"a failure ahead of many passing packages", manyPassed.String(), errors.New("exit status 1"), []string{"the real reason", "exit status 1"}},
		{"not go test -json output", "go: cannot find main module\n", errors.New("exit status 1"), []string{"cannot find main module"}},
	}
	for _, c := range cases {
		got := baselineReason(c.raw, c.err)
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: want %q in:\n%s", c.name, want, got)
			}
		}
		if strings.Contains(got, "ok  \t") {
			t.Errorf("%s: passing packages in:\n%s", c.name, got)
		}
	}
}
