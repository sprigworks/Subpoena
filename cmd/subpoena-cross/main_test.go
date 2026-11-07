//subpoena:impl_derived
//subpoena:pure_logic

package main

import (
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/internal/cross"
)

// Review 6, finding 8: a repeat that hung has no output, and is no link failure.
func TestUnconfirmedAdvice(t *testing.T) {
	hint := "the link check's advice"
	if got := unconfirmedAdvice(cross.Result{Hint: hint}); len(got) != 1 || got[0] != hint {
		t.Fatalf("link check: %q", got)
	}
	got := strings.Join(unconfirmedAdvice(cross.Result{}), "\n")
	if !strings.Contains(got, "look for a flake") {
		t.Fatalf("a hang with no output: %q", got)
	}
	got = strings.Join(unconfirmedAdvice(cross.Result{Output: "one\ntwo"}), "\n")
	if !strings.Contains(got, "look for a flake") || !strings.Contains(got, "one\ntwo") {
		t.Fatalf("output: %q", got)
	}
}

// Review 9, H1. A kill lost to a hang was no flake, so the advice must not say so.
func TestUnconfirmedAdviceForAHangIsNotAFlake(t *testing.T) {
	got := strings.Join(unconfirmedAdvice(cross.Result{Hung: true, Output: "one\ntwo"}), "\n")
	if strings.Contains(got, "flake,") || !strings.Contains(got, "hung") || !strings.Contains(got, "one\ntwo") {
		t.Fatalf("got %q", got)
	}
}
