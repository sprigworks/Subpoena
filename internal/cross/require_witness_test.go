//subpoena:impl_derived

package cross

import (
	"context"
	"strings"
	"testing"
)

// Later witness evidence cannot redeem a failure already decided by testimony.
func TestRequireWitness(t *testing.T) {
	for _, tc := range []struct {
		name, test string
		strict     bool
		want       Outcome
	}{
		{"default", strongTest, false, Killed},
		{"return value", strongTest, true, KilledBySelfReport},
		{"testimony", strings.Replace(strongTest, "non-admin must be denied", "testimony: no denial span", 1), true, KilledBySelfReport},
		{"witness", tagTest, true, Killed},
		{"later witness", strings.Replace(strongTest, `t.Fatal("non-admin must be denied")`, `t.Error("non-admin must be denied"); t.Error("witness: process ran")`, 1), true, KilledBySelfReport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := module(t, map[string]string{"auth.go": authOK, "auth_test.go": tc.test})
			rep, err := Run(context.Background(), Options{Target: dir, RequireWitness: tc.strict})
			if err != nil {
				t.Fatal(err)
			}
			got := rep.Results[0]
			if got.Outcome != tc.want || rep.Failed() != (tc.want != Killed) {
				t.Fatalf("want %s, got %+v (failed=%v)", tc.want, got, rep.Failed())
			}
			if got.FirstFailure == "" || len(got.Failing) == 0 {
				t.Fatalf("lost diagnostic evidence: %+v", got)
			}
		})
	}
}

func TestRequireWitnessGroupCannotAcceptSelfReportMasking(t *testing.T) {
	dir := module(t, map[string]string{"exec.go": layeredSrc, "exec_test.go": layeredTest, MaskedFile: maskedList})
	rep, err := Run(context.Background(), Options{Target: dir, RequireWitness: true, Select: true, Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Failed() || len(rep.Results) != 3 || rep.Results[2].Outcome != KilledBySelfReport {
		t.Fatalf("self-report group must fail: %+v", rep)
	}
	for _, r := range rep.Results[:2] {
		if r.Outcome != Survived || r.Accepted != "" {
			t.Fatalf("self-report group masked a survivor: %+v", r)
		}
	}
}
