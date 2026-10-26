package harness

import "testing"

// Verdict is the three-valued outcome of an assertion about the captured
// telemetry. Absence ("nothing happened") is only meaningful if the capture is
// complete; an incomplete capture yields Inconclusive, never Pass.
type Verdict int

const (
	// Pass means the claim holds.
	Pass Verdict = iota
	// Fail means the claim is contradicted by captured spans.
	Fail
	// Inconclusive means the capture was incomplete and cannot support the claim.
	Inconclusive
)

func (v Verdict) String() string {
	switch v {
	case Pass:
		return "Pass"
	case Fail:
		return "Fail"
	case Inconclusive:
		return "Inconclusive"
	}
	return "Unknown"
}

// Absent asserts that q matches no trace. A match is a definitive Fail even
// from an incomplete capture; zero matches is Pass only if the capture is
// complete, otherwise Inconclusive. The error is non-nil only if q cannot be
// evaluated (see Trace.Query).
func (t *Trace) Absent(q string) (Verdict, error) {
	r, err := t.Query(q)
	if err != nil {
		return Fail, err
	}
	switch {
	case r.Count() > 0:
		return Fail, nil
	case !t.complete:
		return Inconclusive, nil
	}
	return Pass, nil
}

// Exists asserts that q matches at least one trace. A match is a definitive
// Pass; no match from an incomplete capture is Inconclusive.
func (t *Trace) Exists(q string) (Verdict, error) {
	r, err := t.Query(q)
	if err != nil {
		return Fail, err
	}
	switch {
	case r.Count() > 0:
		return Pass, nil
	case !t.complete:
		return Inconclusive, nil
	}
	return Fail, nil
}

// Options tune the Require helpers.
type Options struct {
	// AllowInconclusive downgrades Inconclusive from a failure to a skip-like
	// log line. Off by default: an unproven claim is not a passing test.
	AllowInconclusive bool
}

// RequireAbsent fails the test unless q matches no trace in a complete capture.
func RequireAbsent(tb testing.TB, t *Trace, q string, opts ...Options) {
	tb.Helper()
	v, err := t.Absent(q)
	report(tb, "absent", q, v, err, opts)
}

// RequireExists fails the test unless q matches at least one trace.
func RequireExists(tb testing.TB, t *Trace, q string, opts ...Options) {
	tb.Helper()
	v, err := t.Exists(q)
	report(tb, "exists", q, v, err, opts)
}

func report(tb testing.TB, kind, q string, v Verdict, err error, opts []Options) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("%s %s: cannot evaluate: %v", kind, q, err)
	}
	switch v {
	case Pass:
	case Inconclusive:
		if len(opts) > 0 && opts[0].AllowInconclusive {
			tb.Logf("%s %s: inconclusive (capture incomplete), allowed by options", kind, q)
			return
		}
		tb.Fatalf("%s %s: INCONCLUSIVE: capture incomplete, absence is not proven", kind, q)
	default:
		tb.Fatalf("%s %s: %s", kind, q, v)
	}
}
