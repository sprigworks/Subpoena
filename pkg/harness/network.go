package harness

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoDial checks the independent network witness after its observation window
// has ended. match selects the attempts the claim is about (nil: any attempt);
// one matching attempt contradicts absence even if capture was unhealthy. With
// none, missing or bad health makes the claim Inconclusive.
//
//subpoena:enforcement_point
func NoDial(w witness.NetworkWitness, traceID string, match func(witness.NetworkEvent) bool) (Verdict, error) {
	var hits []witness.NetworkEvent
	for _, e := range w.Dialed(traceID) {
		if match == nil || match(e) {
			hits = append(hits, e)
		}
	}
	if len(hits) != 0 {
		return Fail, fmt.Errorf("witness saw connection attempts for %s: %+v", traceID, hits) //subpoena:enforcement
	}
	if err := captureHealth(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	return Pass, nil
}

// RequireNoDial fails the test unless a healthy witness reports no matching
// connection attempt.
func RequireNoDial(tb testing.TB, w witness.NetworkWitness, traceID string, match func(witness.NetworkEvent) bool) {
	tb.Helper()
	v, err := NoDial(w, traceID, match)
	if v != Pass {
		tb.Fatalf("%s", noDialMessage(traceID, v, err))
	}
}

// DialTo matches attempts to any of the given addresses. A zero port in an
// address matches every port.
func DialTo(addrs ...netip.AddrPort) func(witness.NetworkEvent) bool {
	return func(e witness.NetworkEvent) bool {
		for _, a := range addrs {
			if e.Dest.Addr().Unmap() == a.Addr().Unmap() && (a.Port() == 0 || a.Port() == e.Dest.Port()) {
				return true
			}
		}
		return false
	}
}
