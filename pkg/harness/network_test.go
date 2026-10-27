//subpoena:impl_derived
//subpoena:pure_logic

package harness

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

type unknownNet struct{ events []witness.NetworkEvent }

func (w unknownNet) Dialed(string) []witness.NetworkEvent { return w.events }

type healthNet struct {
	unknownNet
	err error
}

func (w healthNet) Health() error { return w.err }

func TestNoDialNeedsHealthyCapture(t *testing.T) {
	gap := errors.New("observation lost")
	evil := netip.MustParseAddrPort("192.0.2.7:443")
	allowed := netip.MustParseAddrPort("198.51.100.1:443")
	seen := func(d netip.AddrPort) unknownNet { return unknownNet{[]witness.NetworkEvent{{PID: 42, Dest: d}}} }
	for _, tc := range []struct {
		name  string
		w     witness.NetworkWitness
		match func(witness.NetworkEvent) bool
		want  Verdict
	}{
		{"healthy empty", healthNet{}, nil, Pass},
		{"unhealthy empty", healthNet{err: gap}, nil, Inconclusive},
		{"unknown empty", unknownNet{}, nil, Inconclusive},
		{"healthy observed", healthNet{unknownNet: seen(evil)}, nil, Fail},
		{"unhealthy observed", healthNet{seen(evil), gap}, nil, Fail},
		{"observed, not matched", healthNet{unknownNet: seen(allowed)}, DialTo(evil), Pass},
		{"observed, not matched, unhealthy", healthNet{seen(allowed), gap}, DialTo(evil), Inconclusive},
		{"matched", healthNet{unknownNet: seen(evil)}, DialTo(evil), Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NoDial(tc.w, "trace", tc.match)
			if got != tc.want || (err == nil) != (got == Pass) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			fatal, _ := runRequire(func(tb testing.TB) { RequireNoDial(tb, tc.w, "trace", tc.match) })
			if (fatal == "") != (got == Pass) {
				t.Fatalf("RequireNoDial fatal = %q for %v", fatal, got)
			}
		})
	}
}

func TestDialTo(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.7:443")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(v4.Addr().As16()), 443)
	anyPort := netip.AddrPortFrom(v4.Addr(), 0)
	for _, tc := range []struct {
		name string
		rule netip.AddrPort
		dest netip.AddrPort
		want bool
	}{
		{"exact", v4, v4, true},
		{"other port", v4, netip.AddrPortFrom(v4.Addr(), 80), false},
		{"any port", anyPort, netip.AddrPortFrom(v4.Addr(), 80), true},
		{"mapped dest", v4, mapped, true},
		{"mapped rule", mapped, v4, true},
		{"other addr", v4, netip.MustParseAddrPort("192.0.2.8:443"), false},
	} {
		if got := DialTo(tc.rule)(witness.NetworkEvent{Dest: tc.dest}); got != tc.want {
			t.Errorf("%s: DialTo(%v)(%v) = %v, want %v", tc.name, tc.rule, tc.dest, got, tc.want)
		}
	}
}
