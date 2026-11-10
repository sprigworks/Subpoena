//subpoena:impl_derived
//subpoena:pure_logic

package harness

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

type unknownDelivery struct{ events []witness.DeliveryEvent }

func (w unknownDelivery) Delivered(string) []witness.DeliveryEvent { return w.events }

type healthDelivery struct {
	unknownDelivery
	err error
}

func (w healthDelivery) Health() error { return w.err }

// stoppableDelivery reports what it saw only for the window Stop closed.
type stoppableDelivery struct {
	healthDelivery
	stopped *bool
	cover   witness.DeliveryCoverage
}

func (w stoppableDelivery) Stop() { *w.stopped = true }
func (w stoppableDelivery) Delivered(string) []witness.DeliveryEvent {
	if !*w.stopped {
		return nil
	}
	return w.events
}
func (w stoppableDelivery) DeliveryCoverage() witness.DeliveryCoverage { return w.cover }

var (
	subscriber = netip.MustParseAddrPort("127.0.0.1:40001")
	publisher  = netip.MustParseAddrPort("127.0.0.1:40002")
)

func sent(peers ...netip.AddrPort) unknownDelivery {
	var w unknownDelivery
	for _, p := range peers {
		w.events = append(w.events, witness.DeliveryEvent{PID: 42, Comm: "broker", Op: witness.OpDeliver, Protocol: "tcp", Peer: p, Bytes: 9, Attribution: witness.ByCgroup})
	}
	return w
}

func TestNoDeliveryNeedsHealthyCapture(t *testing.T) {
	gap := errors.New("observation lost")
	for _, tc := range []struct {
		name  string
		w     witness.DeliveryWitness
		match func(witness.DeliveryEvent) bool
		want  Verdict
	}{
		{"healthy empty", healthDelivery{}, nil, Pass},
		{"unhealthy empty", healthDelivery{err: gap}, nil, Inconclusive},
		{"unknown health, empty", unknownDelivery{}, nil, Inconclusive},
		{"healthy observed", healthDelivery{unknownDelivery: sent(subscriber)}, nil, Fail},
		{"unhealthy observed", healthDelivery{sent(subscriber), gap}, nil, Fail},
		{"an ack to the publisher is not the subscriber", healthDelivery{unknownDelivery: sent(publisher)}, DeliveryTo(subscriber), Pass},
		{"not matched, unhealthy", healthDelivery{sent(publisher), gap}, DeliveryTo(subscriber), Inconclusive},
		{"matched", healthDelivery{unknownDelivery: sent(publisher, subscriber)}, DeliveryTo(subscriber), Fail},
		{"matched, unhealthy", healthDelivery{sent(subscriber), gap}, DeliveryTo(subscriber), Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NoDelivery(tc.w, "trace", tc.match)
			if got != tc.want || (err == nil) != (got == Pass) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			fatal, _ := runRequire(func(tb testing.TB) { RequireNoDelivery(tb, tc.w, "trace", tc.match) })
			if (fatal == "") != (got == Pass) {
				t.Fatalf("RequireNoDelivery fatal = %q for %v", fatal, got)
			}
			tb := &cleanupTB{}
			if CheckNoDelivery(tb, tc.w, "trace", tc.match) != (got == Pass) || tb.failed == (got == Pass) {
				t.Fatalf("CheckNoDelivery failed=%v for %v", tb.failed, got)
			}
		})
	}
}

// noCapture is a witness file that says no delivery hook ran.
type noCapture struct {
	healthDelivery
	captured bool
}

func (w noCapture) CapturedDeliveries() bool { return w.captured }

// An empty, healthy file proves nothing about sends if nothing watched for them.
func TestNoDeliveryNeedsTheCaptureToHaveRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		w    witness.DeliveryWitness
		want Verdict
	}{
		{"no capture", noCapture{}, Inconclusive},
		{"capture", noCapture{captured: true}, Pass},
		{"a sighting stands without one", noCapture{healthDelivery: healthDelivery{unknownDelivery: sent(subscriber)}}, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := NoDelivery(tc.w, "trace", nil); got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	tb := &cleanupTB{}
	if checkDeliveries(tb, noCapture{}, "trace", DeliveryRule{Never: []netip.AddrPort{subscriber}}) {
		t.Fatal("WatchDeliveries passed a file with no capture")
	}
	if len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], TagInconclusive) {
		t.Fatalf("errs = %q", tb.errs)
	}
}

// The real reader: a file from subpoena-witness run without -deliveries.
func TestNoDeliveryOverAFileWithNoCapture(t *testing.T) {
	const (
		start = `{"time":"2026-11-06T12:00:00Z","record":"start","healthy":false%s}` + "\n"
		stop  = `{"time":"2026-11-06T12:00:09Z","record":"stop","healthy":true}` + "\n"
	)
	for _, tc := range []struct {
		captures string
		want     Verdict
	}{
		{"", Inconclusive},
		{`,"captures":["exec"]`, Inconclusive},
		{`,"captures":["exec","delivery"]`, Pass},
	} {
		l, err := witness.ReadLog(strings.NewReader(fmt.Sprintf(start, tc.captures) + stop))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := NoDelivery(l, "trace", nil); got != tc.want {
			t.Errorf("%q: got %v, %v; want %v", tc.captures, got, err, tc.want)
		}
	}
}

// A subscriber's conn.LocalAddr() on a link-local address carries a zone, and the
// kernel's peer never does.
func TestALinkLocalRuleWithAZone(t *testing.T) {
	peer := netip.MustParseAddrPort("[fe80::1]:40001")
	zoned := netip.MustParseAddrPort("[fe80::1%eth0]:40001")
	if !DeliveryTo(zoned)(witness.DeliveryEvent{Peer: peer}) {
		t.Fatal("DeliveryTo with a zone missed the peer")
	}
	if v, _ := NoDelivery(healthDelivery{unknownDelivery: sent(peer)}, "trace", DeliveryTo(zoned)); v != Fail {
		t.Fatalf("verdict = %v, want Fail", v)
	}
	never := &cleanupTB{}
	if checkDeliveries(never, healthDelivery{unknownDelivery: sent(peer)}, "trace", DeliveryRule{Never: []netip.AddrPort{zoned}}) {
		t.Fatal("Never with a zone excused the peer")
	}
	// Allowed excuses only what is known: the event does not say which link.
	allowed := &cleanupTB{}
	if checkDeliveries(allowed, healthDelivery{unknownDelivery: sent(peer)}, "trace", DeliveryRule{Allowed: []netip.AddrPort{zoned}}) {
		t.Fatal("Allowed with a zone excused a peer on a link the event does not name")
	}
}

func TestNoDeliveryMessagesAreTagged(t *testing.T) {
	for _, tc := range []struct {
		w   witness.DeliveryWitness
		tag string
	}{
		{healthDelivery{unknownDelivery: sent(subscriber)}, TagWitness},
		{healthDelivery{err: errors.New("gap")}, TagInconclusive},
	} {
		tb := &cleanupTB{}
		tb.run(func(tb testing.TB) { RequireNoDelivery(tb, tc.w, "trace", nil) })
		if len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], tc.tag+": no delivery") {
			t.Fatalf("want %s, got %q", tc.tag, tb.errs)
		}
	}
}

func TestDeliveryTo(t *testing.T) {
	mapped := netip.AddrPortFrom(netip.AddrFrom16(subscriber.Addr().As16()), subscriber.Port())
	anyPort := netip.AddrPortFrom(subscriber.Addr(), 0)
	portOnly := netip.AddrPortFrom(netip.Addr{}, subscriber.Port())
	wildcard := netip.AddrPortFrom(netip.IPv4Unspecified(), subscriber.Port())
	portless := netip.AddrPortFrom(subscriber.Addr(), 0)
	otherHost := netip.MustParseAddrPort("192.0.2.8:40001")
	for _, tc := range []struct {
		name string
		rule []netip.AddrPort
		peer netip.AddrPort
		want bool
	}{
		{"exact", []netip.AddrPort{subscriber}, subscriber, true},
		{"another port on the host", []netip.AddrPort{subscriber}, publisher, false},
		{"another host, same port", []netip.AddrPort{subscriber}, otherHost, false},
		{"any port", []netip.AddrPort{anyPort}, publisher, true},
		{"port on any address", []netip.AddrPort{portOnly}, otherHost, true},
		{"port on any address, other port", []netip.AddrPort{portOnly}, publisher, false},
		{"port on the wildcard address", []netip.AddrPort{wildcard}, otherHost, true},
		{"mapped peer", []netip.AddrPort{subscriber}, mapped, true},
		{"mapped rule", []netip.AddrPort{mapped}, subscriber, true},
		{"second of two", []netip.AddrPort{publisher, subscriber}, subscriber, true},
		{"unknown peer may be anyone", []netip.AddrPort{subscriber}, netip.AddrPort{}, true},
		{"unspecified peer may be anyone", []netip.AddrPort{subscriber}, netip.MustParseAddrPort("0.0.0.0:0"), true},
		{"a peer with no port on the host may be it", []netip.AddrPort{subscriber}, portless, true},
		{"a peer with no port elsewhere is not", []netip.AddrPort{subscriber}, netip.AddrPortFrom(otherHost.Addr(), 0), false},
		{"no peers named matches everything", nil, publisher, true},
	} {
		if got := DeliveryTo(tc.rule...)(witness.DeliveryEvent{Peer: tc.peer}); got != tc.want {
			t.Errorf("%s: DeliveryTo(%v)(%v) = %v, want %v", tc.name, tc.rule, tc.peer, got, tc.want)
		}
	}
}

func TestWatchDeliveriesRule(t *testing.T) {
	gap := errors.New("observation lost")
	unknown := netip.AddrPort{}
	portless := netip.AddrPortFrom(subscriber.Addr(), 0)
	for _, tc := range []struct {
		name    string
		peers   []netip.AddrPort
		rule    DeliveryRule
		health  error
		witness int // messages tagged witness:
		other   int // messages tagged inconclusive:
	}{
		{name: "nothing sent", rule: DeliveryRule{Never: []netip.AddrPort{subscriber}}},
		{name: "only the publisher", peers: []netip.AddrPort{publisher}, rule: DeliveryRule{Never: []netip.AddrPort{subscriber}}},
		{name: "refused peer", peers: []netip.AddrPort{subscriber}, rule: DeliveryRule{Never: []netip.AddrPort{subscriber}}, witness: 1},
		{name: "never beats allowed", peers: []netip.AddrPort{subscriber}, rule: DeliveryRule{Allowed: []netip.AddrPort{subscriber}, Never: []netip.AddrPort{subscriber}}, witness: 1},
		{name: "allowed", peers: []netip.AddrPort{publisher}, rule: DeliveryRule{Allowed: []netip.AddrPort{publisher}}},
		{name: "not allowed", peers: []netip.AddrPort{subscriber}, rule: DeliveryRule{Allowed: []netip.AddrPort{publisher}}, witness: 1},
		{name: "empty allow list allows none", peers: []netip.AddrPort{publisher}, rule: DeliveryRule{Allowed: []netip.AddrPort{}}, witness: 1},
		{name: "unknown peer hits never", peers: []netip.AddrPort{unknown}, rule: DeliveryRule{Never: []netip.AddrPort{subscriber}}, witness: 1},
		{name: "allow list does not excuse an unknown peer", peers: []netip.AddrPort{unknown}, rule: DeliveryRule{Allowed: []netip.AddrPort{subscriber}}, witness: 1},
		{name: "allow list does not excuse a missing port", peers: []netip.AddrPort{portless}, rule: DeliveryRule{Allowed: []netip.AddrPort{subscriber}}, witness: 1},
		{name: "bad health", rule: DeliveryRule{Never: []netip.AddrPort{subscriber}}, health: gap, other: 1},
		{name: "refused and bad health", peers: []netip.AddrPort{subscriber}, rule: DeliveryRule{Never: []netip.AddrPort{subscriber}}, health: gap, witness: 1, other: 1},
		{name: "a rule naming no one claims nothing", peers: []netip.AddrPort{publisher}, other: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopped := false
			w := stoppableDelivery{healthDelivery: healthDelivery{sent(tc.peers...), tc.health}, stopped: &stopped}
			tb := &cleanupTB{}
			tb.run(func(tb testing.TB) { WatchDeliveries(tb, w, "trace", tc.rule) })
			if !stopped {
				t.Fatal("the check must end the observation window before it reads")
			}
			var witnessed, other int
			for _, e := range tb.errs {
				switch {
				case strings.HasPrefix(e, TagWitness+": "):
					witnessed++
				case strings.HasPrefix(e, TagInconclusive+": "):
					other++
				default:
					t.Errorf("untagged failure %q", e)
				}
			}
			if witnessed != tc.witness || other != tc.other {
				t.Fatalf("witness %d, inconclusive %d; want %d, %d: %q", witnessed, other, tc.witness, tc.other, tb.errs)
			}
		})
	}
}

func TestWatchDeliveriesNeedsReportedHealth(t *testing.T) {
	tb := &cleanupTB{}
	tb.run(func(tb testing.TB) {
		WatchDeliveries(tb, unknownDelivery{}, "trace", DeliveryRule{Never: []netip.AddrPort{subscriber}})
	})
	if len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], TagInconclusive+": ") {
		t.Fatalf("errs = %q", tb.errs)
	}
}

func TestWatchDeliveriesRunsAfterAnEarlierFatal(t *testing.T) {
	stopped := false
	w := stoppableDelivery{healthDelivery: healthDelivery{unknownDelivery: sent(publisher, subscriber)}, stopped: &stopped}
	tb := &cleanupTB{}
	tb.run(func(tb testing.TB) {
		WatchDeliveries(tb, w, "trace", DeliveryRule{Never: []netip.AddrPort{subscriber}})
		tb.Fatalf("test stops early")
	})
	if len(tb.errs) != 2 || !strings.Contains(tb.errs[1], subscriber.String()) {
		t.Fatalf("errs = %q", tb.errs)
	}
	if len(tb.logs) != 1 || !strings.Contains(tb.logs[0], publisher.String()) {
		t.Fatalf("every send seen must be logged after an earlier failure: %q", tb.logs)
	}
}

func TestWatchDeliveriesLogsWhatItDidNotReport(t *testing.T) {
	stopped := false
	w := stoppableDelivery{stopped: &stopped, cover: witness.DeliveryCoverage{OtherFamilySends: 3}}
	tb := &cleanupTB{}
	tb.run(func(tb testing.TB) {
		WatchDeliveries(tb, w, "trace", DeliveryRule{Never: []netip.AddrPort{subscriber}})
	})
	if len(tb.errs) != 0 || len(tb.logs) != 1 || !strings.Contains(tb.logs[0], "3 send(s)") {
		t.Fatalf("errs %q logs %q", tb.errs, tb.logs)
	}
}
