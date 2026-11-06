package harness

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// NoDelivery checks the independent delivery witness after its observation
// window has ended. match selects the sends the claim is about (nil: any send,
// which on a broker includes its acks to the publisher; DeliveryTo names a
// peer). One matching send contradicts absence even if capture was unhealthy.
// With none, missing or bad health makes the claim Inconclusive, and so does a
// witness file with no delivery capture in it.
//
//subpoena:enforcement_point
func NoDelivery(w witness.DeliveryWitness, traceID string, match func(witness.DeliveryEvent) bool) (Verdict, error) {
	var hits []witness.DeliveryEvent
	for _, e := range w.Delivered(traceID) {
		if match == nil || match(e) {
			hits = append(hits, e)
		}
	}
	if len(hits) != 0 {
		return Fail, fmt.Errorf("witness saw sends for %s: %+v", traceID, hits) //subpoena:enforcement
	}
	if err := deliveryCapture(w); err != nil {
		return Inconclusive, err //subpoena:enforcement
	}
	return Pass, nil
}

// deliveryCapture is why absence of a send cannot rest on w, or nil: a witness
// file that says no delivery hook ran, or missing or bad capture health.
//
//subpoena:enforcement_point
func deliveryCapture(w witness.DeliveryWitness) error {
	if c, ok := w.(interface{ CapturedDeliveries() bool }); ok && !c.CapturedDeliveries() {
		return errors.New("the witness file's start record names no delivery capture, so a send could not have been seen (run subpoena-witness with -deliveries)") //subpoena:enforcement
	}
	return captureHealth(w)
}

// RequireNoDelivery fails the test unless a healthy witness reports no matching
// send.
func RequireNoDelivery(tb testing.TB, w witness.DeliveryWitness, traceID string, match func(witness.DeliveryEvent) bool) {
	tb.Helper()
	v, err := NoDelivery(w, traceID, match)
	if v != Pass {
		tb.Fatalf("%s", noDeliveryMessage(tb, traceID, v, err))
	}
}

// DeliveryTo matches sends that may have gone to any of the given peers. A peer
// is the far end of the connection as the sender sees it: for a subscriber, the
// address and port of its own socket (conn.LocalAddr() in the subscriber), not
// the broker's listener. A zero port matches every port of the address, and a
// zero or unspecified address matches the port on any address.
//
// A send whose peer the witness could not read matches, because it may have
// gone there. With no peers given it matches every send: a rule that names no
// one must not pass for lack of a name.
func DeliveryTo(peers ...netip.AddrPort) func(witness.DeliveryEvent) bool {
	return func(e witness.DeliveryEvent) bool {
		return len(peers) == 0 || slices.ContainsFunc(peers, func(p netip.AddrPort) bool { return mayBePeer(e, p) })
	}
}

// mayBePeer reports whether e may have gone to rule: it did, or the witness
// cannot say it did not. The kernel reports no zone, so a rule's zone (which a
// link-local conn.LocalAddr() has) cannot tell a peer apart and is left out.
func mayBePeer(e witness.DeliveryEvent, rule netip.AddrPort) bool {
	if e.PeerUnknown() {
		return true
	}
	return addrFits(e.Peer.Addr().WithZone(""), rule.Addr().WithZone("")) && (rule.Port() == 0 || e.Peer.Port() == 0 || e.Peer.Port() == rule.Port())
}

// isPeer reports whether e is known to have gone to rule. A rule with a zone is
// not: the event does not say which link the send took.
func isPeer(e witness.DeliveryEvent, rule netip.AddrPort) bool {
	if e.PeerUnknown() {
		return false
	}
	return addrFits(e.Peer.Addr(), rule.Addr()) && (rule.Port() == 0 || e.Peer.Port() == rule.Port())
}

func addrFits(peer, rule netip.Addr) bool {
	a := rule.Unmap()
	return !a.IsValid() || a.IsUnspecified() || peer.Unmap() == a
}

// DeliveryRule says which peers a WatchDeliveries check accepts. Entries are
// peers as DeliveryTo takes them, and the two lists match differently, each in
// the direction that fails closed: Never also fires on a send whose peer is
// unknown or partly known, and Allowed excuses only a send known to have gone to
// the entry. A rule must name someone: nil Allowed and an empty Never fail the
// check, since they claim nothing.
type DeliveryRule struct {
	// Allowed lists the peers the code may send to. Nil allows any peer not in
	// Never; an empty, non-nil slice allows none.
	Allowed []netip.AddrPort
	// Never lists peers nothing may be sent to, whatever Allowed says.
	Never []netip.AddrPort
}

// WatchDeliveries registers a witness check that runs when the test ends, even
// after an earlier Fatal, as WatchSpawns does for processes. Call it right after
// the witness starts.
//
// At cleanup it stops w (if w has a Stop method), then fails the test, with
// messages tagged "witness:", for every send seen for traceID that the rule
// refuses, and with "inconclusive:" for missing or bad capture health. If the
// test has already failed, every send the witness saw is logged as well.
func WatchDeliveries(tb testing.TB, w witness.DeliveryWitness, traceID string, rule DeliveryRule) {
	tb.Helper()
	tb.Cleanup(func() { checkDeliveries(tb, w, traceID, rule) })
}

// checkDeliveries is WatchDeliveries' cleanup. It reports whether the check
// passed.
//
//subpoena:enforcement_point
func checkDeliveries(tb testing.TB, w witness.DeliveryWitness, traceID string, rule DeliveryRule) bool {
	failedBefore := tb.Failed()
	stopWitness(w)
	ok := true
	if rule.Allowed == nil && len(rule.Never) == 0 {
		tb.Errorf("%s: %s: the delivery rule names no peer, so it claims nothing", TagInconclusive, traceID) //subpoena:enforcement
		ok = false
	}
	for _, e := range w.Delivered(traceID) {
		switch {
		case slices.ContainsFunc(rule.Never, func(p netip.AddrPort) bool { return mayBePeer(e, p) }):
			WitnessErrorf(tb, "send to a refused peer for %s: pid %d %q %s %s to %v, %d bytes (%s)", traceID, e.PID, e.Comm, e.Protocol, e.Op, e.Peer, e.Bytes, e.Attribution) //subpoena:enforcement
			ok = false
		case rule.Allowed != nil && !slices.ContainsFunc(rule.Allowed, func(p netip.AddrPort) bool { return isPeer(e, p) }):
			WitnessErrorf(tb, "send to a peer not allowed for %s: pid %d %q %s %s to %v, %d bytes (%s)", traceID, e.PID, e.Comm, e.Protocol, e.Op, e.Peer, e.Bytes, e.Attribution) //subpoena:enforcement
			ok = false
		case failedBefore:
			tb.Logf("%s: after an earlier failure, saw pid %d %q send to %v, %d bytes (%s)", TagWitness, e.PID, e.Comm, e.Peer, e.Bytes, e.Attribution)
		}
	}
	if c, has := w.(interface {
		DeliveryCoverage() witness.DeliveryCoverage
	}); has {
		if n := c.DeliveryCoverage().OtherFamilySends; n != 0 {
			tb.Logf("%s: %s: %d send(s) on sockets that are not inet (AF_UNIX, netlink, ...) were not reported", TagWitness, traceID, n)
		}
	}
	if err := deliveryCapture(w); err != nil {
		tb.Errorf("%s: %s: capture unhealthy, absence of refused sends is not proven: %v", TagInconclusive, traceID, err) //subpoena:enforcement
		return false
	}
	return ok
}
