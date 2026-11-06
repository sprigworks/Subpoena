//subpoena:spec_derived
//subpoena:pure_logic

// A witness file must name the capture a claim needs (docs/ports.md W4), and a
// broadcast or multicast send may have reached the peer (W8). These run on real
// file lines through ReadLog, as a claim over a witness file does.
package harness

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

const (
	captureTrace = "c0de00000000000000000000000000a1"
	fileStop     = `{"time":"2026-11-06T12:00:09Z","record":"stop","healthy":true}`
)

// fileWith reads a healthy, empty witness file whose start record has rest.
func fileWith(t *testing.T, rest string, lines ...string) *witness.Log {
	t.Helper()
	all := append([]string{`{"time":"2026-11-06T12:00:00Z","record":"start","healthy":false` + rest + `}`}, lines...)
	l, err := witness.ReadLog(strings.NewReader(strings.Join(append(all, fileStop), "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Health(); err != nil {
		t.Fatalf("the file must be healthy, so only the capture can decide: %v", err)
	}
	return l
}

const (
	noCaptures    = ``
	execOnly      = `,"captures":["exec"]`
	deliveryToo   = `,"captures":["exec","delivery"]`
	rowOnly       = `,"captures":["row"]`
	fileOnly      = `,"roots":["/r"],"captures":["file"]`
	rootsButNoCap = `,"roots":["/r"]`
	rootsButExec  = `,"roots":["/r"],"captures":["exec"]`
)

func TestEveryAbsenceClaimNeedsItsCapture(t *testing.T) {
	cleanDB := fakeDB{change: witness.SQLiteChange{Verdict: witness.SQLiteNoChange, Exact: true, Schema: []string{"users"}}}
	claims := []struct {
		name   string
		claim  func(l *witness.Log) (Verdict, error)
		passes []string
		not    []string
	}{
		{"NoSpawn", func(l *witness.Log) (Verdict, error) { return NoSpawn(l, captureTrace) },
			[]string{execOnly, deliveryToo}, []string{noCaptures, fileOnly, rowOnly}},
		{"NoRow", func(l *witness.Log) (Verdict, error) { return NoRow(l, captureTrace, "users") },
			[]string{rowOnly}, []string{noCaptures, execOnly, deliveryToo, fileOnly}},
		{"NoWrite", func(l *witness.Log) (Verdict, error) { return NoWrite(l, captureTrace, "/r/x") },
			[]string{fileOnly}, []string{rootsButNoCap, rootsButExec, rowOnly}},
		{"NoWrite of anything", func(l *witness.Log) (Verdict, error) { return NoWrite(l, captureTrace) },
			[]string{fileOnly}, []string{rootsButNoCap, rootsButExec}},
		{"NoCommit", func(l *witness.Log) (Verdict, error) { return NoCommit(l, cleanDB, captureTrace, "users") },
			[]string{fileOnly}, []string{rootsButNoCap, rootsButExec}},
		{"NoDelivery", func(l *witness.Log) (Verdict, error) { return NoDelivery(l, captureTrace, nil) },
			[]string{deliveryToo}, []string{noCaptures, execOnly, fileOnly, rowOnly}},
	}
	for _, c := range claims {
		t.Run(c.name, func(t *testing.T) {
			for _, rest := range c.passes {
				if v, err := c.claim(fileWith(t, rest)); v != Pass {
					t.Errorf("start record %q: %v (%v), want Pass", rest, v, err)
				}
			}
			for _, rest := range c.not {
				v, err := c.claim(fileWith(t, rest))
				if v != Inconclusive || err == nil || !strings.Contains(err.Error(), "capture") {
					t.Errorf("start record %q: %v (%v), want Inconclusive naming the capture", rest, v, err)
				}
			}
		})
	}
}

// What a file saw is evidence whichever captures it names.
func TestASightingStillFailsWithNoCaptureNamed(t *testing.T) {
	exec := `{"time":"2026-11-06T12:00:01Z","pid":7,"comm":"sh","trace_id":"` + captureTrace + `"}`
	if v, err := NoSpawn(fileWith(t, noCaptures, exec), captureTrace); v != Fail {
		t.Errorf("NoSpawn: %v (%v)", v, err)
	}
	write := `{"time":"2026-11-06T12:00:01Z","file_op":"write","path":"/r/x","root":"/r","source":"inotify","attribution":"root"}`
	if v, err := NoWrite(fileWith(t, rootsButNoCap, write), captureTrace, "/r/x"); v != Fail {
		t.Errorf("NoWrite: %v (%v)", v, err)
	}
	row := `{"time":"2026-11-06T12:00:01Z","event":"row","verb":"INSERT","tables":["users"],"rows":1,"outcome":"committed","attribution":"destination"}`
	if v, err := NoRow(fileWith(t, noCaptures, row), captureTrace, "users"); v != Fail {
		t.Errorf("NoRow: %v (%v)", v, err)
	}
}

func TestWatchChecksNeedTheirCapture(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(tb testing.TB) bool
		want  bool
	}{
		{"spawns, exec", func(tb testing.TB) bool { return checkSpawns(tb, fileWith(t, execOnly), captureTrace, SpawnRule{}) }, true},
		{"spawns, file", func(tb testing.TB) bool { return checkSpawns(tb, fileWith(t, fileOnly), captureTrace, SpawnRule{}) }, false},
		{"writes, file", func(tb testing.TB) bool {
			return checkWrites(tb, fileWith(t, fileOnly), captureTrace, WriteRule{Never: []string{"/r/x"}})
		}, true},
		{"writes, exec", func(tb testing.TB) bool {
			return checkWrites(tb, fileWith(t, rootsButExec), captureTrace, WriteRule{Never: []string{"/r/x"}})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &cleanupTB{}
			if got := tc.check(f); got != tc.want {
				t.Fatalf("check = %v, want %v", got, tc.want)
			}
			if !tc.want && (len(f.errs) != 1 || !strings.HasPrefix(f.errs[0], TagInconclusive) || !strings.Contains(f.errs[0], "capture")) {
				t.Fatalf("errors = %q, want one Inconclusive naming the capture", f.errs)
			}
			if tc.want && len(f.errs) != 0 {
				t.Fatalf("errors = %q", f.errs)
			}
		})
	}
}

// fanoutLine is a send from the trace to peer, with SO_BROADCAST set or not.
func fanoutLine(peer string, broadcast bool) string {
	b := ""
	if broadcast {
		b = `,"broadcast":true`
	}
	return `{"time":"2026-11-06T12:00:01Z","delivery_op":"sendmsg","pid":7,"comm":"app","protocol":"udp","peer":"` + peer + `"` + b +
		`,"trace_id":"` + captureTrace + `","attribution":"cgroup"}`
}

func TestAFanoutSendMayHaveReachedThePeer(t *testing.T) {
	sub := netip.MustParseAddrPort("172.17.0.3:41912")
	for _, tc := range []struct {
		name      string
		peer      string
		broadcast bool
		rule      netip.AddrPort
		want      Verdict
	}{
		{"subnet broadcast, the subscriber's port", "172.17.255.255:41912", true, sub, Inconclusive},
		{"limited broadcast", "255.255.255.255:41912", false, sub, Inconclusive},
		{"multicast", "239.7.7.7:41912", false, sub, Inconclusive},
		{"IPv6 multicast", "[ff02::1]:41912", false, sub, Inconclusive},
		{"mapped multicast", "[::ffff:239.7.7.7]:41912", false, sub, Inconclusive},
		{"another port", "239.7.7.7:41999", false, sub, Pass},
		{"broadcast on another port", "172.17.255.255:41999", true, sub, Pass},
		{"a rule with no port", "239.7.7.7:41999", false, netip.AddrPortFrom(sub.Addr(), 0), Inconclusive},
		{"a peer with no port", "239.7.7.7:0", false, sub, Inconclusive},
		{"could be a subnet's, SO_BROADCAST set", "172.17.0.11:41912", true, sub, Inconclusive},
		{"could be a subnet's, no option", "172.17.0.11:41912", false, sub, Pass},
		{"cannot be a subnet's, SO_BROADCAST set", "172.17.0.9:41912", true, sub, Pass},
		{"last bits 10, SO_BROADCAST set", "172.17.0.10:41912", true, sub, Pass},
		{"IPv6 has no broadcast", "[fd00::b]:41912", true, sub, Pass},
		{"a host, no option", "172.17.0.9:41912", false, sub, Pass},
		{"the group itself", "239.7.7.7:41912", false, netip.MustParseAddrPort("239.7.7.7:41912"), Fail},
		{"the subscriber itself, SO_BROADCAST set", "172.17.0.3:41912", true, sub, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := fileWith(t, deliveryToo, fanoutLine(tc.peer, tc.broadcast))
			v, err := NoDelivery(l, captureTrace, DeliveryTo(tc.rule))
			if v != tc.want {
				t.Fatalf("NoDelivery = %v (%v), want %v", v, err, tc.want)
			}
			if tc.want == Inconclusive && !strings.Contains(err.Error(), "may have reached") {
				t.Fatalf("message: %v", err)
			}
			f := &cleanupTB{}
			if got := checkDeliveries(f, l, captureTrace, DeliveryRule{Never: []netip.AddrPort{tc.rule}}); got != (tc.want == Pass) {
				t.Fatalf("Never: check = %v (%q), want %v", got, f.errs, tc.want == Pass)
			}
			if tc.want == Inconclusive && !strings.Contains(strings.Join(f.errs, " "), TagInconclusive) {
				t.Fatalf("Never must be Inconclusive, not witness evidence: %q", f.errs)
			}
		})
	}
}

// A claim about every send has no peer to be unsure of.
func TestAFanoutSendIsASendToAnAnyPeerClaim(t *testing.T) {
	l := fileWith(t, deliveryToo, fanoutLine("239.7.7.7:41912", false))
	if v, err := NoDelivery(l, captureTrace, nil); v != Fail {
		t.Fatalf("NoDelivery = %v (%v), want Fail", v, err)
	}
}

// A match of the caller's own sees only Peer, as the docs say.
func TestAFanoutSendAndAMatchOfYourOwn(t *testing.T) {
	l := fileWith(t, deliveryToo, fanoutLine("239.7.7.7:41912", false))
	sub := netip.MustParseAddrPort("172.17.0.3:41912")
	own := func(e witness.DeliveryEvent) bool { return e.Peer == sub }
	if v, err := NoDelivery(l, captureTrace, own); v != Pass {
		t.Fatalf("NoDelivery = %v (%v), want Pass", v, err)
	}
}
