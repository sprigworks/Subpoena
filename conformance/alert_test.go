//subpoena:impl_derived

// Tier 3: the alert rules in examples/gateway/alerts, provisioned into a real
// Grafana with a real Tempo behind it, driven through Grafana's own scheduler
// (no ad hoc evaluation), from silence to clean traffic to a violation.
package conformance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	alertRulesPath = "../examples/gateway/alerts/no_exec_after_deny.yaml"
	invariantUID   = "subpoena-no-exec-after-deny"
	livenessUID    = "subpoena-authorize-telemetry-missing"
)

// ruleTitles reads the rule file and returns uid -> title, the key Grafana's
// state API uses.
func ruleTitles(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(alertRulesPath)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups []struct {
			Rules []struct {
				UID   string `yaml:"uid"`
				Title string `yaml:"title"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			out[r.UID] = r.Title
		}
	}
	for _, uid := range []string{invariantUID, livenessUID} {
		if out[uid] == "" {
			t.Fatalf("%s: no rule %s", alertRulesPath, uid)
		}
	}
	return out
}

// TestAlertRulesFireOnlyOnViolation runs only when SUBPOENA_ALERTS_REQUIRE=1
// (make alerts) or SUBPOENA_GRAFANA_URL is set; it pushes fixture spans into
// the Tempo behind that Grafana.
func TestAlertRulesFireOnlyOnViolation(t *testing.T) {
	require := os.Getenv("SUBPOENA_ALERTS_REQUIRE") == "1"
	gURL := os.Getenv("SUBPOENA_GRAFANA_URL")
	if !require && gURL == "" {
		t.Skip("tier-3 alert check is opt-in: run `make alerts`")
	}
	if gURL == "" {
		t.Fatal("SUBPOENA_ALERTS_REQUIRE=1 but SUBPOENA_GRAFANA_URL is not set")
	}
	titles := ruleTitles(t)
	inv, live := titles[invariantUID], titles[livenessUID]

	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	tempo := ClientFromEnv()
	g := &Grafana{URL: gURL, HTTP: tempo.HTTP}
	if err := g.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tempo.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{invariantUID, livenessUID} {
		if err := g.Provisioned(ctx, uid); err != nil {
			t.Fatalf("the rule file did not provision: %v", err)
		}
	}

	// A broken query must never look like a verdict either way.
	noError := func(rs map[string]RuleState) {
		t.Helper()
		for _, n := range []string{inv, live} {
			if rs[n].Health == "error" {
				t.Fatalf("rule evaluation failed: %s", rs[n])
			}
		}
	}

	// 1. Silence: no spans at all. The invariant is quiet (nothing violates);
	// the liveness rule is not (nothing arrives).
	rs, err := g.WaitEvaluated(ctx, time.Now(), inv, live)
	if err != nil {
		t.Fatal(err)
	}
	noError(rs)
	if rs[inv].State != "inactive" {
		t.Fatalf("with no spans the invariant should be quiet: %s", rs[inv])
	}
	if s := rs[live].State; s != "pending" && s != "firing" {
		t.Fatalf("with no spans the liveness rule should alert: %s", rs[live])
	}
	t.Logf("silence: %s; %s", rs[inv], rs[live])

	// 2. Clean traffic: a denied session that never execs and an allowed one
	// that does. Wait until the liveness rule has seen the spans, and the
	// invariant has been evaluated no earlier than that (the two rules'
	// evaluations are not simultaneous), and require the invariant to be quiet.
	push(ctx, t, tempo, "deny_without_exec.json", "allow_then_exec.json")
	rs = waitFor(ctx, t, g, noError, func(rs map[string]RuleState) bool {
		return rs[live].State == "inactive" && rs[live].Health == "ok" &&
			!rs[inv].LastEvaluation.Before(rs[live].LastEvaluation)
	})
	if rs[inv].State != "inactive" {
		t.Fatalf("clean traffic made the invariant fire: %s", rs[inv])
	}
	t.Logf("clean: %s; %s", rs[inv], rs[live])

	// 3. One violating trace: a denied authorize followed by an exec.
	push(ctx, t, tempo, "deny_then_exec_violation.json")
	rs = waitFor(ctx, t, g, noError, func(rs map[string]RuleState) bool { return rs[inv].State == "firing" })
	t.Logf("violation: %s; %s", rs[inv], rs[live])
}

func push(ctx context.Context, t *testing.T, c *Client, names ...string) {
	t.Helper()
	for _, n := range names {
		f, err := LoadFixture(filepath.Join(fixturesDir, n))
		if err != nil {
			t.Fatal(err)
		}
		e, err := f.Rebased(time.Now().UnixNano())
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Push(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
}

// waitFor polls rule state until ok holds or the context ends, running check
// (which fails the test) on every state it sees. Tempo serves metrics only for
// spans older than its query_end_cutoff (30s), and the group evaluates once a
// minute, so a change shows up within about 90s.
func waitFor(ctx context.Context, t *testing.T, g *Grafana, check func(map[string]RuleState), ok func(map[string]RuleState) bool) map[string]RuleState {
	t.Helper()
	var last map[string]RuleState
	for {
		rs, err := g.Rules(ctx)
		if err == nil {
			last = rs
			check(rs)
			if ok(rs) {
				return rs
			}
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			t.Fatalf("rule state never reached the expected value: %v (last: %v)", err, last)
		}
	}
}
