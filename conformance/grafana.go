package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Grafana reads alert rule state from a Grafana over HTTP. It is used only by
// the tier-3 check (alert_test.go, make alerts), against a throwaway Grafana
// with anonymous admin access, so it sends no credentials.
type Grafana struct {
	URL  string // SUBPOENA_GRAFANA_URL
	HTTP *http.Client
}

// RuleState is one alert rule as Grafana's scheduler last evaluated it.
type RuleState struct {
	Name string `json:"name"`
	// State is "inactive", "pending" or "firing" (lowercase, Prometheus-style).
	State string `json:"state"`
	// Health is "ok", "nodata" or "error".
	Health         string    `json:"health"`
	LastError      string    `json:"lastError"`
	LastEvaluation time.Time `json:"lastEvaluation"`
}

func (s RuleState) String() string {
	r := fmt.Sprintf("%s=%s/%s at %s", s.Name, s.State, s.Health, s.LastEvaluation.Format(time.RFC3339))
	if s.LastError != "" {
		r += " error: " + s.LastError
	}
	return r
}

// Rules returns every Grafana-managed rule's state, keyed by title.
func (g *Grafana) Rules(ctx context.Context) (map[string]RuleState, error) {
	var body struct {
		Data struct {
			Groups []struct {
				Rules []RuleState `json:"rules"`
			} `json:"groups"`
		} `json:"data"`
	}
	if err := g.get(ctx, "/api/prometheus/grafana/api/v1/rules", &body); err != nil {
		return nil, err
	}
	out := map[string]RuleState{}
	for _, gr := range body.Data.Groups {
		for _, r := range gr.Rules {
			out[r.Name] = r
		}
	}
	return out, nil
}

// Provisioned reports whether a rule with this UID was loaded.
func (g *Grafana) Provisioned(ctx context.Context, uid string) error {
	var r struct {
		UID string `json:"uid"`
	}
	if err := g.get(ctx, "/api/v1/provisioning/alert-rules/"+uid, &r); err != nil {
		return err
	}
	if r.UID != uid {
		return fmt.Errorf("conformance: rule %s not provisioned", uid)
	}
	return nil
}

// WaitReady polls /api/health until Grafana answers 200.
func (g *Grafana) WaitReady(ctx context.Context) error {
	for {
		var h struct {
			Database string `json:"database"`
		}
		err := g.get(ctx, "/api/health", &h)
		if err == nil && h.Database == "ok" {
			return nil
		}
		if err := sleep(ctx, time.Second); err != nil {
			return fmt.Errorf("conformance: Grafana not ready at %s: %w", g.URL, err)
		}
	}
}

// WaitEvaluated polls until every named rule has been evaluated after since,
// then returns their states from that evaluation.
func (g *Grafana) WaitEvaluated(ctx context.Context, since time.Time, names ...string) (map[string]RuleState, error) {
	for {
		rs, err := g.Rules(ctx)
		if err == nil {
			done := true
			for _, n := range names {
				if r, ok := rs[n]; !ok || !r.LastEvaluation.After(since) {
					done = false
				}
			}
			if done {
				return rs, nil
			}
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return rs, fmt.Errorf("conformance: rules %v not evaluated after %s: %w", names, since.Format(time.RFC3339), err)
		}
	}
}

func (g *Grafana) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.URL, "/")+path, nil)
	if err != nil {
		return err
	}
	h := g.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, v)
}
