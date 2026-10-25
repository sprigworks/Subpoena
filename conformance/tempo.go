package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

// Default endpoints of conformance/docker-compose.yml. The host ports are
// offset from Tempo's own (3200, 4318) so the conformance Tempo can run beside
// a local LGTM stack that already holds those.
const (
	DefaultTempoURL = "http://localhost:13200"
	DefaultOTLPURL  = "http://localhost:14318"
)

// Client talks to a Tempo over HTTP: OTLP/HTTP JSON in, /api/search out. It is
// the only way this repository uses Tempo.
type Client struct {
	TempoURL string // query API, SUBPOENA_TEMPO_URL
	OTLPURL  string // OTLP/HTTP receiver, SUBPOENA_OTLP_URL
	HTTP     *http.Client
}

// ClientFromEnv builds a Client from SUBPOENA_TEMPO_URL and SUBPOENA_OTLP_URL.
func ClientFromEnv() *Client {
	return &Client{
		TempoURL: envOr("SUBPOENA_TEMPO_URL", DefaultTempoURL),
		OTLPURL:  envOr("SUBPOENA_OTLP_URL", DefaultOTLPURL),
		HTTP:     &http.Client{Timeout: 15 * time.Second},
	}
}

func envOr(k, def string) string {
	if v := strings.TrimRight(os.Getenv(k), "/"); v != "" {
		return v
	}
	return def
}

// Reachable reports whether anything answers /ready, ready or not. Used to
// decide between running and skipping.
func (c *Client) Reachable(ctx context.Context) bool {
	resp, err := c.do(ctx, http.MethodGet, c.TempoURL+"/ready", "", nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// WaitReady polls /ready until Tempo answers 200. A freshly started Tempo
// reports 503 for a while (ring and ingester warm-up).
func (c *Client) WaitReady(ctx context.Context) error {
	var last string
	for {
		resp, err := c.do(ctx, http.MethodGet, c.TempoURL+"/ready", "", nil)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(b)))
		} else {
			last = err.Error()
		}
		if err := sleep(ctx, time.Second); err != nil {
			return fmt.Errorf("conformance: Tempo not ready at %s: %s: %w", c.TempoURL, last, err)
		}
	}
}

// Push sends one export to the OTLP/HTTP JSON endpoint.
func (c *Client) Push(ctx context.Context, e *Export) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, c.OTLPURL+"/v1/traces", "application/json", body)
	if err != nil {
		return fmt.Errorf("conformance: push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("conformance: push: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Search runs q through /api/search and returns the normalised trace IDs.
func (c *Client) Search(ctx context.Context, q string, from, to time.Time) ([]string, error) {
	v := url.Values{}
	v.Set("q", q)
	v.Set("start", fmt.Sprint(from.Unix()))
	v.Set("end", fmt.Sprint(to.Unix()))
	v.Set("limit", "1000")
	resp, err := c.do(ctx, http.MethodGet, c.TempoURL+"/api/search?"+v.Encode(), "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		Traces []struct {
			TraceID string `json:"traceID"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode search response: %w", err)
	}
	ids := make([]string, 0, len(out.Traces))
	for _, t := range out.Traces {
		ids = append(ids, NormID(t.TraceID))
	}
	sort.Strings(ids)
	return ids, nil
}

// WaitIndexed polls /api/search until every id is searchable. It lists all
// spans with `{ true }` and looks for the fixture's trace IDs, which depends on
// no trace-ID intrinsic. It fails with the missing IDs when ctx expires.
func (c *Client) WaitIndexed(ctx context.Context, ids []string, from, to time.Time) error {
	for {
		got, err := c.Search(ctx, "{ true }", from, to)
		have := map[string]bool{}
		for _, id := range got {
			have[id] = true
		}
		var missing []string
		for _, id := range ids {
			if !have[id] {
				missing = append(missing, id)
			}
		}
		if err == nil && len(missing) == 0 {
			return nil
		}
		if serr := sleep(ctx, 500*time.Millisecond); serr != nil {
			if err != nil {
				return fmt.Errorf("conformance: waiting for ingestion: %w (last error: %v)", serr, err)
			}
			return fmt.Errorf("conformance: not searchable in time: %s", strings.Join(missing, ", "))
		}
	}
}

func (c *Client) do(ctx context.Context, method, u, ctype string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	return h.Do(req)
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// Divergence is one query on which Tempo and pkg/traceql disagree.
type Divergence struct {
	Query      Query
	Err        string   // Tempo rejected the query, or the subset failed to parse it
	OnlyTempo  []string // "fixture/traceID" matched by Tempo but not by the subset
	OnlySubset []string // matched by the subset but not by Tempo
}

func (d Divergence) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n  %s\n", d.Query.Name, d.Query.Text)
	if d.Err != "" {
		fmt.Fprintf(&b, "  error: %s\n", d.Err)
	}
	if len(d.OnlyTempo) > 0 {
		fmt.Fprintf(&b, "  matched by Tempo only:  %s\n", strings.Join(d.OnlyTempo, ", "))
	}
	if len(d.OnlySubset) > 0 {
		fmt.Fprintf(&b, "  matched by subset only: %s\n", strings.Join(d.OnlySubset, ", "))
	}
	return b.String()
}

// Run pushes every fixture to Tempo (timestamps rebased to now), waits until
// all are searchable, then runs every query through Tempo and through
// pkg/traceql and returns the queries on which the sets of matching trace IDs
// differ. Trace IDs that are not from these fixtures (stray data in a shared
// Tempo) are ignored on the Tempo side.
func Run(ctx context.Context, c *Client, fixtures []*Fixture, queries []Query, now time.Time) ([]Divergence, error) {
	owner := map[string]string{} // trace ID -> fixture name
	var all []traceql.Trace
	var ids []string
	for _, f := range fixtures {
		trs, err := f.Traces()
		if err != nil {
			return nil, err
		}
		for _, t := range trs {
			if prev, dup := owner[t.ID]; dup {
				return nil, fmt.Errorf("conformance: trace %s is in both %s and %s", t.ID, prev, f.Name)
			}
			owner[t.ID] = f.Name
			ids = append(ids, t.ID)
		}
		all = append(all, trs...)
	}
	sort.Strings(ids)

	for i, f := range fixtures {
		e, err := f.Rebased(now.Add(-time.Minute + time.Duration(i)*time.Millisecond*10).UnixNano())
		if err != nil {
			return nil, err
		}
		if err := c.Push(ctx, e); err != nil {
			return nil, fmt.Errorf("fixture %s: %w", f.Name, err)
		}
	}
	from, to := now.Add(-15*time.Minute), now.Add(15*time.Minute)
	if err := c.WaitIndexed(ctx, ids, from, to); err != nil {
		return nil, err
	}

	label := func(id string) string { return owner[id] + "/" + id }
	var out []Divergence
	for _, q := range queries {
		p, perr := traceql.Parse(q.Text)
		if perr != nil {
			out = append(out, Divergence{Query: q, Err: "pkg/traceql cannot parse it: " + perr.Error()})
			continue
		}
		sub := map[string]bool{}
		for _, m := range p.Eval(all) {
			sub[m.TraceID] = true
		}
		got, serr := c.Search(ctx, q.Text, from, to)
		if serr != nil {
			out = append(out, Divergence{Query: q, Err: "Tempo rejected it: " + serr.Error()})
			continue
		}
		tempo := map[string]bool{}
		for _, id := range got {
			if _, ours := owner[id]; ours {
				tempo[id] = true
			}
		}
		d := Divergence{Query: q}
		for id := range tempo {
			if !sub[id] {
				d.OnlyTempo = append(d.OnlyTempo, label(id))
			}
		}
		for id := range sub {
			if !tempo[id] {
				d.OnlySubset = append(d.OnlySubset, label(id))
			}
		}
		sort.Strings(d.OnlyTempo)
		sort.Strings(d.OnlySubset)
		if len(d.OnlyTempo)+len(d.OnlySubset) > 0 {
			out = append(out, d)
		}
	}
	return out, nil
}
