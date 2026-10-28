// Package alerts renders Grafana provisioning from the shared contract.
package alerts

import (
	"fmt"

	"example.com/platform/contract/generated/go/semconv"
	"example.com/platform/contract/invariants"
	"gopkg.in/yaml.v3"
)

// Render produces one violation and one telemetry-liveness rule per invariant.
// Like gateway's rules, these use instant TraceQL metrics and a reduce step.
func Render() ([]byte, error) {
	var rules []any
	for _, name := range invariants.Names() {
		query, err := invariants.Load(name)
		if err != nil {
			return nil, err
		}
		rules = append(rules,
			rule(name, "violation", query, "OK", "0s", "gt", 0),
			rule(name, "missing", fmt.Sprintf(`{ name = %q }`, semconv.SpanPlatformActionAuthorize), "Alerting", "15m", "lt", 1),
		)
	}
	return yaml.Marshal(map[string]any{
		"apiVersion": 1,
		"groups":     []any{map[string]any{"orgId": 1, "name": "platform-invariants", "folder": "Platform", "interval": "1m", "rules": rules}},
	})
}

func rule(name, suffix, query, noData, duration, comparison string, threshold int) map[string]any {
	return map[string]any{
		"uid": "plt-" + name + "-" + suffix, "title": name + " " + suffix,
		"condition": "C", "for": duration, "noDataState": noData, "execErrState": "Error",
		"labels":      map[string]string{"invariant": name},
		"annotations": map[string]string{"summary": name + " " + suffix, "description": "Application spans only; independent production witness checks require a separate deployment."},
		"data": []any{
			map[string]any{"refId": "A", "relativeTimeRange": map[string]int{"from": 900, "to": 0}, "datasourceUid": "tempo", "model": map[string]any{"refId": "A", "queryType": "traceql", "metricsQueryType": "instant", "query": query + " | count_over_time()"}},
			map[string]any{"refId": "B", "relativeTimeRange": map[string]int{"from": 900, "to": 0}, "datasourceUid": "__expr__", "model": map[string]any{"refId": "B", "type": "reduce", "expression": "A", "reducer": "last"}},
			map[string]any{"refId": "C", "relativeTimeRange": map[string]int{"from": 900, "to": 0}, "datasourceUid": "__expr__", "model": map[string]any{"refId": "C", "type": "threshold", "expression": "B", "conditions": []any{map[string]any{"evaluator": map[string]any{"type": comparison, "params": []int{threshold}}}}}},
		},
	}
}
