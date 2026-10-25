//subpoena:spec_derived
//subpoena:pure_logic

// Policy evaluation is pure logic: a decision from a user and a host, no
// telemetry to collect. The marker exempts this file from no-trace-assertion;
// the decision's effect is tested with the harness and the witness in
// gateway_test.go.
package gateway_test

import (
	"testing"

	"github.com/sprigworks/subpoena/examples/gateway"
)

func TestPolicy(t *testing.T) {
	cases := []struct {
		user    gateway.User
		host    string
		allowed bool
		policy  string
	}{
		{gateway.User{}, "prod-1", false, gateway.PolicyDenyProdNonAdmin},
		{gateway.User{Admin: true}, "prod-1", true, gateway.PolicyAllowAdmin},
		{gateway.User{}, "staging-1", true, gateway.PolicyAllowDefault},
		{gateway.User{}, "production", true, gateway.PolicyAllowDefault}, // "prod-*" needs the dash
	}
	for _, c := range cases {
		got := gateway.Evaluate(c.user, c.host)
		if got.Allowed != c.allowed || got.PolicyID != c.policy {
			t.Errorf("%+v on %s: got %+v", c.user, c.host, got)
		}
	}
}
