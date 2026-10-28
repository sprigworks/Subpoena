//subpoena:pure_logic
//subpoena:impl_derived

package alerts_test

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"example.com/platform/contract/alerts"
	"example.com/platform/contract/generated/go/semconv"
	"example.com/platform/contract/invariants"
	"gopkg.in/yaml.v3"
)

func TestProvisioningMatchesSharedContract(t *testing.T) {
	want, err := alerts.Render()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stale provisioning: run make generate")
	}
	var doc struct {
		APIVersion int `yaml:"apiVersion"`
		Groups     []struct {
			Rules []struct {
				UID       string `yaml:"uid"`
				NoData    string `yaml:"noDataState"`
				ExecError string `yaml:"execErrState"`
				Data      []struct {
					Model struct {
						Query string `yaml:"query"`
					} `yaml:"model"`
				} `yaml:"data"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.APIVersion != 1 || len(doc.Groups) != 1 || len(doc.Groups[0].Rules) != 2*len(invariants.Names()) {
		t.Fatal("missing rule pairs")
	}
	rules := doc.Groups[0].Rules
	for i, name := range invariants.Names() {
		query := invariants.MustLoad(name)
		violation, liveness := rules[2*i], rules[2*i+1]
		if violation.Data[0].Model.Query != query+" | count_over_time()" {
			t.Fatal("invariant text drift")
		}
		if liveness.Data[0].Model.Query != fmt.Sprintf(`{ name = %q } | count_over_time()`, semconv.SpanPlatformActionAuthorize) {
			t.Fatal("liveness query drift")
		}
		if violation.NoData != "OK" || liveness.NoData != "Alerting" || violation.ExecError != "Error" || liveness.ExecError != "Error" {
			t.Fatal("unsafe missing-data or query-error policy")
		}
		// Production rules cannot read attributes stripped by production.Exporter.
		for _, attr := range regexp.MustCompile(`span\.([a-zA-Z0-9_.]+)`).FindAllStringSubmatch(query, -1) {
			if tier, ok := semconv.AttributeTiers[attr[1]]; !ok || tier != semconv.TierAll {
				t.Fatalf("production invariant reads unavailable attribute %s", attr[1])
			}
		}
		if strings.TrimSpace(query) == "" {
			t.Fatal("empty invariant")
		}
	}
}
