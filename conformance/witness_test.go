//subpoena:spec_derived
//subpoena:pure_logic

// Runs conformance/witness.yaml (docs/ports.md W3, W4) through
// witness.ReadLog and harness.NoSpawn: the Go reader passes the same cases a
// port's reader must. The cases are files the witness wrote; no telemetry.
package conformance

import (
	"bytes"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness"
)

type witnessCases struct {
	Traces map[string]string `yaml:"traces"`
	Cases  []struct {
		Name            string              `yaml:"name"`
		Lines           []string            `yaml:"lines"`
		ReadError       string              `yaml:"read_error"`
		Health          string              `yaml:"health"`
		Spawned         map[string][]int    `yaml:"spawned"`
		NoSpawn         map[string]string   `yaml:"no_spawn"`
		Wrote           map[string][]string `yaml:"wrote"`
		NoWrite         map[string]string   `yaml:"no_write"`
		NoWritePaths    []string            `yaml:"no_write_paths"`
		Delivered       map[string][]string `yaml:"delivered"`
		NoDelivery      map[string]string   `yaml:"no_delivery"`
		NoDeliveryPeers []string            `yaml:"no_delivery_peers"`
		Committed       map[string][]string `yaml:"committed"`
		NoRow           map[string]string   `yaml:"no_row"`
	} `yaml:"cases"`
}

func TestWitnessCases(t *testing.T) {
	b, err := os.ReadFile("witness.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// KnownFields: a misspelt key (no_spwan) must fail, not drop a check.
	var wc witnessCases
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&wc); err != nil {
		t.Fatal(err)
	}
	trace := func(t *testing.T, name string) string {
		t.Helper()
		id, ok := wc.Traces[name]
		if !ok {
			t.Fatalf("unknown trace %q", name)
		}
		return id
	}
	if len(wc.Cases) < 10 {
		t.Fatalf("only %d cases", len(wc.Cases))
	}
	for _, c := range wc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if (c.ReadError == "") == (c.Health == "") {
				t.Fatal("a case needs exactly one of read_error and health")
			}
			log, err := witness.ReadLog(strings.NewReader(strings.Join(c.Lines, "\n") + "\n"))
			if c.ReadError != "" {
				if err == nil || !strings.Contains(err.Error(), c.ReadError) {
					t.Fatalf("want a read error containing %q, got %v", c.ReadError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch h := log.Health(); {
			case c.Health == "ok" && h != nil:
				t.Errorf("want healthy, got %v", h)
			case c.Health != "ok" && (h == nil || !strings.Contains(h.Error(), c.Health)):
				t.Errorf("want a capture fault containing %q, got %v", c.Health, h)
			}
			for name, want := range c.Spawned {
				var got []int
				for _, e := range log.Spawned(trace(t, name)) {
					got = append(got, e.PID)
				}
				if len(got) != 0 || len(want) != 0 {
					if !reflect.DeepEqual(got, want) {
						t.Errorf("spawned %s: got %v, want %v", name, got, want)
					}
				}
			}
			for name, want := range c.Wrote {
				var got []string
				for _, e := range log.Wrote(trace(t, name)) {
					got = append(got, e.Path)
				}
				if len(got) != 0 || len(want) != 0 {
					if !reflect.DeepEqual(got, want) {
						t.Errorf("wrote %s: got %v, want %v", name, got, want)
					}
				}
			}
			for name, want := range c.NoWrite {
				if v, _ := harness.NoWrite(log, trace(t, name), c.NoWritePaths...); v.String() != want {
					t.Errorf("no write %s: got %s, want %s", name, v, want)
				}
			}
			for name, want := range c.NoSpawn {
				if v, _ := harness.NoSpawn(log, trace(t, name)); v.String() != want {
					t.Errorf("no_spawn %s: got %s, want %s", name, v, want)
				}
			}
			for name, want := range c.Delivered {
				got := []string{}
				for _, e := range log.Delivered(trace(t, name)) {
					peer := ""
					if e.Peer.IsValid() {
						peer = e.Peer.String()
					}
					got = append(got, peer)
				}
				if len(got) != len(want) || (len(got) != 0 && !reflect.DeepEqual(got, want)) {
					t.Errorf("delivered %s: got %v, want %v", name, got, want)
				}
			}
			var peers []netip.AddrPort
			for _, p := range c.NoDeliveryPeers {
				peers = append(peers, netip.MustParseAddrPort(p))
			}
			for name, want := range c.NoDelivery {
				if v, _ := harness.NoDelivery(log, trace(t, name), harness.DeliveryTo(peers...)); v.String() != want {
					t.Errorf("no_delivery %s: got %s, want %s", name, v, want)
				}
			}
			for name, want := range c.NoRow {
				if v, _ := harness.NoRow(log, trace(t, name), ""); v.String() != want {
					t.Errorf("no_row %s: got %s, want %s", name, v, want)
				}
			}
			for name, want := range c.Committed {
				got := []string{}
				for _, e := range log.Committed(trace(t, name)) {
					got = append(got, e.Verb)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("committed %s: got %v, want %v", name, got, want)
				}
			}
		})
	}
}
