//subpoena:spec_derived
//subpoena:pure_logic

// conformance/witness.yaml through ReadLog and Health, from this package, so
// cross-examining pkg/witness runs every fail-closed case against the reader
// (the conformance package runs the same file through NoSpawn too). The
// cases are files the witness wrote; there is no telemetry.
package witness

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReadLogPassesTheSharedCases(t *testing.T) {
	b, err := os.ReadFile("../../conformance/witness.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Traces map[string]string `yaml:"traces"`
		Cases  []struct {
			Name      string            `yaml:"name"`
			Lines     []string          `yaml:"lines"`
			ReadError string            `yaml:"read_error"`
			Health    string            `yaml:"health"`
			Spawned   map[string][]int  `yaml:"spawned"`
			NoSpawn   map[string]string `yaml:"no_spawn"`
		} `yaml:"cases"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("only %d cases", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			l, err := ReadLog(strings.NewReader(strings.Join(c.Lines, "\n") + "\n"))
			switch {
			case c.ReadError != "":
				if err == nil || !strings.Contains(err.Error(), c.ReadError) {
					t.Fatalf("want a read error containing %q, got %v", c.ReadError, err)
				}
				return
			case err != nil:
				t.Fatal(err)
			}
			switch h := l.Health(); {
			case c.Health == "ok" && h != nil:
				t.Errorf("want healthy, got %v", h)
			case c.Health != "ok" && (h == nil || !strings.Contains(h.Error(), c.Health)):
				t.Errorf("want a capture fault containing %q, got %v", c.Health, h)
			}
		})
	}
}
