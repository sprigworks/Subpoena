//subpoena:spec_derived

// Runs conformance/harness.yaml (docs/ports.md H1-H6) through pkg/harness:
// the Go harness passes the same cases a port's harness must.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/sprigworks/subpoena/pkg/harness"
)

type harnessCase struct {
	Name     string `yaml:"name"`
	Capacity int    `yaml:"capacity"`
	Spans    []struct {
		ID     string         `yaml:"id"`
		Parent string         `yaml:"parent"`
		Name   string         `yaml:"name"`
		Attrs  map[string]any `yaml:"attrs"`
		Ended  *bool          `yaml:"ended"`
	} `yaml:"spans"`
	Collect struct {
		Complete   bool     `yaml:"complete"`
		Dropped    int      `yaml:"dropped"`
		Unfinished []string `yaml:"unfinished"`
		Traces     int      `yaml:"traces"`
	} `yaml:"collect"`
	Assertions []struct {
		Absent  string `yaml:"absent"`
		Exists  string `yaml:"exists"`
		Verdict string `yaml:"verdict"`
		Require string `yaml:"require"`
		Error   bool   `yaml:"error"`
	} `yaml:"assertions"`
}

func loadHarnessCases(t *testing.T) []harnessCase {
	t.Helper()
	b, err := os.ReadFile("harness.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []harnessCase `yaml:"cases"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 5 {
		t.Fatalf("want the harness cases, got %d", len(f.Cases))
	}
	return f.Cases
}

func kv(k string, v any) (attribute.KeyValue, error) {
	switch v := v.(type) {
	case string:
		return attribute.String(k, v), nil
	case bool:
		return attribute.Bool(k, v), nil
	case int:
		return attribute.Int(k, v), nil
	}
	return attribute.KeyValue{}, fmt.Errorf("attribute %s: unsupported value %v (%T)", k, v, v)
}

// recordingTB records whether a Require helper failed the test, without
// failing this one. Fatalf stops the helper the way testing.T does; the
// helpers call nothing else that fails.
type recordingTB struct {
	testing.TB
	failed bool
}

func (r *recordingTB) Helper()               {}
func (r *recordingTB) Logf(string, ...any)   {}
func (r *recordingTB) Fatalf(string, ...any) { r.failed = true; panic(r) }

func requireFails(tb *testing.T, fn func(testing.TB)) (failed bool) {
	rec := &recordingTB{TB: tb}
	defer func() {
		if p := recover(); p != nil && p != rec {
			panic(p)
		}
		failed = rec.failed
	}()
	fn(rec)
	return rec.failed
}

func TestHarnessCases(t *testing.T) {
	for _, c := range loadHarnessCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			h := harness.NewWithCapacity(c.Capacity)
			defer h.Shutdown(context.Background())
			tracer := h.Tracer("harness-case")
			ctxs := map[string]context.Context{}
			var toEnd []trace.Span
			for _, s := range c.Spans {
				parent := context.Background()
				if s.Parent != "" {
					p, ok := ctxs[s.Parent]
					if !ok {
						t.Fatalf("span %s: parent %s is not an earlier span", s.ID, s.Parent)
					}
					parent = p
				}
				var opts []trace.SpanStartOption
				if s.Parent == "" {
					opts = append(opts, trace.WithNewRoot())
				}
				ctx, sp := tracer.Start(parent, s.Name, opts...)
				for k, v := range s.Attrs {
					a, err := kv(k, v)
					if err != nil {
						t.Fatal(err)
					}
					sp.SetAttributes(a)
				}
				ctxs[s.ID] = ctx
				if s.Ended == nil || *s.Ended {
					toEnd = append(toEnd, sp)
				}
			}
			for i := len(toEnd) - 1; i >= 0; i-- {
				toEnd[i].End()
			}

			tr, err := h.Collect(context.Background())
			var ie *harness.IncompleteError
			dropped, unfinished := 0, []string{}
			if errors.As(err, &ie) {
				dropped = ie.Dropped
				unfinished = append(unfinished, ie.Unfinished...)
			} else if err != nil {
				t.Fatal(err)
			}
			if c.Collect.Unfinished == nil {
				c.Collect.Unfinished = []string{}
			}
			if tr.Complete() != c.Collect.Complete || dropped != c.Collect.Dropped ||
				!reflect.DeepEqual(unfinished, c.Collect.Unfinished) || len(tr.TraceIDs()) != c.Collect.Traces {
				t.Fatalf("collect: complete=%v dropped=%d unfinished=%v traces=%d, want %+v",
					tr.Complete(), dropped, unfinished, len(tr.TraceIDs()), c.Collect)
			}
			if (err == nil) != c.Collect.Complete {
				t.Fatalf("Collect error %v, but complete=%v", err, c.Collect.Complete)
			}

			for _, a := range c.Assertions {
				kind, q, check, require := "absent", a.Absent, tr.Absent, harness.RequireAbsent
				if a.Exists != "" {
					kind, q, check, require = "exists", a.Exists, tr.Exists, harness.RequireExists
				}
				v, err := check(q)
				if a.Error {
					if err == nil {
						t.Errorf("%s %s: want a parse error, got verdict %v", kind, q, v)
					}
					continue
				}
				if err != nil {
					t.Errorf("%s %s: %v", kind, q, err)
					continue
				}
				if v.String() != a.Verdict {
					t.Errorf("%s %s: verdict %v, want %s", kind, q, v, a.Verdict)
				}
				failed := requireFails(t, func(tb testing.TB) { require(tb, tr, q) })
				if want := a.Require == "fails"; failed != want {
					t.Errorf("%s %s: the Require helper failed=%v, want %s", kind, q, failed, a.Require)
				}
			}
		})
	}
}
