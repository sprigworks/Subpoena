//subpoena:impl_derived

package conformance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

func decode(t *testing.T, s string) *Fixture {
	t.Helper()
	var e Export
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		t.Fatal(err)
	}
	return &Fixture{Name: "inline", Export: e}
}

func span(trace, id, parent, attrs string) string {
	return `{"traceId":"` + trace + `","spanId":"` + id + `","parentSpanId":"` + parent + `","name":"n","startTimeUnixNano":"1000","endTimeUnixNano":"2000","attributes":[` + attrs + `]}`
}

func export(spans ...string) string {
	return `{"resourceSpans":[{"scopeSpans":[{"spans":[` + strings.Join(spans, ",") + `]}]}]}`
}

func TestAttributeKinds(t *testing.T) {
	f := decode(t, export(span("ab", "01", "", `
		{"key":"s","value":{"stringValue":"x"}},
		{"key":"b","value":{"boolValue":false}},
		{"key":"i","value":{"intValue":"-7"}},
		{"key":"n","value":{"intValue":3}},
		{"key":"d","value":{"doubleValue":1.5}}`)))
	trs, err := f.Traces()
	if err != nil {
		t.Fatal(err)
	}
	a := trs[0].Spans[0].Attrs
	want := map[string]any{"s": "x", "b": false, "i": int64(-7), "n": int64(3), "d": 1.5}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("attr %s = %#v (%T), want %#v (%T)", k, a[k], a[k], v, v)
		}
	}
}

// Arrays and maps are kept as traceql.Unsupported, so only a query that reads
// them is refused (docs/traceql-subset.md). A value with no type at all is
// malformed, and fails the conversion.
func TestArrayAndMapValuesConvertToUnsupported(t *testing.T) {
	for kind, kv := range map[string]string{
		"array":  `{"key":"a","value":{"arrayValue":{"values":[{"stringValue":"x"}]}}}`,
		"kvlist": `{"key":"a","value":{"kvlistValue":{"values":[]}}}`,
	} {
		trs, err := decode(t, export(span("ab", "01", "", kv))).Traces()
		if err != nil {
			t.Errorf("%s: %v", kind, err)
			continue
		}
		if got := trs[0].Spans[0].Attrs["a"]; got != (traceql.Unsupported{Kind: kind}) {
			t.Errorf("%s: converted to %#v", kind, got)
		}
	}
	if _, err := decode(t, export(span("ab", "01", "", `{"key":"a","value":{}}`))).Traces(); err == nil {
		t.Error("a value with no type: want an error")
	}
}

func TestTracesGroupAcrossTheRequestAndNormaliseIDs(t *testing.T) {
	f := decode(t, export(
		span("AB", "01", "", ""),
		span("cd", "02", "", ""),
		span("ab", "03", "01", "")))
	trs, err := f.Traces()
	if err != nil {
		t.Fatal(err)
	}
	if len(trs) != 2 {
		t.Fatalf("want 2 traces, got %d", len(trs))
	}
	if trs[0].ID != strings.Repeat("0", 30)+"ab" || len(trs[0].Spans) != 2 || trs[1].ID != strings.Repeat("0", 30)+"cd" {
		t.Fatalf("grouping wrong: %+v", trs)
	}
	if NormID("00AB") != strings.Repeat("0", 28)+"00ab" {
		t.Error("NormID must lower-case and pad")
	}
}

func TestRebasedShiftsTimestampsAndLeavesTheOriginal(t *testing.T) {
	f := decode(t, export(span("ab", "01", "", "")))
	e, err := f.Rebased(5_000_000)
	if err != nil {
		t.Fatal(err)
	}
	got := e.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if got.StartTimeUnixNano != "5000000" || got.EndTimeUnixNano != "5001000" {
		t.Fatalf("rebased to %s..%s", got.StartTimeUnixNano, got.EndTimeUnixNano)
	}
	if f.Export.ResourceSpans[0].ScopeSpans[0].Spans[0].StartTimeUnixNano != "1000" {
		t.Fatal("Rebased mutated the fixture")
	}
}

func TestPushedJSONUsesOTLPEncodings(t *testing.T) {
	f := decode(t, export(span("ab", "01", "", `{"key":"i","value":{"intValue":2}}`)))
	b, err := json.Marshal(f.Export)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"intValue":"2"`) {
		t.Errorf("64-bit integers must be JSON strings: %s", b)
	}
}
