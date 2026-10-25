// Package conformance holds the fixtures and helpers that check pkg/traceql
// against a real Tempo. Fixtures are OTLP/JSON export requests; the same file
// is evaluated in-process by pkg/traceql and pushed to Tempo over OTLP/HTTP.
//
// This package never imports Tempo: Tempo is AGPL-3.0 and is used only as a
// separate process over HTTP.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sprigworks/subpoena/pkg/traceql"
)

// Export is an OTLP/JSON ExportTraceServiceRequest. Only the fields the
// conformance suite needs are modelled; the rest of a fixture is dropped on
// push. Field names follow the OTLP/JSON mapping (lowerCamelCase; trace and
// span IDs are hex strings; 64-bit integers may be strings).
type Export struct {
	ResourceSpans []ResourceSpans `json:"resourceSpans"`
}

type ResourceSpans struct {
	Resource   Resource     `json:"resource"`
	ScopeSpans []ScopeSpans `json:"scopeSpans"`
}

type Resource struct {
	Attributes []KeyValue `json:"attributes,omitempty"`
}

type ScopeSpans struct {
	Scope Scope  `json:"scope"`
	Spans []Span `json:"spans"`
}

type Scope struct {
	Name string `json:"name,omitempty"`
}

type Span struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId,omitempty"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind,omitempty"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []KeyValue `json:"attributes,omitempty"`
}

type KeyValue struct {
	Key   string   `json:"key"`
	Value AnyValue `json:"value"`
}

// AnyValue holds exactly one of the scalar kinds. Arrays and key-value lists
// are outside the TraceQL subset and rejected when converted.
type AnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	IntValue    *Int64   `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`

	// Unsupported catches arrayValue and kvlistValue so conversion can fail loudly.
	ArrayValue  json.RawMessage `json:"arrayValue,omitempty"`
	KvlistValue json.RawMessage `json:"kvlistValue,omitempty"`
}

// Int64 accepts both the OTLP/JSON string form ("2") and a plain number (2),
// and marshals as a string, as the spec requires.
type Int64 int64

func (i *Int64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("conformance: bad intValue %s", b)
	}
	*i = Int64(v)
	return nil
}

func (i Int64) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(strconv.FormatInt(int64(i), 10))), nil
}

// Fixture is one named OTLP export loaded from fixtures/<Name>.json.
type Fixture struct {
	Name   string
	Export Export
}

// LoadFixture reads and decodes one fixture file. Unknown fields (such as the
// "_comment" the fixtures carry) are ignored.
func LoadFixture(path string) (*Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Export
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("conformance: %s: %w", path, err)
	}
	return &Fixture{Name: strings.TrimSuffix(filepath.Base(path), ".json"), Export: e}, nil
}

// LoadFixtures loads every *.json in dir, sorted by name.
func LoadFixtures(dir string) ([]*Fixture, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []*Fixture
	for _, p := range paths {
		f, err := LoadFixture(p)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// NormID lower-cases a trace ID and left-pads it to 32 hex digits. Tempo may
// return IDs with leading zeros trimmed.
func NormID(id string) string {
	id = strings.ToLower(id)
	if len(id) < 32 {
		id = strings.Repeat("0", 32-len(id)) + id
	}
	return id
}

// Traces converts the fixture to the evaluator's model. Traces keep first-seen
// order; spans of one trace may be spread across resources, scopes and the
// request in any order.
func (f *Fixture) Traces() ([]traceql.Trace, error) {
	var out []traceql.Trace
	idx := map[string]int{}
	for _, rs := range f.Export.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				tid := NormID(sp.TraceID)
				i, ok := idx[tid]
				if !ok {
					i = len(out)
					idx[tid] = i
					out = append(out, traceql.Trace{ID: tid})
				}
				attrs := map[string]any{}
				for _, kv := range sp.Attributes {
					v, err := kv.Value.scalar()
					if err != nil {
						return nil, fmt.Errorf("conformance: fixture %s span %s attribute %s: %w", f.Name, sp.SpanID, kv.Key, err)
					}
					attrs[kv.Key] = v
				}
				out[i].Spans = append(out[i].Spans, traceql.Span{
					ID: strings.ToLower(sp.SpanID), ParentID: strings.ToLower(sp.ParentSpanID),
					Name: sp.Name, Attrs: attrs,
				})
			}
		}
	}
	return out, nil
}

func (v AnyValue) scalar() (any, error) {
	n := 0
	var out any
	if v.StringValue != nil {
		n, out = n+1, *v.StringValue
	}
	if v.BoolValue != nil {
		n, out = n+1, *v.BoolValue
	}
	if v.IntValue != nil {
		n, out = n+1, int64(*v.IntValue)
	}
	if v.DoubleValue != nil {
		n, out = n+1, *v.DoubleValue
	}
	if len(v.ArrayValue) > 0 || len(v.KvlistValue) > 0 {
		return nil, fmt.Errorf("array and kvlist values are outside the TraceQL subset")
	}
	if n != 1 {
		return nil, fmt.Errorf("expected exactly one scalar value, found %d", n)
	}
	return out, nil
}

// TraceIDs returns the sorted, normalised trace IDs in the fixture.
func (f *Fixture) TraceIDs() ([]string, error) {
	trs, err := f.Traces()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(trs))
	for _, t := range trs {
		ids = append(ids, t.ID)
	}
	sort.Strings(ids)
	return ids, nil
}

// Rebased returns a deep copy of the export with every timestamp shifted so
// that the earliest span starts at start (unix nanoseconds). Tempo searches a
// time window, so fixtures with fixed 2023 timestamps would fall outside it.
func (f *Fixture) Rebased(start int64) (*Export, error) {
	b, err := json.Marshal(f.Export)
	if err != nil {
		return nil, err
	}
	var cp Export
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, err
	}
	first := int64(-1)
	for _, rs := range cp.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				t, err := strconv.ParseInt(sp.StartTimeUnixNano, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("conformance: %s: bad startTimeUnixNano %q", f.Name, sp.StartTimeUnixNano)
				}
				if first < 0 || t < first {
					first = t
				}
			}
		}
	}
	shift := start - first
	for _, rs := range cp.ResourceSpans {
		for si := range rs.ScopeSpans {
			sps := rs.ScopeSpans[si].Spans
			for i := range sps {
				s, _ := strconv.ParseInt(sps[i].StartTimeUnixNano, 10, 64)
				e, err := strconv.ParseInt(sps[i].EndTimeUnixNano, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("conformance: %s: bad endTimeUnixNano %q", f.Name, sps[i].EndTimeUnixNano)
				}
				sps[i].StartTimeUnixNano = strconv.FormatInt(s+shift, 10)
				sps[i].EndTimeUnixNano = strconv.FormatInt(e+shift, 10)
			}
		}
	}
	return &cp, nil
}

// Query is a TraceQL string with a stable name.
type Query struct {
	Name string // "invariants/<file>" or "queries/<file>"
	Text string
}

// LoadQueries reads every invariants/*.traceql (from invariantsDir) and every
// queries/*.traceql (from queriesDir), trimmed, sorted by name.
func LoadQueries(invariantsDir, queriesDir string) ([]Query, error) {
	var out []Query
	for _, d := range []struct{ prefix, dir string }{{"invariants", invariantsDir}, {"queries", queriesDir}} {
		paths, err := filepath.Glob(filepath.Join(d.dir, "*.traceql"))
		if err != nil {
			return nil, err
		}
		sort.Strings(paths)
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			out = append(out, Query{
				Name: d.prefix + "/" + strings.TrimSuffix(filepath.Base(p), ".traceql"),
				Text: strings.TrimSpace(string(b)),
			})
		}
	}
	return out, nil
}
