//subpoena:spec_derived
//subpoena:pure_logic

// docs/ports.md, "Generated names": every language's generated module holds
// the same span names, attribute keys, enum values and export tiers. Weaver
// writes all three from one registry; this catches a template that drifts.
// It reads generated source files; there is no telemetry.
package production

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/generated/go/semconv"
)

type names struct {
	values map[string][]string // SPAN, ATTR, VAL -> sorted values
	tiers  map[string]string   // attribute key -> tier
}

// read extracts the names from one generated file. def matches a constant
// (kind, identifier, value); tier matches one tier-map entry (identifier, tier).
func read(t *testing.T, path string, def, tier *regexp.Regexp, kind func(string) string) names {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := names{values: map[string][]string{}, tiers: map[string]string{}}
	byIdent := map[string]string{}
	for _, m := range def.FindAllStringSubmatch(string(b), -1) {
		k := kind(m[1])
		n.values[k] = append(n.values[k], m[3])
		byIdent[m[1]+m[2]] = m[3]
	}
	for _, m := range tier.FindAllStringSubmatch(string(b), -1) {
		key, ok := byIdent[m[1]]
		if !ok {
			t.Fatalf("%s: tier entry for unknown constant %s", path, m[1])
		}
		n.tiers[key] = strings.ToLower(m[2])
	}
	for k := range n.values {
		sort.Strings(n.values[k])
	}
	return n
}

func TestEveryLanguageHasTheSameNames(t *testing.T) {
	upper := strings.ToUpper
	goNames := read(t, "../../generated/go/semconv/semconv.go",
		regexp.MustCompile(`(?m)^\t(Span|Attr|Val)(\w+) += "([^"]*)"$`),
		regexp.MustCompile(`(?m)^\t(Attr\w+): +Tier(\w+),$`), upper)
	py := read(t, "../../generated/python/semconv.py",
		regexp.MustCompile(`(?m)^(SPAN|ATTR|VAL)(_\w+): Final = "([^"]*)"$`),
		regexp.MustCompile(`(?m)^    (ATTR_\w+): TIER_(\w+),$`), upper)
	ts := read(t, "../../generated/ts/semconv.ts",
		regexp.MustCompile(`(?m)^export const (SPAN|ATTR|VAL)(_\w+) = "([^"]*)";$`),
		regexp.MustCompile(`(?m)^  \[(ATTR_\w+)\]: TIER_(\w+),$`), upper)

	if len(goNames.values["SPAN"]) == 0 || len(goNames.values["ATTR"]) == 0 {
		t.Fatalf("no Go names read; has the Go template changed? %v", goNames.values)
	}
	// The Go tier map is also the one pkg/production uses at run time.
	want := map[string]string{}
	for k, v := range semconv.AttributeTiers {
		want[k] = string(v)
	}
	if !reflect.DeepEqual(goNames.tiers, want) {
		t.Fatalf("reading the Go source disagrees with semconv.AttributeTiers:\n got  %v\n want %v", goNames.tiers, want)
	}
	for lang, n := range map[string]names{"Python": py, "TypeScript": ts} {
		if !reflect.DeepEqual(n.values, goNames.values) {
			t.Errorf("%s names differ from Go:\n %s %v\n Go %v", lang, lang, n.values, goNames.values)
		}
		if !reflect.DeepEqual(n.tiers, goNames.tiers) {
			t.Errorf("%s tiers differ from Go:\n %s %v\n Go %v", lang, lang, n.tiers, goNames.tiers)
		}
	}
}
