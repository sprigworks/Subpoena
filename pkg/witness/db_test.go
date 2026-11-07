//subpoena:spec_derived
//subpoena:pure_logic

// From the round 2 brief, "New witnesses", and witnesses/README.md: a
// rolled-back write is not an effect, an unparsed statement counts against
// every table, zero rows is no row.
package witness

import "testing"

func TestRowEventEffect(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    RowEvent
		want bool
	}{
		{"committed rows", RowEvent{Outcome: OutcomeCommitted, Rows: 2}, true},
		{"committed, count unknown", RowEvent{Outcome: OutcomeCommitted, Rows: RowsUnknown}, true},
		{"committed, zero rows", RowEvent{Outcome: OutcomeCommitted, Rows: 0}, false},
		{"rolled back", RowEvent{Outcome: OutcomeRolledBack, Rows: 2}, false},
		{"failed", RowEvent{Outcome: OutcomeFailed, Rows: 2}, false},
		{"unknown", RowEvent{Outcome: OutcomeUnknown, Rows: 2}, false},
		{"read", RowEvent{Outcome: OutcomeRead, Rows: RowsUnknown}, false},
	} {
		if got := tc.e.Effect(); got != tc.want {
			t.Errorf("%s: Effect() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRowEventTouches(t *testing.T) {
	one := func(names ...string) RowEvent { return RowEvent{Tables: names} }
	for _, tc := range []struct {
		name  string
		e     RowEvent
		table string
		want  bool
	}{
		{"same", one("users"), "users", true},
		{"other", one("users"), "orders", false},
		{"any of several", one("a", "users"), "users", true},
		{"case", one("Users"), "users", true},
		{"schema on the event", one("public.users"), "users", true},
		{"schema on the claim", one("users"), "public.users", true},
		{"same schema", one("public.users"), "public.users", true},
		{"other schema", one("public.users"), "other.users", false},
		{"suffix is not a part", one("superusers"), "users", false},
		{"every table", one("users"), "", true},
		{"opaque", RowEvent{Opaque: true}, "users", true},
		{"opaque with a table", RowEvent{Opaque: true, Tables: []string{"orders"}}, "users", true},
		{"no table named", RowEvent{}, "users", true},
	} {
		if got := tc.e.Touches(tc.table); got != tc.want {
			t.Errorf("%s: Touches(%q) = %v, want %v", tc.name, tc.table, got, tc.want)
		}
	}
}
