//subpoena:impl_derived
//subpoena:pure_logic

// Builtin classification lists checked against the PostgreSQL catalog.
package live

import (
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The lists are only as good as what the server says of them: every keyword it has
// is known, and everything listed as inert is a stable or immutable catalog
// routine, except the few named here, whose side effects are not on rows.
func TestListsAgainstTheServer(t *testing.T) {
	r := newPGRig(t)
	strs := func(q string, args ...any) []string {
		t.Helper()
		rows, err := r.direct.Query(r.ctx, q, args...)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got, want := strs("SELECT upper(word) FROM pg_get_keywords() ORDER BY upper(word) COLLATE \"C\""), listed(t, "pg-keywords.txt"); !slices.Equal(got, want) {
		t.Errorf("the server's keywords differ from pgKeywords: %d against %d", len(got), len(want))
	}
	noRows := []string{
		"CURRVAL", "GEN_RANDOM_UUID", "LASTVAL", "NEXTVAL", "NOW", "PG_ADVISORY_LOCK", "PG_ADVISORY_UNLOCK",
		"PG_ADVISORY_XACT_LOCK", "PG_SLEEP", "PG_TRY_ADVISORY_LOCK", "RANDOM",
	}
	volatile := strs(`SELECT DISTINCT upper(proname::text) FROM pg_proc WHERE pronamespace = 'pg_catalog'::regnamespace AND provolatile = 'v' AND upper(proname::text) = ANY($1)`, listed(t, "pg-listed-funcs.txt"))
	for _, f := range volatile {
		if !slices.Contains(noRows, f) {
			t.Errorf("%s is listed as inert and has a volatile overload", f)
		}
	}
	missing := strs(`SELECT n FROM unnest($1::text[]) n WHERE lower(n) NOT IN (SELECT proname::text FROM pg_proc WHERE pronamespace = 'pg_catalog'::regnamespace)`, listed(t, "pg-listed-funcs.txt"))
	for _, f := range missing {
		// Keywords the grammar turns into a catalog call of another name.
		if f != "CHAR_LENGTH" && f != "CURRENT_SCHEMA" {
			t.Errorf("%s is listed and is no catalog function", f)
		}
	}
	for _, op := range listed(t, "pg-listed-operators.txt") {
		for _, bad := range strs(`SELECT o.oid::regoperator::text FROM pg_operator o JOIN pg_proc p ON p.oid = o.oprcode WHERE o.oprname = $1 AND o.oprnamespace = 'pg_catalog'::regnamespace AND p.provolatile = 'v'`, op) {
			t.Errorf("listed operator %s", bad)
		}
		if len(strs(`SELECT oprname::text FROM pg_operator WHERE oprname = $1 AND oprnamespace = 'pg_catalog'::regnamespace`, op)) == 0 && op != "!=" && op != "=>" {
			t.Errorf("%s is listed and is no catalog operator", op)
		}
	}
}
