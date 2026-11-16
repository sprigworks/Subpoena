//subpoena:impl_derived
//subpoena:pure_logic

// Documented limits on preinstalled routines and indirect table routing.
package live

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/sprigworks/subpoena/pkg/harness"
)

// The limits witnesses/README.md states: routines installed before the capture
// that nothing in the statement can tell from what they imitate. If one of these
// stops passing, the limit has closed: change the docs.
func TestPostgresPreinstalledRoutineLimits(t *testing.T) {
	cases := map[string]func(r *pgRig, c *pgx.Conn){
		"view over a writing function": func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "")
			r.direct1("CREATE VIEW v_" + r.table + " AS SELECT w_" + r.table + "()")
			sent(c, "SELECT * FROM v_"+r.table)
		},
		"function called as a column": func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE TABLE one_" + r.table + " (a int); INSERT INTO one_" + r.table + " VALUES (1)")
			r.writer("w_"+r.table, "one_"+r.table)
			sent(c, "SELECT o.w_"+r.table+" FROM one_"+r.table+" o")
		},
		"function called as a column in WHERE": func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE TABLE one_" + r.table + " (a int); INSERT INTO one_" + r.table + " VALUES (1)")
			r.writer("w_"+r.table, "one_"+r.table)
			sent(c, "SELECT 1 FROM one_"+r.table+" o WHERE o.w_"+r.table+" = 1")
		},
		"overload of a listed name": func(r *pgRig, c *pgx.Conn) {
			r.writer("lower", "int")
			r.t.Cleanup(func() { r.direct.Exec(context.Background(), "DROP FUNCTION lower(int)") })
			sent(c, "SELECT lower(1)")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			r := newPGRig(t)
			c := r.connect("disable")
			run(r, c)
			c.Close(context.Background())
			if v := r.verdict(1); v != harness.Pass {
				t.Fatalf("this limit has closed (%v): change witnesses/README.md and docs/ports.md", v)
			}
		})
	}
}

// The limits witnesses/README.md states for rows that reach a table the statement
// does not name: only the catalog shows these, and a claim is as good as the name
// in the statement. If one of these stops passing, the limit has closed: change the
// docs.
func TestIndirectTableRoutingLimits(t *testing.T) {
	pg := map[string]func(r *pgRig) (claim string, rows int){
		"insert through an updatable view, claim on its table": func(r *pgRig) (string, int) {
			r.direct1("CREATE VIEW v_" + r.table + " AS SELECT * FROM " + r.table)
			sent(r.connect("disable"), "INSERT INTO v_"+r.table+" VALUES (1, 'a')")
			return r.table, r.count(r.table)
		},
		"insert into a child, claim on its parent": func(r *pgRig) (string, int) {
			r.direct1("CREATE TABLE c_" + r.table + " () INHERITS (" + r.table + ")")
			sent(r.connect("disable"), "INSERT INTO c_"+r.table+" VALUES (1, 'a')")
			return r.table, r.count(r.table)
		},
		"insert into a partition, claim on its parent": func(r *pgRig) (string, int) {
			p := "p_" + r.table
			r.direct1("CREATE TABLE " + p + " (id int) PARTITION BY RANGE (id); CREATE TABLE " + p + "_a PARTITION OF " + p + " FOR VALUES FROM (0) TO (10)")
			r.cleanup("DROP TABLE " + p)
			sent(r.connect("disable"), "INSERT INTO "+p+"_a VALUES (1)")
			return p, r.count(p)
		},
		"insert into a parent, claim on its partition": func(r *pgRig) (string, int) {
			p := "p_" + r.table
			r.direct1("CREATE TABLE " + p + " (id int) PARTITION BY RANGE (id); CREATE TABLE " + p + "_a PARTITION OF " + p + " FOR VALUES FROM (0) TO (10)")
			r.cleanup("DROP TABLE " + p)
			sent(r.connect("disable"), "INSERT INTO "+p+" VALUES (1)")
			return p + "_a", r.count(p + "_a")
		},
	}
	for name, run := range pg {
		t.Run(name, func(t *testing.T) {
			r := newPGRig(t)
			claim, rows := run(r)
			if rows != 1 {
				t.Fatalf("%d rows", rows)
			}
			r.w.Stop()
			if v, _ := harness.NoRow(r.w, trace, claim); v != harness.Pass {
				t.Fatalf("this limit has closed (%v): change witnesses/README.md and docs/ports.md", v)
			}
		})
	}
	t.Run("MySQL insert through an updatable view", func(t *testing.T) {
		r := newMyRig(t)
		must(t, r.direct, "CREATE VIEW v_"+r.table+" AS SELECT * FROM "+r.table)
		db := r.conn("multiStatements=true")
		must(t, db, "INSERT INTO v_"+r.table+" VALUES (1, 'a')")
		db.Close()
		if v := r.verdict(1); v != harness.Pass {
			t.Fatalf("this limit has closed (%v): change witnesses/README.md and docs/ports.md", v)
		}
	})
}
