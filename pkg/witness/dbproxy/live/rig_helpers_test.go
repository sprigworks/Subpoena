//subpoena:impl_derived
//subpoena:pure_logic

// Helpers shared by the live-server database witness tests.
package live

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sprigworks/subpoena/pkg/harness"
)

// verdict stops the witness and returns its answer on the rig's table.
func (r *pgRig) verdict(rows int) harness.Verdict {
	r.t.Helper()
	if got := r.rows(); got != rows {
		r.t.Fatalf("the table holds %d rows, the case expected %d", got, rows)
	}
	r.w.Stop()
	v, _ := harness.NoRow(r.w, trace, r.table)
	return v
}

func (r *pgRig) direct1(q string) {
	r.t.Helper()
	if _, err := r.direct.Exec(r.ctx, q); err != nil {
		r.t.Fatalf("%s: %v", q, err)
	}
}

// writer installs a function that writes the rig's table, as a migration would:
// off the witness.
func (r *pgRig) writer(name, args string) {
	r.t.Helper()
	r.direct1(fmt.Sprintf("CREATE FUNCTION %s(%s) RETURNS int LANGUAGE plpgsql AS $f$ BEGIN %s; RETURN 1; END $f$", name, args, r.ins()))
}

func (r *pgRig) ins() string { return "INSERT INTO " + r.table + " VALUES (1, 'a')" }

// sent sends q as a simple query. Its error is the case's business.
func sent(c *pgx.Conn, q string) { c.PgConn().Exec(context.Background(), q).ReadAll() }

func (r *myRig) ins() string { return "INSERT INTO " + r.table + " VALUES (1, 'a')" }

func (r *myRig) verdict(rows int) harness.Verdict {
	r.t.Helper()
	if got := r.rows(); got != rows {
		r.t.Fatalf("the table holds %d rows, the case expected %d: %+v", got, rows, r.w.Statements())
	}
	r.w.Stop()
	v, _ := harness.NoRow(r.w, trace, r.table)
	return v
}

// writerFn installs a stored function that writes the rig's table.
func (r *myRig) writerFn(name string) {
	r.t.Helper()
	must(r.t, r.direct, "CREATE FUNCTION "+name+"(x int) RETURNS int DETERMINISTIC MODIFIES SQL DATA BEGIN "+r.ins()+"; RETURN 1; END")
}

// login connects through the witness with extra startup parameters.
func (r *pgRig) login(params map[string]string) *pgx.Conn {
	r.t.Helper()
	cfg, err := pgx.ParseConfig(pgDSN(r.w.Addr().String(), "disable"))
	if err != nil {
		r.t.Fatal(err)
	}
	for k, v := range params {
		cfg.RuntimeParams[k] = v
	}
	c, err := pgx.ConnectConfig(r.ctx, cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func (r *pgRig) cleanup(q string) {
	r.t.Cleanup(func() { r.direct.Exec(context.Background(), q) })
}

func (r *pgRig) count(table string) int {
	r.t.Helper()
	var n int
	if err := r.direct.QueryRow(r.ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// shadow installs a writing lower(text) in a new schema, and returns the schema.
func (r *pgRig) shadow() string {
	r.t.Helper()
	s := "s_" + r.table
	r.direct1("CREATE SCHEMA " + s)
	r.writer(s+".lower", "text")
	return s
}

func listed(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile("../testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// waitMyQuiet gives a quit time to reach the witness, then stops it: Stop on a
// connection still closing would read as a drop.
func waitMyQuiet(r *myRig) {
	r.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if c := r.w.Coverage(); c.Unknown+c.RolledBack != 0 {
			break
		}
	}
	r.w.Stop()
}
