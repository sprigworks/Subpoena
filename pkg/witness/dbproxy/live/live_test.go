//subpoena:impl_derived
//subpoena:pure_logic

// The witness against real servers, driven by real clients, and checked against
// what the tables really hold. These start postgres and mysql containers, so
// they skip without Docker or without the images. SUBPOENA_DB_REQUIRE=1 turns a
// skip into a failure and lets Docker pull the images; `make test-db` sets it.
// They also skip under subpoena-cross, which would otherwise start containers
// for every mutant. No span is involved, so there is nothing to Collect.
package live

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sprigworks/subpoena/internal/crossmark"
	"github.com/sprigworks/subpoena/pkg/harness"
	"github.com/sprigworks/subpoena/pkg/witness/dbproxy"
)

const (
	pgImage    = "postgres:17"
	mysqlImage = "mysql:8.4"
	password   = "subpoena-test"
	trace      = "c0de00000000000000000000000000a1"
)

var required = os.Getenv("SUBPOENA_DB_REQUIRE") != ""

// skip gives up on a test, or fails it where a skip must not pass.
func skip(t *testing.T, format string, a ...any) {
	t.Helper()
	if required {
		t.Fatalf(format, a...)
	}
	t.Skipf(format, a...)
}

type container struct {
	once sync.Once
	id   string
	addr string
	err  error
	skip string
}

var (
	pgC, myC container
	names    atomic.Int64
)

func TestMain(m *testing.M) {
	code := m.Run()
	for _, c := range []*container{&pgC, &myC} {
		if c.id != "" {
			exec.Command("docker", "rm", "-f", c.id).Run()
		}
	}
	os.Exit(code)
}

// start runs image once for the whole test binary and waits for ready to pass.
func (c *container) start(t *testing.T, image string, port int, ready func(addr string) error, args ...string) string {
	t.Helper()
	if crossmark.Active {
		t.Skip("live database tests do not run under subpoena-cross")
	}
	c.once.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			c.skip = "no docker on PATH"
			return
		}
		if err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
			c.skip = "the Docker daemon is not reachable"
			return
		}
		if !required {
			if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
				c.skip = "image " + image + " is not present; SUBPOENA_DB_REQUIRE=1 pulls it"
				return
			}
		}
		run := append([]string{"run", "-d", "--rm", "-p", fmt.Sprintf("127.0.0.1::%d", port)}, args...)
		out, err := exec.Command("docker", run...).Output()
		if err != nil {
			c.err = fmt.Errorf("docker run %s: %w", image, err)
			return
		}
		c.id = strings.TrimSpace(string(out))
		out, err = exec.Command("docker", "port", c.id, fmt.Sprint(port)).Output()
		if err != nil {
			c.err = fmt.Errorf("docker port: %w", err)
			return
		}
		c.addr = strings.TrimSpace(strings.Split(string(out), "\n")[0])
		deadline := time.Now().Add(8 * time.Minute) // MySQL takes minutes to initialise on a loaded host
		for {
			if c.err = ready(c.addr); c.err == nil || time.Now().After(deadline) {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
	if c.skip != "" {
		skip(t, "%s", c.skip)
	}
	if c.err != nil {
		t.Fatalf("%s: %v", image, c.err)
	}
	return c.addr
}

func table(prefix string) string { return fmt.Sprintf("%s_%d", prefix, names.Add(1)) }

// ---- PostgreSQL ----

func pgDSN(addr, mode string) string {
	host, port, _ := net.SplitHostPort(addr)
	return fmt.Sprintf("host=%s port=%s user=postgres password=%s dbname=postgres sslmode=%s", host, port, password, mode)
}

func pgServer(t *testing.T) string {
	return pgC.start(t, pgImage, 5432, func(addr string) error {
		c, err := pgx.Connect(context.Background(), pgDSN(addr, "disable"))
		if err != nil {
			return err
		}
		return c.Close(context.Background())
	}, "-e", "POSTGRES_PASSWORD="+password, pgImage, "-c", "max_prepared_transactions=4")
}

type pgRig struct {
	t      *testing.T
	ctx    context.Context
	direct *pgx.Conn // bypasses the witness: the ground truth
	w      *dbproxy.Proxy
	table  string
}

func newPGRig(t *testing.T, opts ...string) *pgRig {
	t.Helper()
	addr := pgServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	direct, err := pgx.Connect(ctx, pgDSN(addr, "disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { direct.Close(context.Background()) })
	r := &pgRig{t: t, ctx: ctx, direct: direct, table: table("users")}
	if _, err := direct.Exec(ctx, "CREATE TABLE "+r.table+" (id int PRIMARY KEY, v text)"); err != nil {
		t.Fatal(err)
	}
	w, err := dbproxy.New(dbproxy.Config{Engine: dbproxy.Postgres, Upstream: recorded(t, addr, opts...)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Stop() })
	r.w = w
	return r
}

func (r *pgRig) connect(mode string) *pgx.Conn {
	r.t.Helper()
	c, err := pgx.Connect(r.ctx, pgDSN(r.w.Addr().String(), mode))
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func (r *pgRig) rows() int {
	r.t.Helper()
	var n int
	if err := r.direct.QueryRow(r.ctx, "SELECT count(*) FROM "+r.table).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// agree stops the witness and holds it to the truth: the table's real row count
// decides whether no-row must pass or fail, with healthy capture.
func (r *pgRig) agree(rows int) {
	r.t.Helper()
	if got := r.rows(); got != rows {
		r.t.Fatalf("the table holds %d rows, the test expected %d", got, rows)
	}
	if err := r.w.Stop(); err != nil {
		r.t.Fatalf("capture: %v", err)
	}
	agree(r.t, r.w, r.table, rows)
}

func agree(t *testing.T, w *dbproxy.Proxy, table string, rows int) {
	t.Helper()
	v, err := harness.NoRow(w, trace, table)
	if rows == 0 && v != harness.Pass {
		t.Fatalf("no rows in %s, and the witness says %v: %v", table, v, err)
	}
	if rows != 0 && v != harness.Fail {
		t.Fatalf("%d rows in %s, and the witness says %v: %v\n%+v", rows, table, v, err, w.Statements())
	}
}

func TestPostgresAutocommit(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
}

func TestPostgresPreparedAutocommit(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	// pgx's default: a named statement, cached, then Bind/Execute each time.
	for i := 1; i <= 3; i++ {
		if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES ($1, 'a')", i); err != nil {
			t.Fatal(err)
		}
	}
	r.agree(3)
	if got := r.w.Committed(trace); len(got) != 3 || got[0].Rows != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestPostgresRollbackPasses(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	tx, err := c.Begin(r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES ($1, 'a')", 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(r.ctx); err != nil {
		t.Fatal(err)
	}
	r.agree(0)
	if cov := r.w.Coverage(); cov.RolledBack != 1 || cov.Committed != 0 {
		t.Fatalf("%+v", cov)
	}
}

func TestPostgresCommit(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	tx, err := c.Begin(r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES ($1, 'a')", 1); err != nil {
		t.Fatal(err)
	}
	if got := r.w.Committed(trace); len(got) != 0 {
		t.Fatalf("reported before COMMIT: %+v", got)
	}
	if err := tx.Commit(r.ctx); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
}

func TestPostgresFailedStatementPasses(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES ($1, $2)", 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES ($1, 'dup')", 1); err == nil {
		t.Fatal("want a duplicate key error")
	}
	if r.rows() != 1 {
		t.Fatal("rows")
	}
	r.w.Stop()
	cov := r.w.Coverage()
	if cov.Committed != 1 || cov.Failed != 1 {
		t.Fatalf("%+v", cov)
	}
}

// The commit fails at COMMIT, on a deferred constraint, after the INSERT said OK.
func TestPostgresDeferredConstraintRollsBack(t *testing.T) {
	r := newPGRig(t)
	parent, child := table("parent"), table("child")
	for _, q := range []string{
		"CREATE TABLE " + parent + " (id int PRIMARY KEY)",
		"CREATE TABLE " + child + " (id int REFERENCES " + parent + " DEFERRABLE INITIALLY DEFERRED)",
	} {
		if _, err := r.direct.Exec(r.ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	c := r.connect("disable")
	tx, _ := c.Begin(r.ctx)
	if _, err := tx.Exec(r.ctx, "INSERT INTO "+child+" VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(r.ctx); err == nil {
		t.Fatal("want the commit to fail")
	}
	if err := r.w.Stop(); err != nil {
		t.Fatal(err)
	}
	harness.RequireNoRow(t, r.w, trace, child)
}

func TestPostgresPipelinedBatch(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	b := &pgx.Batch{}
	b.Queue("INSERT INTO "+r.table+" VALUES ($1, 'a')", 1)
	b.Queue("INSERT INTO "+r.table+" VALUES ($1, 'a')", 1) // duplicate: undoes the first
	b.Queue("INSERT INTO "+r.table+" VALUES ($1, 'a')", 2)
	if err := c.SendBatch(r.ctx, b).Close(); err == nil {
		t.Fatal("want a duplicate key error")
	}
	r.agree(0)

	r2 := newPGRig(t)
	c2 := r2.connect("disable")
	b2 := &pgx.Batch{}
	b2.Queue("INSERT INTO "+r2.table+" VALUES ($1, 'a')", 1)
	b2.Queue("INSERT INTO "+r2.table+" VALUES ($1, 'a')", 2)
	if err := c2.SendBatch(r2.ctx, b2).Close(); err != nil {
		t.Fatal(err)
	}
	r2.agree(2)
}

func TestPostgresMultiStatementSimpleQuery(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	mr := c.PgConn().Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a'); INSERT INTO "+r.table+" VALUES (2, 'b'); SELECT 1/0")
	if _, err := mr.ReadAll(); err == nil {
		t.Fatal("want division by zero")
	}
	r.agree(0)

	// The manual's example: the explicit COMMIT keeps the first INSERT.
	r2 := newPGRig(t)
	c2 := r2.connect("disable")
	mr = c2.PgConn().Exec(r2.ctx, "INSERT INTO "+r2.table+" VALUES (1, 'a'); COMMIT; INSERT INTO "+r2.table+" VALUES (2, 'b'); SELECT 1/0")
	if _, err := mr.ReadAll(); err == nil {
		t.Fatal("want division by zero")
	}
	r2.agree(1)
	if got := r2.w.Committed(trace); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestPostgresSavepoint(t *testing.T) {
	r := newPGRig(t)
	other := table("other")
	if _, err := r.direct.Exec(r.ctx, "CREATE TABLE "+other+" (id int)"); err != nil {
		t.Fatal(err)
	}
	c := r.connect("disable")
	tx, _ := c.Begin(r.ctx)
	if _, err := tx.Exec(r.ctx, "INSERT INTO "+other+" VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	nested, err := tx.Begin(r.ctx) // SAVEPOINT
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nested.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')"); err != nil {
		t.Fatal(err)
	}
	if err := nested.Rollback(r.ctx); err != nil { // ROLLBACK TO SAVEPOINT
		t.Fatal(err)
	}
	if err := tx.Commit(r.ctx); err != nil {
		t.Fatal(err)
	}
	r.agree(0)
	agree(t, r.w, other, 1)
}

func TestPostgresCopyFrom(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	n, err := c.CopyFrom(r.ctx, pgx.Identifier{r.table}, []string{"id", "v"},
		pgx.CopyFromRows([][]any{{1, "a"}, {2, "b"}}))
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	r.agree(2)
}

func TestPostgresZeroRowDeleteIsNoRow(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "DELETE FROM "+r.table+" WHERE id = $1", 9); err != nil {
		t.Fatal(err)
	}
	r.agree(0)
	if cov := r.w.Coverage(); cov.ZeroRow != 1 {
		t.Fatalf("%+v", cov)
	}
}

// A function writes behind a SELECT: the text cannot say where, so it counts
// against every table, including one it did not touch.
func TestPostgresFunctionBehindSelectOverReports(t *testing.T) {
	r := newPGRig(t)
	fn := table("write_it")
	if _, err := r.direct.Exec(r.ctx, "CREATE FUNCTION "+fn+"() RETURNS void LANGUAGE sql AS $$ INSERT INTO "+r.table+" VALUES (1, 'a') $$"); err != nil {
		t.Fatal(err)
	}
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "SELECT "+fn+"()"); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
	if v, _ := harness.NoRow(r.w, trace, "some_other_table"); v != harness.Fail {
		t.Fatalf("opaque must count against every table: %v", v)
	}
}

func TestPostgresDoBlockOverReports(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "DO $$ BEGIN INSERT INTO "+r.table+" VALUES (1, 'a'); END $$"); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
}

func TestPostgresSQLLevelPrepareOverReports(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	for _, q := range []string{"PREPARE p AS INSERT INTO " + r.table + " VALUES (1, 'a')", "EXECUTE p"} {
		if _, err := c.Exec(r.ctx, q, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
	}
	r.agree(1)
}

func TestPostgresPreparedTransaction(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	for _, q := range []string{"BEGIN", "INSERT INTO " + r.table + " VALUES (1, 'a')", "PREPARE TRANSACTION 'x" + r.table + "'"} {
		if _, err := c.Exec(r.ctx, q, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.direct.Exec(r.ctx, "COMMIT PREPARED 'x"+r.table+"'"); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
}

func TestPostgresTLSPreferredGoesOnInTheClear(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("prefer")
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')"); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
	if cov := r.w.Coverage(); cov.TLSRefused == 0 {
		t.Fatalf("%+v", cov)
	}
}

func TestPostgresTLSRequiredIsInconclusive(t *testing.T) {
	r := newPGRig(t)
	if c, err := pgx.Connect(r.ctx, pgDSN(r.w.Addr().String(), "require")); err == nil {
		c.Close(r.ctx)
		t.Fatal("a client requiring TLS must not get a connection")
	}
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
}

func TestPostgresTerminateRollsBack(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "BEGIN", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	c.Close(r.ctx) // Terminate
	waitNoBackend(r)
	r.agree(0)
}

// waitNoBackend waits until the server has undone the closed connection's work.
func waitNoBackend(r *pgRig) {
	r.t.Helper()
	for i := 0; i < 500; i++ {
		var n int
		if err := r.direct.QueryRow(r.ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'").Scan(&n); err != nil {
			r.t.Fatal(err)
		}
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPostgresClientDropMidTransactionIsInconclusive(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "BEGIN", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	c.PgConn().Conn().Close() // no Terminate
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
	if cov := r.w.Coverage(); cov.Unknown != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestPostgresServerKillsTransactionIsInconclusive(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	pid := c.PgConn().PID()
	if _, err := c.Exec(r.ctx, "BEGIN", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := r.direct.Exec(r.ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(r.ctx, "SELECT 1", pgx.QueryExecModeSimpleProtocol); err == nil {
		t.Fatal("want the connection gone")
	}
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
}

func TestPostgresCancelRequestPasses(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	errs := make(chan error, 1)
	go func() {
		_, err := c.Exec(r.ctx, "SELECT pg_sleep(30)", pgx.QueryExecModeSimpleProtocol)
		errs <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancelled := false
	for i := 0; i < 20 && !cancelled; i++ {
		// pgconn's CancelRequest dials the address the connection was made to.
		if err := c.PgConn().CancelRequest(r.ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-errs:
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "57014" {
				t.Fatalf("want query_canceled, got %v", err)
			}
			cancelled = true
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !cancelled {
		t.Fatal("the cancel did not reach the server")
	}
	r.agree(0)
}

func TestPostgresMarkHidesSetup(t *testing.T) {
	r := newPGRig(t)
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'seed')"); err != nil {
		t.Fatal(err)
	}
	r.w.Mark()
	if err := r.w.Stop(); err != nil {
		t.Fatal(err)
	}
	harness.RequireNoRow(t, r.w, trace, r.table)
}

func TestPostgresPoolIdleConnectionsAreClean(t *testing.T) {
	r := newPGRig(t)
	r.connect("disable")
	r.connect("disable")
	r.agree(0)
	if cov := r.w.Coverage(); cov.Connections != 2 {
		t.Fatalf("%+v", cov)
	}
}

func TestPostgresWatchRows(t *testing.T) {
	r := newPGRig(t)
	harness.WatchRows(t, r.w, trace, harness.RowRule{Allowed: []string{r.table}, Never: []string{"secrets"}})
	c := r.connect("disable")
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (1, 'a')"); err != nil {
		t.Fatal(err)
	}
}

// docker runs a client from the image on the host network, so it can reach the
// witness's loopback listener.
func dockerClient(t *testing.T, image string, env []string, args ...string) (string, error) {
	t.Helper()
	run := []string{"run", "--rm", "--network", "host"}
	for _, e := range env {
		run = append(run, "-e", e)
	}
	run = append(append(run, image), args...)
	out, err := exec.Command("docker", run...).CombinedOutput()
	return string(out), err
}

// psql, libpq's own client: extended protocol is pgx's above, this is the simple
// one, with its startup.
func TestPostgresPsqlClient(t *testing.T) {
	r := newPGRig(t, "postgres-psql")
	host, port, _ := net.SplitHostPort(r.w.Addr().String())
	script := "BEGIN; INSERT INTO " + r.table + " VALUES (1, 'a'); ROLLBACK; INSERT INTO " + r.table + " VALUES (2, 'b');"
	out, err := dockerClient(t, pgImage, []string{"PGPASSWORD=" + password, "PGSSLMODE=prefer"},
		"psql", "-h", host, "-p", port, "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", script)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	r.agree(1)
	if cov := r.w.Coverage(); cov.Committed != 1 || cov.RolledBack != 1 {
		t.Fatalf("%+v", cov)
	}
}

// One session of each kind for the parent package's replay tests: see
// recorded_test.go there, whose expectations these statements must match.
func TestPostgresRecordedSession(t *testing.T) {
	r := newPGRig(t, "postgres-pgx")
	c := r.connect("disable")
	simple := pgx.QueryExecModeSimpleProtocol
	steps := func(sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(r.ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	steps("INSERT INTO "+r.table+" VALUES (1, 'autocommit')", simple)
	steps("INSERT INTO "+r.table+" VALUES ($1, 'prepared')", 2)
	steps("INSERT INTO "+r.table+" VALUES ($1, 'prepared')", 3)
	steps("BEGIN", simple)
	steps("UPDATE "+r.table+" SET v = 'x' WHERE id = 1", simple)
	steps("ROLLBACK", simple)
	steps("BEGIN", simple)
	steps("DELETE FROM "+r.table+" WHERE id = 1", simple)
	steps("COMMIT", simple)
	if _, err := c.Exec(r.ctx, "INSERT INTO "+r.table+" VALUES (2, 'duplicate')", simple); err == nil {
		t.Fatal("want a duplicate key error")
	}
	var n int
	if err := c.QueryRow(r.ctx, "SELECT count(*) FROM "+r.table).Scan(&n); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	r.agree(2)
}

// ---- MySQL ----

func myDSN(addr string, extra string) string {
	return "root:" + password + "@tcp(" + addr + ")/app?" + extra
}

func mysqlServer(t *testing.T) string {
	mysqldrv.SetLogger(discardLog{}) // it logs every EOF while the server starts
	return myC.start(t, mysqlImage, 3306, func(addr string) error {
		db, err := sql.Open("mysql", myDSN(addr, ""))
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	}, "-e", "MYSQL_ROOT_PASSWORD="+password, "-e", "MYSQL_DATABASE=app", mysqlImage)
}

type myRig struct {
	t      *testing.T
	ctx    context.Context
	direct *sql.DB
	w      *dbproxy.Proxy
	table  string
}

func newMyRig(t *testing.T, opts ...string) *myRig {
	t.Helper()
	addr := mysqlServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	direct, err := sql.Open("mysql", myDSN(addr, "multiStatements=true"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { direct.Close() })
	r := &myRig{t: t, ctx: ctx, direct: direct, table: table("users")}
	if _, err := direct.Exec("CREATE TABLE " + r.table + " (id int PRIMARY KEY, v varchar(20)) ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}
	w, err := dbproxy.New(dbproxy.Config{Engine: dbproxy.MySQL, Upstream: recorded(t, addr, opts...)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Stop() })
	r.w = w
	return r
}

type discardLog struct{}

func (discardLog) Print(...any) {}

// conn is one connection through the witness, closed before the capture ends.
func (r *myRig) conn(extra string) *sql.DB {
	r.t.Helper()
	db, err := sql.Open("mysql", myDSN(r.w.Addr().String(), extra))
	if err != nil {
		r.t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	r.t.Cleanup(func() { db.Close() })
	return db
}

func (r *myRig) rows() int {
	r.t.Helper()
	var n int
	if err := r.direct.QueryRow("SELECT count(*) FROM " + r.table).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *myRig) agree(rows int) {
	r.t.Helper()
	if got := r.rows(); got != rows {
		r.t.Fatalf("the table holds %d rows, the test expected %d", got, rows)
	}
	if err := r.w.Stop(); err != nil {
		r.t.Fatalf("capture: %v", err)
	}
	agree(r.t, r.w, r.table, rows)
}

func must(t *testing.T, db interface {
	Exec(string, ...any) (sql.Result, error)
}, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestMySQLAutocommit(t *testing.T) {
	r := newMyRig(t)
	must(t, r.conn(""), "INSERT INTO "+r.table+" VALUES (1, 'a')")
	r.agree(1)
}

// With arguments and no interpolation the driver uses COM_STMT_PREPARE/EXECUTE.
func TestMySQLPrepared(t *testing.T) {
	r := newMyRig(t)
	db := r.conn("")
	st, err := db.Prepare("INSERT INTO " + r.table + " VALUES (?, 'a')")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := st.Exec(i); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	r.agree(3)
	if got := r.w.Committed(trace); len(got) != 3 || got[0].Rows != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestMySQLPreparedSelect(t *testing.T) {
	r := newMyRig(t)
	db := r.conn("")
	must(t, r.direct, "INSERT INTO "+r.table+" VALUES (1, 'a'), (2, 'b')")
	var v string
	if err := db.QueryRow("SELECT v FROM "+r.table+" WHERE id = ?", 2).Scan(&v); err != nil || v != "b" {
		t.Fatal(v, err)
	}
	r.w.Stop()
	if err := r.w.Health(); err != nil {
		t.Fatal(err)
	}
	harness.RequireNoRow(t, r.w, trace, r.table)
}

func TestMySQLRollbackPasses(t *testing.T) {
	r := newMyRig(t)
	tx, err := r.conn("").Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "INSERT INTO "+r.table+" VALUES (?, 'a')", 1)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	r.agree(0)
	if cov := r.w.Coverage(); cov.RolledBack != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestMySQLCommit(t *testing.T) {
	r := newMyRig(t)
	tx, err := r.conn("").Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "INSERT INTO "+r.table+" VALUES (1, 'a')")
	if got := r.w.Committed(trace); len(got) != 0 {
		t.Fatalf("reported before COMMIT: %+v", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r.agree(1)
}

func TestMySQLSavepoint(t *testing.T) {
	r := newMyRig(t)
	other := table("other")
	must(t, r.direct, "CREATE TABLE "+other+" (id int)")
	tx, err := r.conn("").Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "INSERT INTO "+other+" VALUES (1)")
	must(t, tx, "SAVEPOINT s")
	must(t, tx, "INSERT INTO "+r.table+" VALUES (1, 'a')")
	must(t, tx, "ROLLBACK TO SAVEPOINT s")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r.agree(0)
	agree(t, r.w, other, 1)
}

func TestMySQLAutocommitOff(t *testing.T) {
	r := newMyRig(t)
	db := r.conn("autocommit=0")
	must(t, db, "INSERT INTO "+r.table+" VALUES (1, 'a')")
	if got := r.w.Committed(trace); len(got) != 0 {
		t.Fatalf("reported before COMMIT: %+v", got)
	}
	must(t, db, "COMMIT")
	r.agree(1)
}

func TestMySQLImplicitCommitByDDL(t *testing.T) {
	r := newMyRig(t)
	tx, err := r.conn("").Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "INSERT INTO "+r.table+" VALUES (1, 'a')")
	must(t, tx, "CREATE TABLE "+table("ddl")+" (id int)") // commits the INSERT
	tx.Rollback()                                         // too late
	r.agree(1)
}

// MyISAM ignores ROLLBACK, and the server warns.
func TestMySQLRollbackOfNonTransactionalTable(t *testing.T) {
	r := newMyRig(t)
	plain := table("plain")
	must(t, r.direct, "CREATE TABLE "+plain+" (id int) ENGINE=MyISAM")
	tx, err := r.conn("").Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "INSERT INTO "+plain+" VALUES (1)")
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := r.direct.QueryRow("SELECT count(*) FROM " + plain).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err := r.w.Stop(); err != nil {
		t.Fatal(err)
	}
	agree(t, r.w, plain, 1)
}

func TestMySQLMultiStatement(t *testing.T) {
	r := newMyRig(t)
	db := r.conn("multiStatements=true")
	must(t, db, "INSERT INTO "+r.table+" VALUES (1, 'a'); UPDATE "+r.table+" SET v = 'b'; DELETE FROM "+r.table+" WHERE id = 9")
	r.agree(1)
	if got := r.w.Committed(trace); len(got) != 3 || got[2].Rows != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestMySQLFailedStatementPasses(t *testing.T) {
	r := newMyRig(t)
	db := r.conn("")
	if _, err := db.Exec("INSERT INTO no_such_table VALUES (1)"); err == nil {
		t.Fatal("want an error")
	}
	r.agree(0)
	if cov := r.w.Coverage(); cov.Failed != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestMySQLStoredProcedureOverReports(t *testing.T) {
	r := newMyRig(t)
	proc := table("write_it")
	must(t, r.direct, "CREATE PROCEDURE "+proc+"() INSERT INTO "+r.table+" VALUES (1, 'a')")
	must(t, r.conn(""), "CALL "+proc+"()")
	r.agree(1)
	if v, _ := harness.NoRow(r.w, trace, "some_other_table"); v != harness.Fail {
		t.Fatalf("opaque must count against every table: %v", v)
	}
}

// MySQL runs the inside of a /*! comment.
func TestMySQLExecutableCommentOverReports(t *testing.T) {
	r := newMyRig(t)
	must(t, r.conn(""), "/*! INSERT INTO "+r.table+" VALUES (1, 'a') */")
	r.agree(1)
}

func TestMySQLLocalInfile(t *testing.T) {
	r := newMyRig(t)
	must(t, r.direct, "SET GLOBAL local_infile = 1")
	mysqldrv.RegisterReaderHandler("rows", func() io.Reader { return strings.NewReader("1\ta\n2\tb\n") })
	defer mysqldrv.DeregisterReaderHandler("rows")
	must(t, r.conn(""), "LOAD DATA LOCAL INFILE 'Reader::rows' INTO TABLE "+r.table)
	r.agree(2)
}

func TestMySQLTLSPreferredGoesOnInTheClear(t *testing.T) {
	r := newMyRig(t)
	must(t, r.conn("tls=preferred"), "INSERT INTO "+r.table+" VALUES (1, 'a')")
	r.agree(1)
	if cov := r.w.Coverage(); cov.TLSRefused == 0 {
		t.Fatalf("%+v", cov)
	}
}

func TestMySQLTLSRequiredIsInconclusive(t *testing.T) {
	r := newMyRig(t)
	if err := r.conn("tls=skip-verify").Ping(); err == nil {
		t.Fatal("a client requiring TLS must not get a connection")
	}
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
}

func TestMySQLClientDropMidTransactionIsInconclusive(t *testing.T) {
	r := newMyRig(t)
	// A raw dialer, so the socket can be dropped with no COM_QUIT.
	var raw net.Conn
	name := table("dial")
	mysqldrv.RegisterDialContext(name, func(ctx context.Context, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		raw = c
		return c, err
	})
	db, err := sql.Open("mysql", "root:"+password+"@"+name+"("+r.w.Addr().String()+")/app")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "INSERT INTO "+r.table+" VALUES (1, 'a')")
	raw.Close()
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
	if cov := r.w.Coverage(); cov.Unknown != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestMySQLServerKillsTransactionIsInconclusive(t *testing.T) {
	r := newMyRig(t)
	ctx := r.ctx
	db := r.conn("")
	c, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var id int
	if err := c.QueryRowContext(ctx, "SELECT connection_id()").Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"BEGIN", "INSERT INTO " + r.table + " VALUES (1, 'a')"} {
		if _, err := c.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	must(t, r.direct, fmt.Sprintf("KILL %d", id))
	if _, err := c.ExecContext(ctx, "SELECT 1"); err == nil {
		t.Fatal("want the connection gone")
	}
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
}

// See TestPostgresRecordedSession.
func TestMySQLRecordedSession(t *testing.T) {
	r := newMyRig(t, "mysql-driver")
	db := r.conn("")
	must(t, db, "INSERT INTO "+r.table+" VALUES (1, 'autocommit')")
	st, err := db.Prepare("INSERT INTO " + r.table + " VALUES (?, 'prepared')")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int{2, 3} {
		if _, err := st.Exec(id); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "UPDATE "+r.table+" SET v = 'x' WHERE id = 1")
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	must(t, tx, "DELETE FROM "+r.table+" WHERE id = 1")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO " + r.table + " VALUES (2, 'duplicate')"); err == nil {
		t.Fatal("want a duplicate key error")
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + r.table).Scan(&n); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	r.agree(2)
}

func TestMySQLWatchRows(t *testing.T) {
	r := newMyRig(t)
	harness.WatchRows(t, r.w, trace, harness.RowRule{Allowed: []string{r.table}, Never: []string{"secrets"}})
	must(t, r.conn(""), "INSERT INTO "+r.table+" VALUES (1, 'a')")
}

// The mysql client, which negotiates CLIENT_DEPRECATE_EOF, unlike the Go driver,
// and would use query attributes if they were left in the greeting.
func TestMySQLCommandLineClient(t *testing.T) {
	r := newMyRig(t, "mysql-cli")
	host, port, _ := net.SplitHostPort(r.w.Addr().String())
	script := "SELECT 1; BEGIN; INSERT INTO " + r.table + " VALUES (1, 'a'); ROLLBACK; INSERT INTO " + r.table + " VALUES (2, 'b'); SELECT * FROM " + r.table + ";"
	out, err := dockerClient(t, mysqlImage, []string{"MYSQL_PWD=" + password}, "mysql", "-h", host, "-P", port, "-uroot",
		"--protocol=tcp", "--ssl-mode=PREFERRED", "--get-server-public-key", "app", "-e", script)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	r.agree(1)
	if cov := r.w.Coverage(); cov.Committed != 1 || cov.RolledBack != 1 {
		t.Fatalf("%+v", cov)
	}
}

func TestMySQLCommandLineClientRequiringTLS(t *testing.T) {
	r := newMyRig(t)
	host, port, _ := net.SplitHostPort(r.w.Addr().String())
	out, err := dockerClient(t, mysqlImage, []string{"MYSQL_PWD=" + password}, "mysql", "-h", host, "-P", port, "-uroot",
		"--protocol=tcp", "--ssl-mode=REQUIRED", "app", "-e", "SELECT 1")
	if err == nil {
		t.Fatalf("a client requiring TLS must not get through: %s", out)
	}
	r.w.Stop()
	if v, err := harness.NoRow(r.w, trace, r.table); v != harness.Inconclusive {
		t.Fatalf("%v, %v", v, err)
	}
}
