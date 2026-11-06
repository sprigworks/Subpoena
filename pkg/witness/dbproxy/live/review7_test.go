//subpoena:impl_derived
//subpoena:pure_logic

// Round 2 review 7 against real servers. A false pass here is a row present on a
// direct connection that the witness must not pass; a false Fail is no row in the
// claimed table that it must. The stated limits are pinned at the end, so that
// closing one has to change the docs too. No span is involved, so there is
// nothing to Collect.
package live

import (
	"context"
	"database/sql"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sprigworks/subpoena/pkg/harness"
)

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

func TestReview7PostgresFalsePasses(t *testing.T) {
	one := func(r *pgRig) string {
		n := "one_" + r.table
		r.direct1("CREATE TABLE " + n + " (a int); INSERT INTO " + n + " VALUES (1)")
		return n
	}
	domain := func(r *pgRig, name string) {
		r.writer("w_"+r.table, "int")
		r.direct1("CREATE DOMAIN " + name + " AS int CHECK (w_" + r.table + "(VALUE) = 1)")
		r.cleanup("DROP DOMAIN " + name)
	}
	cases := map[string]func(r *pgRig){
		// H2
		"SET search_path, an E string": func(r *pgRig) {
			s := r.shadow()
			c := r.connect("disable")
			sent(c, "SET search_path = "+s+`, E'pg\x5fcatalog', public`)
			sent(c, "SELECT lower('x')")
		},
		"SET search_path, a dollar quote": func(r *pgRig) {
			s := r.shadow()
			c := r.connect("disable")
			sent(c, "SET search_path = "+s+`, $$pg_catalog$$, public`)
			sent(c, "SELECT lower('x')")
		},
		"SET of a quoted upper-case name": func(r *pgRig) {
			s := r.shadow()
			c := r.connect("disable")
			sent(c, `SET "SEARCH_PATH" = `+s+`, pg_catalog, public`)
			sent(c, "SELECT lower('x')")
		},
		"login SEARCH_PATH": func(r *pgRig) {
			s := r.shadow()
			sent(r.login(map[string]string{"SEARCH_PATH": s + ",pg_catalog,public"}), "SELECT lower('x')")
		},
		"login options search-path": func(r *pgRig) {
			s := r.shadow()
			sent(r.login(map[string]string{"options": "-c search-path=" + s + ",pg_catalog,public"}), "SELECT lower('x')")
		},
		"login options, escaped": func(r *pgRig) {
			s := r.shadow()
			sent(r.login(map[string]string{"options": `--search\_path=` + s + `,pg\_catalog,public`}), "SELECT lower('x')")
		},
		// H3
		"ORDER BY rollup()": func(r *pgRig) {
			r.writer("rollup", "int")
			r.cleanup("DROP FUNCTION rollup(int)")
			sent(r.connect("disable"), "SELECT 1 AS a ORDER BY rollup(1)")
		},
		"ORDER BY cube()": func(r *pgRig) {
			r.writer("cube", "int")
			r.cleanup("DROP FUNCTION cube(int)")
			sent(r.connect("disable"), "SELECT 1 AS a ORDER BY cube(1)")
		},
		"JOIN ON conflict()": func(r *pgRig) {
			n := one(r)
			r.writer("conflict", "int")
			r.cleanup("DROP FUNCTION conflict(int)")
			sent(r.connect("disable"), "SELECT 1 FROM "+n+" a JOIN "+n+" b ON conflict(1) = 1")
		},
		"CASE THEN insert()": func(r *pgRig) {
			n := one(r)
			r.writer("insert", "int")
			r.cleanup("DROP FUNCTION insert(int)")
			sent(r.connect("disable"), "UPDATE "+n+" SET a = CASE WHEN true THEN insert(1) ELSE 0 END")
		},
		"DISTINCT ON then over()": func(r *pgRig) {
			r.writer("over", "int")
			r.cleanup("DROP FUNCTION over(int)")
			sent(r.connect("disable"), "SELECT DISTINCT ON (1) over(1)")
		},
		"NOT like()": func(r *pgRig) {
			r.writer("\"like\"", "int, int")
			r.cleanup(`DROP FUNCTION "like"(int, int)`)
			sent(r.connect("disable"), "SELECT 1 WHERE NOT like(1, 2) = 1")
		},
		// M1
		"a routine swaps a prepared name": func(r *pgRig) {
			f := "rp_" + r.table
			r.direct1("CREATE FUNCTION " + f + "() RETURNS int LANGUAGE plpgsql AS $f$ BEGIN EXECUTE 'DEALLOCATE s7'; EXECUTE $q$PREPARE s7 AS WITH d AS (" + r.ins() + " RETURNING 1) SELECT 1$q$; RETURN 1; END $f$")
			c := r.connect("disable")
			if _, err := c.Prepare(r.ctx, "s7", "SELECT 1"); err != nil {
				r.t.Fatal(err)
			}
			sent(c, "BEGIN; SELECT "+f+"(); ROLLBACK")
			if res := c.PgConn().ExecPrepared(r.ctx, "s7", nil, nil, nil).Read(); res.Err != nil {
				r.t.Fatal(res.Err)
			}
		},
		// M2
		"a domain named double": func(r *pgRig) {
			domain(r, "double")
			sent(r.connect("disable"), "SELECT 1::double")
		},
		"a domain named x": func(r *pgRig) {
			domain(r, "x")
			sent(r.connect("disable"), "SELECT x '1'")
		},
		"a domain named zone": func(r *pgRig) {
			domain(r, "zone")
			sent(r.connect("disable"), "SELECT zone '1'")
		},
		// H8, in the forms the wire can show
		"ALTER child INHERIT parent": func(r *pgRig) {
			r.direct1("CREATE TABLE c_" + r.table + " (id int NOT NULL, v text); INSERT INTO c_" + r.table + " VALUES (1,'a')")
			sent(r.connect("disable"), "ALTER TABLE c_"+r.table+" INHERIT "+r.table)
		},
		"CREATE TABLE INHERITS, then a write to the child": func(r *pgRig) {
			c := r.connect("disable")
			sent(c, "CREATE TABLE c_"+r.table+" () INHERITS ("+r.table+")")
			sent(c, "INSERT INTO c_"+r.table+" VALUES (1, 'a')")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			r := newPGRig(t)
			run(r)
			if v := r.verdict(1); v != harness.Fail {
				t.Fatalf("a row is there, and the witness says %v: %+v", v, r.w.Statements())
			}
		})
	}
	t.Run("SET SCHEMA", func(t *testing.T) {
		r := newPGRig(t)
		s, n := "st_"+r.table, "m_"+r.table
		r.direct1("CREATE SCHEMA " + s + "; CREATE TABLE " + s + "." + n + " (id int); INSERT INTO " + s + "." + n + " VALUES (1)")
		r.cleanup("DROP TABLE public." + n)
		sent(r.connect("disable"), "ALTER TABLE "+s+"."+n+" SET SCHEMA public")
		if got := r.count("public." + n); got != 1 {
			t.Fatal(got)
		}
		r.w.Stop()
		if v, _ := harness.NoRow(r.w, trace, "public."+n); v != harness.Fail {
			t.Fatalf("%v: %+v", v, r.w.Statements())
		}
	})
	t.Run("ATTACH PARTITION", func(t *testing.T) {
		r := newPGRig(t)
		p := "p_" + r.table
		r.direct1("CREATE TABLE " + p + " (id int) PARTITION BY RANGE (id); CREATE TABLE " + p + "_a (id int); INSERT INTO " + p + "_a VALUES (1)")
		r.cleanup("DROP TABLE " + p)
		sent(r.connect("disable"), "ALTER TABLE "+p+" ATTACH PARTITION "+p+"_a FOR VALUES FROM (0) TO (10)")
		if got := r.count(p); got != 1 {
			t.Fatal(got)
		}
		r.w.Stop()
		if v, _ := harness.NoRow(r.w, trace, p); v != harness.Fail {
			t.Fatalf("%v: %+v", v, r.w.Statements())
		}
	})
}

// What an application, a driver or a client sends, with no row in the claimed
// table. TBL is the claimed table and OTHER another one.
func TestReview7PostgresFalseFails(t *testing.T) {
	for name, q := range map[string]string{
		// F1
		"bare JOIN of a subquery":  "SELECT 1 FROM TBL a JOIN (SELECT 1 AS id) b ON a.id = b.id",
		"chained JOINs":            "SELECT 1 FROM TBL a JOIN (SELECT 1 AS id) b ON true JOIN (SELECT 1 AS id) c ON c.id = b.id",
		"alias column list":        "SELECT id FROM unnest(ARRAY[1,2]) AS t(id)",
		"alias list with no AS":    "SELECT id FROM unnest(ARRAY[1,2]) t(id)",
		"values alias":             "SELECT * FROM (VALUES (1, 'a')) AS v(id, x)",
		"bulk update":              "UPDATE OTHER SET id = v.id FROM (VALUES (1)) AS v(id) WHERE OTHER.id = v.id",
		"quoted bulk update":       `UPDATE "OTHER" SET "id" = "d"."id" FROM (VALUES (1)) AS "d"("id") WHERE "OTHER"."id" = "d"."id"`,
		"CTE column list":          "WITH t(a) AS (SELECT 1) SELECT a FROM t",
		"recursive CTE":            "WITH RECURSIVE t(a) AS (SELECT 1 UNION ALL SELECT a + 1 FROM t WHERE a < 3) SELECT a FROM t",
		"NOT MATERIALIZED":         "WITH t AS NOT MATERIALIZED (SELECT 1 AS a) SELECT a FROM t",
		"insert alias and columns": "INSERT INTO OTHER AS u (id) VALUES (1)",
		"upsert on an alias":       "INSERT INTO OTHER AS u (id) VALUES (1) ON CONFLICT DO NOTHING",
		"LIKE of a parenthesis":    "SELECT id FROM TBL WHERE v LIKE ('a%')",
		"NOT LIKE of one":          "SELECT id FROM TBL WHERE v NOT LIKE ('a%')",
		"trim both":                "SELECT trim(both 'x' from 'xax')",
		"AT TIME ZONE":             "SELECT now() AT TIME ZONE 'UTC' - interval '1 day'",
		// ORM shapes
		"gorm":       `SELECT "TBL"."id" FROM "TBL" WHERE "TBL"."id" = 1 ORDER BY "TBL"."id" LIMIT 1`,
		"Prisma":     `SELECT "public"."TBL"."id" FROM "public"."TBL" WHERE ("public"."TBL"."id" = 1 AND 1=1) LIMIT 1 OFFSET 0`,
		"Hibernate":  `select t1_0.id from TBL t1_0 join (select o.id from OTHER o where o.id=1) s1_0 on t1_0.id=s1_0.id where t1_0.id=any(array[1]) for no key update`,
		"Rails":      `SELECT "TBL".* FROM "TBL" INNER JOIN (SELECT "OTHER"."id" FROM "OTHER") "x" ON "x"."id" = "TBL"."id" LIMIT 1`,
		"Django":     `SELECT "t0"."id", COUNT(*) AS "__count" FROM "TBL" AS "t0" LEFT OUTER JOIN "OTHER" AS "o1" ON "o1"."id" = "t0"."id" GROUP BY "t0"."id" HAVING COUNT(*) > 1`,
		"Ecto":       `SELECT t0."id" FROM "TBL" AS t0 LEFT OUTER JOIN LATERAL (SELECT 1 AS a) AS s1 ON TRUE WHERE (t0."id" = ANY(ARRAY[1])) FOR UPDATE SKIP LOCKED`,
		"SQLAlchemy": `INSERT INTO OTHER (id) SELECT p0::int FROM (VALUES (1, 0), (2, 1)) AS imp_sen(p0, sen_counter) ORDER BY sen_counter RETURNING OTHER.id`,
		// L1
		"regclass": "SELECT 'TBL'::regclass",
		"oid":      "SELECT 1::oid",
		"name":     "SELECT 'a'::name",
		"inet":     "SELECT '127.0.0.1'::inet",
		"#>>":      `SELECT '{"a":1}'::jsonb #>> '{a}'`,
		"?":        `SELECT '{"a":1}'::jsonb ? 'a'`,
		"&&":       "SELECT ARRAY[1] && ARRAY[1]",
		"@@":       "SELECT 'a b'::tsvector @@ 'a'::tsquery",
		"&":        "SELECT 5 & 1",
		"loadtype": "select $$text$$::text::regtype::oid",
	} {
		t.Run(name, func(t *testing.T) {
			r := newPGRig(t)
			o := "o_" + r.table
			r.direct1("CREATE TABLE " + o + " (id int PRIMARY KEY)")
			c := r.connect("disable")
			if _, err := c.Exec(r.ctx, strings.ReplaceAll(strings.ReplaceAll(q, "TBL", r.table), "OTHER", o)); err != nil {
				t.Fatal(err)
			}
			c.Close(context.Background())
			if v := r.verdict(0); v != harness.Pass {
				t.Fatalf("no row, and the witness says %v: %+v", v, r.w.Statements())
			}
		})
	}
	t.Run("pgx LoadType", func(t *testing.T) {
		r := newPGRig(t)
		ty := "mood_" + r.table
		r.direct1("CREATE TYPE " + ty + " AS ENUM ('a')")
		c := r.connect("disable")
		if _, err := c.LoadType(r.ctx, ty); err != nil {
			t.Fatal(err)
		}
		c.Close(context.Background())
		if v := r.verdict(0); v != harness.Pass {
			t.Fatalf("%v: %+v", v, r.w.Statements())
		}
	})
	for _, cmd := range []string{`\dt`, `\d TBL`, `\l`} {
		t.Run("psql "+cmd, func(t *testing.T) {
			r := newPGRig(t)
			host, port, _ := net.SplitHostPort(r.w.Addr().String())
			out, err := dockerClient(t, pgImage, []string{"PGPASSWORD=" + password, "PGSSLMODE=prefer"},
				"psql", "-h", host, "-p", port, "-U", "postgres", "-d", "postgres", "-c", strings.ReplaceAll(cmd, "TBL", r.table))
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if v := r.verdict(0); v != harness.Pass {
				for _, e := range r.w.Statements() {
					if e.Opaque {
						t.Logf("%s: %.300s", e.Reason, e.Statement)
					}
				}
				t.Fatalf("no row, and the witness says %v", v)
			}
		})
	}
	for name, q := range map[string]string{
		"a safe search path at login": "-c search_path=public",
		"a safe setting at login":     "-c statement_timeout=5000",
	} {
		t.Run(name, func(t *testing.T) {
			r := newPGRig(t)
			c := r.login(map[string]string{"options": q})
			sent(c, "SELECT lower('x')")
			c.Close(context.Background())
			if v := r.verdict(0); v != harness.Pass {
				t.Fatalf("%v: %+v", v, r.w.Statements())
			}
		})
	}
}

func listed(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile("../testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// The lists are only as good as what the server says of them: every keyword it has
// is known, and everything listed as inert is a stable or immutable catalog
// routine, except the few named here, whose side effects are not on rows.
func TestReview7ListsAgainstTheServer(t *testing.T) {
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

func TestReview7MySQLFalsePasses(t *testing.T) {
	fn := func(r *myRig) string {
		f := "f_" + r.table
		must(r.t, r.direct, "CREATE FUNCTION "+f+"() RETURNS int DETERMINISTIC MODIFIES SQL DATA BEGIN "+r.ins()+"; RETURN 1; END")
		return f
	}
	hidden := func(r *myRig, db *sql.DB, set string) {
		f := fn(r)
		must(r.t, db, set)
		var m string
		if err := db.QueryRow("SELECT @@sql_mode").Scan(&m); err != nil || !strings.Contains(m, "ANSI_QUOTES") {
			r.t.Fatalf("the mode did not take: %q %v", m, err)
		}
		must(r.t, db, `SELECT 1 AS "\", `+f+`() -- "`)
	}
	cases := map[string]func(r *myRig, db *sql.DB){
		// H1
		"sql_mode with an escape": func(r *myRig, db *sql.DB) { hidden(r, db, `SET sql_mode='A\NSI_QUOTES'`) },
		"sql_mode in backticks":   func(r *myRig, db *sql.DB) { hidden(r, db, "SET `sql_mode`='ANSI_QUOTES'") },
		"sql_mode by number":      func(r *myRig, db *sql.DB) { hidden(r, db, "SET sql_mode=4") },
		"sql_mode with a charset": func(r *myRig, db *sql.DB) { hidden(r, db, "SET sql_mode=_utf8mb4'ANSI_QUOTES'") },
		"sql_mode by @@": func(r *myRig, db *sql.DB) {
			hidden(r, db, "SET @@`sql_mode` := CONCAT(@@sql_mode, ',ANSI_QUOTES')")
		},
		"character_set_client in backticks": func(r *myRig, db *sql.DB) {
			f := fn(r)
			must(r.t, db, "SET `character_set_client`=gbk")
			// 0xBF takes the backslash into one character, so the quote closes the string.
			must(r.t, db, "SELECT '\xbf\\', "+f+"() -- '")
		},
		// H5
		"LOCK TABLES fails after its commit": func(r *myRig, db *sql.DB) {
			must(r.t, db, "START TRANSACTION")
			must(r.t, db, r.ins())
			if _, err := db.Exec("LOCK TABLES no_such_" + r.table + " WRITE"); err == nil {
				r.t.Fatal("LOCK TABLES of no table worked")
			}
			must(r.t, db, "ROLLBACK")
		},
		// H6
		"savepoint replaced in another case": func(r *myRig, db *sql.DB) {
			for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", r.ins(), "SAVEPOINT `A`", "ROLLBACK TO a", "COMMIT"} {
				must(r.t, db, q)
			}
		},
		"savepoint replaced under an accent": func(r *myRig, db *sql.DB) {
			for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", r.ins(), "SAVEPOINT `á`", "ROLLBACK TO a", "COMMIT"} {
				must(r.t, db, q)
			}
		},
		// H7
		"LOAD DATA SET of a function": func(r *myRig, db *sql.DB) {
			f := fn(r)
			must(r.t, r.direct, "CREATE TABLE z_"+r.table+" (a int, b int)")
			if out, err := exec.Command("docker", "exec", myC.id, "sh", "-c", "echo 1 > /var/lib/mysql-files/r7.txt").CombinedOutput(); err != nil {
				r.t.Fatalf("%v %s", err, out)
			}
			must(r.t, db, "LOAD DATA INFILE '/var/lib/mysql-files/r7.txt' INTO TABLE z_"+r.table+" (a) SET b = "+f+"()")
		},
		// A rollback to a savepoint and a rollback, on a table that keeps its rows.
		"MyISAM through a savepoint": func(r *myRig, db *sql.DB) {
			must(r.t, r.direct, "ALTER TABLE "+r.table+" ENGINE=MyISAM")
			for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", r.ins(), "ROLLBACK TO a", "ROLLBACK"} {
				must(r.t, db, q)
			}
		},
		"MyISAM explicit ROLLBACK": func(r *myRig, db *sql.DB) {
			must(r.t, r.direct, "ALTER TABLE "+r.table+" ENGINE=MyISAM")
			for _, q := range []string{"START TRANSACTION", r.ins(), "ROLLBACK"} {
				must(r.t, db, q)
			}
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			r := newMyRig(t)
			db := r.conn("multiStatements=true")
			db.SetMaxOpenConns(1)
			run(r, db)
			db.Close()
			if v := r.verdict(1); v != harness.Fail {
				t.Fatalf("a row is there, and the witness says %v: %+v", v, r.w.Statements())
			}
		})
	}
}

// H4: nothing on the wire shows what a quit or a reset undid, so a write open
// then is unknown, on any table: the InnoDB control has no row and still can't pass.
func TestReview7MySQLEndOfSessionIsNotARollback(t *testing.T) {
	myisam := func(r *myRig) { must(r.t, r.direct, "ALTER TABLE "+r.table+" ENGINE=MyISAM") }
	for name, tc := range map[string]struct {
		setup func(r *myRig)
		first string
		rows  int
	}{
		"MyISAM, START TRANSACTION, quit": {myisam, "START TRANSACTION", 1},
		"MyISAM, autocommit off, quit":    {myisam, "SET autocommit=0", 1},
		"InnoDB, START TRANSACTION, quit": {func(*myRig) {}, "START TRANSACTION", 0},
	} {
		t.Run(name, func(t *testing.T) {
			r := newMyRig(t)
			tc.setup(r)
			db := r.conn("multiStatements=true")
			db.SetMaxOpenConns(1)
			must(t, db, tc.first)
			must(t, db, r.ins())
			db.Close()
			waitMyQuiet(r)
			if v := r.verdict(tc.rows); v != harness.Inconclusive {
				t.Fatalf("%v: %+v", v, r.w.Statements())
			}
			if f := strings.Join(r.w.Coverage().Faults, "; "); !strings.Contains(f, "COM_QUIT") {
				t.Fatalf("not the quit's fault: %s", f)
			}
		})
	}
	t.Run("MyISAM, resetconnection", func(t *testing.T) {
		r := newMyRig(t)
		myisam(r)
		host, port, _ := net.SplitHostPort(r.w.Addr().String())
		q := "START TRANSACTION;\n" + r.ins() + ";\nresetconnection\nSELECT 1;\n"
		out, err := dockerClient(t, mysqlImage, []string{"MYSQL_PWD=" + password}, "mysql", "-h", host, "-P", port, "-uroot",
			"--ssl-mode=PREFERRED", "app", "-e", q)
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if v := r.verdict(1); v != harness.Inconclusive {
			t.Fatalf("%v: %+v", v, r.w.Statements())
		}
		if f := strings.Join(r.w.Coverage().Faults, "; "); !strings.Contains(f, "session reset") {
			t.Fatalf("the client's reset did not reach the witness: %s", f)
		}
	})
	t.Run("nothing written, quit", func(t *testing.T) {
		r := newMyRig(t)
		db := r.conn("multiStatements=true")
		db.SetMaxOpenConns(1)
		must(t, db, "START TRANSACTION")
		db.Close()
		waitMyQuiet(r)
		if v := r.verdict(0); v != harness.Pass {
			t.Fatalf("%v: %+v", v, r.w.Statements())
		}
	})
	t.Run("InnoDB, explicit ROLLBACK", func(t *testing.T) {
		r := newMyRig(t)
		db := r.conn("multiStatements=true")
		db.SetMaxOpenConns(1)
		for _, q := range []string{"START TRANSACTION", r.ins(), "ROLLBACK"} {
			must(t, db, q)
		}
		db.Close()
		if v := r.verdict(0); v != harness.Pass {
			t.Fatalf("%v: %+v", v, r.w.Statements())
		}
	})
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

func TestReview7MySQLFalseFails(t *testing.T) {
	for name, q := range map[string]string{
		"alias columns":              "SELECT * FROM (VALUES ROW(1)) AS v(id)",
		"CTE columns":                "WITH t(a) AS (SELECT 1) SELECT a FROM t",
		"JSON_OBJECT":                "SELECT JSON_OBJECT('a', 1)",
		"upsert row alias":           "INSERT INTO OTHER (id) VALUES (1) AS n(id) ON DUPLICATE KEY UPDATE id = n.id",
		"a safe NAMES":               "SET NAMES latin2",
		"a safe sql_mode":            "SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE'",
		"what Rails sends":           "SET @@SESSION.sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), @@SESSION.sql_auto_is_null = 0",
		"reading the mode":           "SET @m = @@sql_mode",
		"another connection charset": "SET character_set_connection = gbk",
		"LOAD DATA, no SET":          "",
		"Rails join":                 "SELECT `TBL`.`id` FROM `TBL` INNER JOIN (SELECT `id` FROM `OTHER`) `x` ON `x`.`id` = `TBL`.`id` LIMIT 1",
	} {
		t.Run(name, func(t *testing.T) {
			r := newMyRig(t)
			o := "o_" + r.table
			must(t, r.direct, "CREATE TABLE "+o+" (id int PRIMARY KEY)")
			db := r.conn("multiStatements=true")
			db.SetMaxOpenConns(1)
			q := q
			if q == "" {
				if out, err := exec.Command("docker", "exec", myC.id, "sh", "-c", "echo 7 > /var/lib/mysql-files/r7b.txt").CombinedOutput(); err != nil {
					t.Fatalf("%v %s", err, out)
				}
				q = "LOAD DATA INFILE '/var/lib/mysql-files/r7b.txt' INTO TABLE " + o + " CHARACTER SET utf8mb4 LINES TERMINATED BY '\\n' (id)"
			}
			must(t, db, strings.ReplaceAll(strings.ReplaceAll(q, "TBL", r.table), "OTHER", o))
			must(t, db, "SELECT id FROM "+r.table) // and the session can still be read
			db.Close()
			if v := r.verdict(0); v != harness.Pass {
				t.Fatalf("no row, and the witness says %v: %+v", v, r.w.Statements())
			}
		})
	}
}

// The limits witnesses/README.md states for rows that reach a table the statement
// does not name: only the catalog shows these, and a claim is as good as the name
// in the statement. If one of these stops passing, the limit has closed: change the
// docs.
func TestReview7StatedLimits(t *testing.T) {
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
