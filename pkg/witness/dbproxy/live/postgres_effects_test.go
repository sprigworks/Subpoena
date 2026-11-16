//subpoena:impl_derived
//subpoena:pure_logic

// PostgreSQL witness verdicts checked against rows read through a direct connection.
package live

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/sprigworks/subpoena/pkg/harness"
)

func TestPostgresIndirectWrites(t *testing.T) {
	cases := []struct {
		name string
		want harness.Verdict
		run  func(r *pgRig, c *pgx.Conn)
	}{
		// H1
		{"prefix", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("to_purge_"+r.table, "")
			sent(c, "SELECT to_purge_"+r.table+"()")
		}},
		{"schema shadow", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE SCHEMA s_" + r.table)
			r.writer("s_"+r.table+".lower", "")
			sent(c, "SELECT s_"+r.table+".lower()")
		}},
		{"keyword name", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("partition", "")
			r.t.Cleanup(func() { r.direct.Exec(context.Background(), "DROP FUNCTION partition()") })
			sent(c, "SELECT partition()")
		}},
		{"functional notation, function created through the listener", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE TABLE one_" + r.table + " (a int); INSERT INTO one_" + r.table + " VALUES (1)")
			sent(c, "CREATE FUNCTION w_"+r.table+"(one_"+r.table+") RETURNS int LANGUAGE plpgsql AS $f$ BEGIN "+r.ins()+"; RETURN 1; END $f$")
			sent(c, "SELECT o.w_"+r.table+" FROM one_"+r.table+" o")
		}},
		{"view created through the listener", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "")
			sent(c, "CREATE VIEW v_"+r.table+" AS SELECT w_"+r.table+"()")
			sent(c, "SELECT * FROM v_"+r.table)
		}},
		{"field of a parenthesis", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE TABLE one_" + r.table + " (a int); INSERT INTO one_" + r.table + " VALUES (1)")
			r.writer("w_"+r.table, "one_"+r.table)
			sent(c, "SELECT (o).w_"+r.table+" FROM one_"+r.table+" o")
		}},
		{"user operator", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "int, int")
			r.direct1("CREATE OPERATOR ### (LEFTARG=int, RIGHTARG=int, FUNCTION=w_" + r.table + ")")
			r.t.Cleanup(func() { r.direct.Exec(context.Background(), "DROP OPERATOR ### (int, int)") })
			sent(c, "SELECT 1 ### 2")
		}},
		{"domain check on a cast", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "int")
			r.direct1("CREATE DOMAIN d_" + r.table + " AS int CHECK (w_" + r.table + "(VALUE) = 1)")
			sent(c, "SELECT 1::d_"+r.table)
		}},
		{"domain check on a typed string", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "int")
			r.direct1("CREATE DOMAIN d_" + r.table + " AS int CHECK (w_" + r.table + "(VALUE) = 1)")
			sent(c, "SELECT d_"+r.table+" '1'")
		}},
		{"search path shadows a built-in", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE SCHEMA s_" + r.table)
			r.writer("s_"+r.table+".lower", "text")
			sent(c, "SET search_path = s_"+r.table+", pg_catalog, public")
			sent(c, "SELECT lower('x')")
		}},

		// H2
		{"quoted analyze", harness.Fail, func(r *pgRig, c *pgx.Conn) { sent(c, `EXPLAIN ("analyze") `+r.ins()) }},
		{"quoted analyze with a value", harness.Fail, func(r *pgRig, c *pgx.Conn) { sent(c, `EXPLAIN ("analyze" true) `+r.ins()) }},

		// H3
		{"CTAS over a writing CTE", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "CREATE TABLE z_"+r.table+" AS WITH d AS ("+r.ins()+" RETURNING 1) SELECT 1 AS a FROM d")
		}},
		{"CTAS over a function", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "")
			sent(c, "CREATE TABLE z_"+r.table+" AS SELECT w_"+r.table+"()")
		}},
		{"ALTER USING", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "int")
			r.direct1("CREATE TABLE z_" + r.table + " (a int); INSERT INTO z_" + r.table + " VALUES (1)")
			sent(c, "ALTER TABLE z_"+r.table+" ALTER a TYPE int USING w_"+r.table+"(a)")
		}},
		{"ALTER DEFAULT", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			r.writer("w_"+r.table, "")
			r.direct1("CREATE TABLE z_" + r.table + " (a int); INSERT INTO z_" + r.table + " VALUES (1)")
			sent(c, "ALTER TABLE z_"+r.table+" ADD b int DEFAULT w_"+r.table+"()")
		}},

		// H4
		{"PREPARE TRANSACTION then ROLLBACK", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "BEGIN; "+r.ins()+"; PREPARE TRANSACTION 'x"+r.table+"'; ROLLBACK")
			r.direct1("COMMIT PREPARED 'x" + r.table + "'")
		}},
		{"PREPARE TRANSACTION then an error", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "BEGIN; "+r.ins()+"; PREPARE TRANSACTION 'y"+r.table+"'; SELECT 1/0")
			r.direct1("COMMIT PREPARED 'y" + r.table + "'")
		}},
		{"COMMIT PREPARED of one it did not see", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			tx, err := r.direct.Begin(r.ctx)
			if err != nil {
				r.t.Fatal(err)
			}
			for _, q := range []string{r.ins(), "PREPARE TRANSACTION 'z" + r.table + "'"} {
				if _, err := tx.Exec(r.ctx, q); err != nil {
					r.t.Fatal(err)
				}
			}
			sent(c, "COMMIT PREPARED 'z"+r.table+"'")
		}},

		// H5
		{"long name", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			long := "u" + strings.Repeat("a", 62-len(r.table)) + r.table // 63 bytes
			r.direct1("ALTER TABLE " + r.table + " RENAME TO " + long)
			r.table = long
			sent(c, "INSERT INTO "+long+"xxxxx VALUES (1, 'a')")
		}},

		// H6
		{"refused Parse", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			p := c.PgConn()
			if _, err := p.Prepare(r.ctx, "s", "WITH d AS ("+r.ins()+" RETURNING 1) SELECT 1", nil); err != nil {
				r.t.Fatal(err)
			}
			if _, err := p.Prepare(r.ctx, "s", "SELECT 1", nil); err == nil {
				r.t.Fatal("the server took a second Parse of s")
			}
			p.ExecPrepared(r.ctx, "s", nil, nil, nil).Read()
		}},
		{"SQL PREPARE over a Parse", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			p := c.PgConn()
			if _, err := p.Prepare(r.ctx, "s", "SELECT 1", nil); err != nil {
				r.t.Fatal(err)
			}
			sent(c, "DEALLOCATE s")
			sent(c, "PREPARE s AS WITH d AS ("+r.ins()+" RETURNING 1) SELECT 1")
			p.ExecPrepared(r.ctx, "s", nil, nil, nil).Read()
		}},

		// H7
		{"carriage return ends a comment", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "WITH x AS (SELECT 1) --\r, d AS ("+r.ins()+" RETURNING 1)\nSELECT 1")
		}},
		{"E string continued", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "WITH x AS (SELECT E''\n'\\''), d AS ("+r.ins()+" RETURNING 1) SELECT 1 --') SELECT 1")
		}},
		{"standard_conforming_strings off", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "SET standard_conforming_strings=off")
			sent(c, "WITH x AS (SELECT '\\''), d AS ("+r.ins()+" RETURNING 1) SELECT 1 --') SELECT 1")
		}},
		{"off from login, seen only in ParameterStatus", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			cfg, err := pgx.ParseConfig(pgDSN(r.w.Addr().String(), "disable"))
			if err != nil {
				r.t.Fatal(err)
			}
			cfg.RuntimeParams["standard_conforming_strings"] = "off"
			off, err := pgx.ConnectConfig(r.ctx, cfg)
			if err != nil {
				r.t.Fatal(err)
			}
			defer off.Close(context.Background())
			sent(off, "WITH x AS (SELECT '\\''), d AS ("+r.ins()+" RETURNING 1) SELECT 1 --') SELECT 1")
		}},
		{"shift-jis hides the quote", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, "SET client_encoding = 'SJIS'")
			sent(c, "WITH x AS (SELECT E'\x83\\'), d AS ("+r.ins()+" RETURNING 1) SELECT 1 --') SELECT 1")
		}},
		{"U& identifier", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, `INSERT INTO U&"\`+fmt.Sprintf("%04x", r.table[0])+r.table[1:]+`" VALUES (1, 'a')`)
		}},

		// M1
		{"DO commits and raises", harness.Inconclusive, func(r *pgRig, c *pgx.Conn) {
			sent(c, "DO $$ BEGIN "+r.ins()+"; COMMIT; RAISE EXCEPTION 'x'; END $$")
		}},
		{"CALL commits and raises", harness.Inconclusive, func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE PROCEDURE p_" + r.table + "() LANGUAGE plpgsql AS $f$ BEGIN " + r.ins() + "; COMMIT; RAISE EXCEPTION 'x'; END $f$")
			sent(c, "CALL p_"+r.table+"()")
		}},
		{"CALL commits, then a pipeline fails", harness.Inconclusive, func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE PROCEDURE p_" + r.table + "() LANGUAGE plpgsql AS $f$ BEGIN " + r.ins() + "; COMMIT; END $f$")
			b := &pgconn.Batch{}
			b.ExecParams("CALL p_"+r.table+"()", nil, nil, nil, nil)
			b.ExecParams("SELECT 1/0", nil, nil, nil, nil)
			c.PgConn().ExecBatch(r.ctx, b).ReadAll()
		}},

		// The fixture's others.
		{"COPY TO PROGRAM", harness.Fail, func(r *pgRig, c *pgx.Conn) {
			sent(c, `COPY (SELECT 1) TO PROGRAM 'psql -U postgres -c "`+strings.ReplaceAll(r.ins(), "'", "''")+`"'`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPGRig(t)
			c := r.connect("disable")
			tc.run(r, c)
			c.Close(context.Background())
			if v := r.verdict(1); v != tc.want {
				t.Fatalf("a row is there, and the witness says %v, want %v: %+v", v, tc.want, r.w.Statements())
			}
		})
	}
}

// What must still pass: over-reporting is the cost, but not of everything.
func TestPostgresReadOnlyControls(t *testing.T) {
	cases := map[string]func(r *pgRig, c *pgx.Conn){
		"built-ins": func(r *pgRig, c *pgx.Conn) {
			sent(c, "SELECT count(*), lower('X'), pg_catalog.upper('x'), 1::int, now() FROM "+r.table+" WHERE id = 1")
		},
		"what an ORM writes": func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE TABLE o_" + r.table + " (uid int)")
			sent(c, `SELECT "u"."id", u.v FROM `+r.table+` u JOIN o_`+r.table+` o ON o.uid = u.id WHERE u.id = 1 ORDER BY u.v`)
		},
		"failed function": func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE FUNCTION f_" + r.table + "() RETURNS int LANGUAGE plpgsql AS $f$ BEGIN " + r.ins() + "; RAISE EXCEPTION 'x'; END $f$")
			sent(c, "SELECT f_"+r.table+"()")
		},
		"failed CALL in a block": func(r *pgRig, c *pgx.Conn) {
			r.direct1("CREATE PROCEDURE p_" + r.table + "() LANGUAGE plpgsql AS $f$ BEGIN " + r.ins() + "; RAISE EXCEPTION 'x'; END $f$")
			sent(c, "BEGIN")
			sent(c, "CALL p_"+r.table+"()")
			sent(c, "ROLLBACK")
		},
		"refused Parse of a write": func(r *pgRig, c *pgx.Conn) {
			c.PgConn().Prepare(r.ctx, "s", "INSERT INTO no_such VALUES (1)", nil)
		},
		"search path that leaves pg_catalog first": func(r *pgRig, c *pgx.Conn) {
			sent(c, "SET search_path = public")
			sent(c, "SELECT lower('x')")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			r := newPGRig(t)
			c := r.connect("disable")
			run(r, c)
			c.Close(context.Background())
			if v := r.verdict(0); v != harness.Pass {
				t.Fatalf("no row, and the witness says %v: %+v", v, r.w.Statements())
			}
		})
	}
}

func TestPostgresSessionAndExpressionWrites(t *testing.T) {
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
func TestPostgresStatementsWithoutClaimedRows(t *testing.T) {
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
