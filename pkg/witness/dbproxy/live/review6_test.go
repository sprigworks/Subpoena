//subpoena:impl_derived
//subpoena:pure_logic

// Round 2 review 6 against real servers. Every case checks the row is really
// there on a direct connection, then holds the witness to it: a row present must
// never pass. The two limits the docs state are pinned at the end, so that closing
// one has to change the docs too. No span is involved, so there is nothing to
// Collect.
package live

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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

func TestReview6Postgres(t *testing.T) {
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
func TestReview6PostgresStillPasses(t *testing.T) {
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

// The limits witnesses/README.md states: routines installed before the capture
// that nothing in the statement can tell from what they imitate. If one of these
// stops passing, the limit has closed: change the docs.
func TestReview6PostgresStatedLimits(t *testing.T) {
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

func TestReview6MySQL(t *testing.T) {
	cases := []struct {
		name string
		want harness.Verdict
		run  func(r *myRig, db *sql.DB)
	}{
		{"prefix", harness.Fail, func(r *myRig, db *sql.DB) {
			r.writerFn("date_w_" + r.table)
			db.Exec("SELECT date_w_" + r.table + "(1)")
		}},
		{"qualified built-in name", harness.Fail, func(r *myRig, db *sql.DB) {
			r.writerFn("app.lower")
			r.t.Cleanup(func() { r.direct.Exec("DROP FUNCTION app.lower") })
			db.Exec("SELECT app.lower(1)")
		}},
		{"a space makes it the stored function", harness.Fail, func(r *myRig, db *sql.DB) {
			r.writerFn("app.count")
			r.t.Cleanup(func() { r.direct.Exec("DROP FUNCTION app.count") })
			db.Exec("SELECT count (1)")
		}},
		{"name starting with a digit", harness.Fail, func(r *myRig, db *sql.DB) {
			r.writerFn("1w_" + r.table)
			db.Exec("SELECT 1w_" + r.table + "(1)")
		}},
		{"quoted name", harness.Fail, func(r *myRig, db *sql.DB) {
			r.writerFn("`w_" + r.table + "`")
			db.Exec("SELECT `w_" + r.table + "`(1)")
		}},
		{"NO_BACKSLASH_ESCAPES", harness.Fail, func(r *myRig, db *sql.DB) {
			must(r.t, db, "SET sql_mode = 'NO_BACKSLASH_ESCAPES'")
			db.Exec("SELECT '\\'; " + r.ins() + "; -- '")
		}},
		{"NO_BACKSLASH_ESCAPES in the same text", harness.Fail, func(r *myRig, db *sql.DB) {
			db.Exec("SET sql_mode = 'NO_BACKSLASH_ESCAPES'; SELECT '\\'; " + r.ins() + "; -- '")
		}},
		{"ANSI_QUOTES", harness.Fail, func(r *myRig, db *sql.DB) {
			must(r.t, db, "SET sql_mode = 'ANSI_QUOTES'")
			db.Exec(`SELECT 1 AS "a\"; ` + r.ins() + `; -- "`)
		}},
		{"gbk hides the quote", harness.Fail, func(r *myRig, db *sql.DB) {
			must(r.t, db, "SET NAMES gbk")
			db.Exec("SELECT '\xbf\\'; " + r.ins() + "; -- '")
		}},
		{"procedure writes and fails", harness.Inconclusive, func(r *myRig, db *sql.DB) {
			must(r.t, r.direct, "CREATE PROCEDURE p_"+r.table+"() BEGIN "+r.ins()+"; SIGNAL SQLSTATE '45000'; END")
			db.Exec("CALL p_" + r.table + "()")
		}},
		{"procedure commits in a transaction, then ROLLBACK", harness.Inconclusive, func(r *myRig, db *sql.DB) {
			must(r.t, r.direct, "CREATE PROCEDURE p_"+r.table+"() BEGIN "+r.ins()+"; COMMIT; START TRANSACTION; END")
			must(r.t, db, "START TRANSACTION")
			must(r.t, db, "CALL p_"+r.table+"()")
			must(r.t, db, "ROLLBACK")
		}},
		{"failed DDL commits what came before", harness.Fail, func(r *myRig, db *sql.DB) {
			must(r.t, db, "START TRANSACTION")
			must(r.t, db, r.ins())
			db.Exec("DROP TABLE no_such_" + r.table)
			must(r.t, db, "ROLLBACK")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newMyRig(t)
			db := r.conn("multiStatements=true")
			tc.run(r, db)
			db.Close()
			if v := r.verdict(1); v != tc.want {
				t.Fatalf("a row is there, and the witness says %v, want %v: %+v", v, tc.want, r.w.Statements())
			}
		})
	}
}

// Where the lexers might part. Whether the row lands is the server's business;
// a row must not pass.
func TestReview6MySQLCommentEdges(t *testing.T) {
	for name, text := range map[string]string{
		"DEL after dashes": "SELECT 1 --\x7f '\n; %s; -- '",
		"NUL in a comment": "SELECT 1 # \x00\n; %s; -- ",
	} {
		t.Run(name, func(t *testing.T) {
			r := newMyRig(t)
			db := r.conn("multiStatements=true")
			db.Exec(fmt.Sprintf(text, r.ins()))
			db.Close()
			rows := r.rows()
			r.w.Stop()
			if v, _ := harness.NoRow(r.w, trace, r.table); rows != 0 && v == harness.Pass {
				t.Fatalf("%d rows, and the witness passes: %+v", rows, r.w.Statements())
			}
		})
	}
}

func TestReview6MySQLStillPasses(t *testing.T) {
	cases := map[string]func(r *myRig, db *sql.DB){
		"built-ins and qualified columns": func(r *myRig, db *sql.DB) {
			must(r.t, db, "SELECT count(*), lower('X'), t.id FROM "+r.table+" t GROUP BY t.id")
		},
		"failed function": func(r *myRig, db *sql.DB) {
			must(r.t, r.direct, "CREATE FUNCTION f_"+r.table+"() RETURNS int DETERMINISTIC MODIFIES SQL DATA BEGIN "+r.ins()+"; SIGNAL SQLSTATE '45000'; RETURN 1; END")
			db.Exec("SELECT f_" + r.table + "()")
		},
		"utf8mb4 and a plain sql_mode": func(r *myRig, db *sql.DB) {
			must(r.t, db, "SET NAMES utf8mb4")
			must(r.t, db, "SET sql_mode = 'STRICT_ALL_TABLES'")
			must(r.t, db, "SELECT 1")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			r := newMyRig(t)
			db := r.conn("multiStatements=true")
			run(r, db)
			db.Close()
			if v := r.verdict(0); v != harness.Pass {
				t.Fatalf("no row, and the witness says %v: %+v", v, r.w.Statements())
			}
		})
	}
}
