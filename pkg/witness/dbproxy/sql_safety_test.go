//subpoena:impl_derived
//subpoena:pure_logic

// Conservative SQL classification and lexical boundaries.
package dbproxy

import (
	"strings"
	"testing"
)

func classOf(t *testing.T, d dialect, sql string) statement {
	t.Helper()
	got := parseSQL(d, sql)
	if len(got) != 1 {
		t.Fatalf("%v %q: %d statements: %+v", d, sql, len(got), got)
	}
	return got[0]
}

func TestUnprovenIsOpaque(t *testing.T) {
	for _, tc := range []sqlCase{
		// H1: a name the application can own is proof of nothing.
		pgOnly("SELECT to_purge_users()", "opaque"),
		pgOnly("SELECT pg_write_it()", "opaque"),
		pgOnly("SELECT json_writer()", "opaque"),
		pgOnly("SELECT array_writer()", "opaque"),
		pgOnly("SELECT current_writer()", "opaque"),
		pgOnly("SELECT regexp_writer()", "opaque"),
		myOnly("SELECT date_w_users()", "opaque"),
		myOnly("SELECT json_writer()", "opaque"),
		pgOnly("SELECT s_users.lower()", "opaque"),
		pgOnly("SELECT s_users.count(*) FROM t", "opaque"),
		pgOnly("SELECT postgres.pg_catalog.lower('x')", "opaque"),
		pgOnly(`SELECT "pg_catalog".lower('x')`, "opaque"),
		pgOnly(`SELECT "LOWER"('x')`, "opaque"),
		pgOnly("SELECT pg_catalog.set_config('search_path', 'a', false)", "opaque"),
		pgOnly("SELECT pg_catalog.query_to_xml('DELETE FROM t', true, true, '')", "opaque"),
		pgOnly("SELECT set_config('x', 'y', false)", "opaque"),
		myOnly("SELECT app.lower('x')", "opaque"),
		myOnly("SELECT pg_catalog.lower('x')", "opaque"),
		myOnly("SELECT `lower`('x')", "opaque"),
		myOnly("SELECT count (1)", "opaque"),
		myOnly("SELECT count/**/(1)", "opaque"),
		myOnly("SELECT 1abc()", "opaque"),
		// Built-ins of the other engine, or of neither, are the application's.
		pgOnly("SELECT ifnull(a, 1) FROM t", "opaque"),
		pgOnly("SELECT strftime('x')", "opaque"),
		myOnly("SELECT nextval('s')", "opaque"),
		myOnly("SELECT strftime('x')", "opaque"),
		// A keyword-looking call.
		pgOnly("SELECT partition()", "opaque"),
		pgOnly("SELECT value()", "opaque"),
		pgOnly("SELECT by(1)", "opaque"),
		pgOnly("SELECT over(1)", "opaque"),
		pgOnly("SELECT filter(1)", "opaque"),
		pgOnly("SELECT like(1, 2)", "opaque"),
		pgOnly("SELECT join(1)", "opaque"),
		pgOnly("SELECT do(1)", "opaque"),
		pgOnly("SELECT key(1)", "opaque"),
		pgOnly("SELECT cube(1)", "opaque"),
		pgOnly("SELECT rollup(1)", "opaque"),
		pgOnly("SELECT set(1)", "opaque"),
		pgOnly("SELECT s.in(1)", "opaque"),
		myOnly("SELECT value()", "opaque"),
		myOnly("SELECT filter(1)", "opaque"),
		myOnly("SELECT do(1)", "opaque"),
		myOnly("SELECT any(1)", "opaque"),
		myOnly("SELECT s.in(1)", "opaque"),
		// A field of an expression can be a function on it; a plain a.b is a stated
		// limit, below.
		pgOnly("SELECT (o).w_users FROM one_users o", "opaque"),
		pgOnly("SELECT a[1].w FROM one", "opaque"),
		pgOnly("SELECT $1.w", "opaque"),
		pgOnly("SELECT o.w(1) FROM one o", "opaque"),
		pgOnly("UPDATE t SET a = (b).w", "opaque"),
		// User operators, casts and typed strings run routines with no call.
		pgOnly("SELECT 1 ### 2", "opaque"),
		pgOnly("SELECT 1 # 2", "opaque"),
		pgOnly("SELECT 1 #/**/# 2", "opaque"),
		pgOnly("SELECT 1 &&& 2", "opaque"),
		pgOnly("SELECT @ 1", "opaque"),
		pgOnly("SELECT a @-@ b FROM t", "opaque"),
		pgOnly("SELECT 1 OPERATOR(public.+) 2", "opaque"),
		pgOnly("UPDATE t SET a = 1 ### 2", "opaque"),
		pgOnly("SELECT 1::mydomain", "opaque"),
		pgOnly("SELECT 1::app.int", "opaque"),
		pgOnly("SELECT CAST(1 AS mydomain)", "opaque"),
		pgOnly("SELECT CAST(1 AS app.int)", "opaque"),
		pgOnly("SELECT mydomain '1'", "opaque"),

		// What has to stay a read for the list to be worth having.
		pgOnly("SELECT lower('x'), pg_catalog.lower('x'), pg_catalog.count(*) FROM t", "read"),
		pgOnly("SELECT * FROM app.users", "read"),
		pgOnly("SELECT * FROM ONLY app.users u, other.t x WHERE a = 1", "read"),
		pgOnly("SELECT * FROM a JOIN app.b ON true", "read"),
		pgOnly("SELECT o.* FROM one o", "read"),
		// A qualified column is a read, on either engine: every ORM writes them.
		pgOnly("SELECT o.w_users FROM one_users o", "read"),
		pgOnly(`SELECT "o"."w" FROM "one" "o"`, "read"),
		pgOnly("SELECT 1 FROM one o WHERE o.w = 1 ORDER BY o.w", "read"),
		pgOnly("SELECT 1 FROM a JOIN b ON a.x = b.y", "read"),
		pgOnly("SELECT app.t.a FROM app.t", "read"),
		pgOnly("INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = EXCLUDED.a", "write", "t"),
		pgOnly("TABLE app.users", "read"),
		pgOnly("SELECT a FROM t WHERE b = -1 AND c >= 2 AND d <> 3 AND e != 4", "read"),
		pgOnly("SELECT a=-1, 1*-1, 'x' || 'y', j->'a', j->>'a', j @> k, a ~ 'b', a !~* 'b', 2 ^ 3 FROM t", "read"),
		pgOnly("SELECT 1::int, $1::text[], 2::numeric(10,2), CAST(1 AS bigint), DATE '2020-01-01', E'a', B'1'", "read"),
		pgOnly("SELECT count(*) FILTER (WHERE a = 1), rank() OVER (PARTITION BY a ORDER BY b) FROM t", "read"),
		pgOnly("SELECT a FROM t GROUP BY CUBE (a), ROLLUP (b)", "opaque"), // a comma: cube() may be a function
		pgOnly("SELECT a FROM t GROUP BY ROLLUP (a)", "read"),
		pgOnly("SELECT a FROM t GROUP BY GROUPING SETS (a)", "read"),
		pgOnly("SELECT string_agg(a, ',') WITHIN GROUP (ORDER BY a) FROM t", "read"),
		pgOnly("SELECT 'a' LIKE ('b'), (a) ILIKE ('b') FROM t", "read"),
		pgOnly("SELECT a FROM t INNER JOIN (SELECT 1) x ON true", "read"),
		pgOnly("SET app.user_id = 5", "read"),
		pgOnly("EXTRACT", "opaque"),
		pgOnly("SELECT extract(year FROM a), substring(a FROM 1), trim(a) FROM t", "read"),
		pgOnly("UPDATE t SET (a, b) = (1, 2)", "write", "t"),
		pgOnly("INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET (a) = (2)", "write", "t"),
		pgOnly("DELETE FROM t USING app.u WHERE a = 1", "write", "t"),
		myOnly("SELECT o.id FROM one o JOIN two t ON o.a = t.b", "read"),
		myOnly("SELECT * FROM t PARTITION (p0)", "read"),
		myOnly("SELECT a = ANY (SELECT 1), b = SOME (SELECT 2) FROM t", "read"),
		myOnly("INSERT INTO t VALUE (1)", "write", "t"),
		myOnly("SELECT date_format(a, 'x'), lower(b) FROM t", "read"),

		// H2: only an option list it reads all of is a plain EXPLAIN.
		pgOnly(`EXPLAIN ("analyze") INSERT INTO t VALUES (1)`, "opaque"),
		pgOnly(`EXPLAIN ("analyze" true) INSERT INTO t VALUES (1)`, "opaque"),
		pgOnly(`EXPLAIN (verbose, "analyze") DELETE FROM t`, "opaque"),
		pgOnly("EXPLAIN (FROB) DELETE FROM t", "opaque"),
		pgOnly("EXPLAIN (VERBOSE true false) DELETE FROM t", "opaque"),
		pgOnly("EXPLAIN (ANALYSE) DELETE FROM t", "opaque"),
		pgOnly("EXPLAIN ANALYSE DELETE FROM t", "opaque"),
		pgOnly("EXPLAIN SELECT write_it()", "opaque"),
		pgOnly("EXPLAIN (VERBOSE, COSTS false, FORMAT json) SELECT 1", "read"),
		pgOnly("EXPLAIN (VERBOSE) DELETE FROM t", "read"),
		myOnly("EXPLAIN ANALYZE SELECT 1", "opaque"),
		myOnly("DESC ANALYZE SELECT 1", "opaque"),
		myOnly("DESCRIBE ANALYZE SELECT 1", "opaque"),
		myOnly("DESCRIBE t", "read"),

		// H3: what runs inside a schema change.
		pgOnly("CREATE TABLE z AS WITH d AS (INSERT INTO users VALUES (1) RETURNING 1) SELECT 1 AS a FROM d", "opaque"),
		pgOnly("CREATE TABLE z AS SELECT writing_func()", "opaque"),
		pgOnly("CREATE TABLE z (a) AS SELECT writing_func()", "opaque"),
		pgOnly("CREATE TABLE z WITH (fillfactor = 70) AS SELECT writing_func()", "opaque"),
		pgOnly("CREATE TABLE z AS EXECUTE p", "opaque"),
		pgOnly("CREATE TEMP TABLE z AS TABLE u", "write", "z"),
		myOnly("CREATE TABLE z SELECT writing_func()", "opaque"),
		myOnly("CREATE TABLE z (a int) SELECT writing_func()", "opaque"),
		myOnly("CREATE TABLE z (SELECT writing_func())", "opaque"),
		myOnly("CREATE TABLE z ENGINE=InnoDB AS SELECT writing_func()", "opaque"),
		both("CREATE TABLE z AS SELECT 1", "write", "z"),
		pgOnly("CREATE TABLE z WITH (fillfactor = 70) AS SELECT 1", "write", "z"),
		both("CREATE TABLE z (a int, b varchar(10), PRIMARY KEY (a))", "write", "z"),
		both("CREATE TABLE z (a int REFERENCES u ON DELETE CASCADE)", "write", "z"),
		both("ALTER TABLE z ADD b int DEFAULT w()", "opaque"),
		pgOnly("ALTER TABLE z ALTER a TYPE int USING w(a)", "opaque"),
		both("ALTER TABLE z ADD CHECK (w(a) = 1)", "opaque"),
		both("ALTER TABLE staging RENAME TO users", "opaque"),
		myOnly("ALTER TABLE a EXCHANGE PARTITION p WITH TABLE b", "opaque"),
		both("ALTER TABLE z ADD b varchar(10) DEFAULT 'x'", "write", "z"),
		both("ALTER TABLE z ADD PRIMARY KEY (a)", "write", "z"),

		// The fixture's other bypasses.
		pgOnly(`COPY (SELECT 1) TO PROGRAM 'x'`, "opaque"),
		pgOnly(`COPY t TO PROGRAM 'x'`, "opaque"),
		pgOnly(`COPY t FROM PROGRAM 'x'`, "opaque"),
		pgOnly("COPY t FROM STDIN WHERE write_it() = 1", "opaque"),
		pgOnly("COPY t FROM STDIN WHERE a = 1", "write", "t"),
		pgOnly(`INSERT INTO U&"\0075sers" VALUES (1)`, "opaque"),
		pgOnly(`INSERT INTO u&"\0075sers" VALUES (1)`, "opaque"),
		pgOnly(`SELECT U&'\0041'`, "opaque"),
		pgOnly("COMMIT PREPARED 'x'", "opaque"),
		pgOnly("ROLLBACK PREPARED 'x'", "read"),
		myOnly("START REPLICA", "opaque"),
		myOnly("SET GLOBAL init_connect = 'x'", "opaque"),
		myOnly("SET PERSIST x = 1", "opaque"),
		myOnly("SET @@GLOBAL.x = 1", "opaque"),

		// H7: where the server's lexer ends a comment or a string.
		pgOnly("WITH x AS (SELECT 1) --\r, d AS (INSERT INTO users VALUES (1) RETURNING 1)\nSELECT 1", "opaque"),
		pgOnly("SELECT 1 --\r, write_it()\n", "opaque"),
		myOnly("SELECT 1 -- \r, write_it()", "read"), // MySQL's comment runs to the newline
		myOnly("SELECT 1 # \r, write_it()", "read"),
		pgOnly("WITH x AS (SELECT E''\n'\\''), d AS (INSERT INTO users VALUES (1) RETURNING 1) SELECT 1 --') SELECT 1", "opaque"),
		pgOnly("SELECT E'a' -- c\n'\\''", "opaque"),
		pgOnly("SELECT E'a'\r'b'", "opaque"),
		pgOnly("SELECT 'a'\n'b'", "read"),
		myOnly("SELECT 1 --\x7f '\nDELETE FROM t; -- '", "opaque"),
		myOnly("SELECT 1 # \x00, write_it()", "opaque"),
		myOnly("SELECT 1 -- \x00, write_it()", "opaque"),
		myOnly("SELECT 1 \x00", "opaque"),
		pgOnly(`TRUNCATE U&"\0075sers"`, "opaque"), // nothing after the name to give it away
	} {
		for _, d := range []dialect{dialectPostgres, dialectMySQL} {
			if (d == dialectPostgres && !tc.pg) || (d == dialectMySQL && !tc.my) {
				continue
			}
			got := parseSQL(d, tc.sql)
			worst := "none"
			for i := range got {
				if got[i].class == classOpaque || worst == "none" {
					worst = got[i].class.String()
				}
			}
			if worst != tc.want {
				t.Errorf("%v %q: class %s, want %s: %+v", d, tc.sql, worst, tc.want, got)
			}
			if tc.want == "write" && (len(got) != 1 || strings.Join(got[0].tables, ",") != strings.Join(tc.tables, ",")) {
				t.Errorf("%v %q: %+v, want tables %q", d, tc.sql, got, tc.tables)
			}
		}
	}
}

// A dollar quote right after a parameter is the server's string, not the
// number's tail.
func TestPostgresNumberStopsAtDollar(t *testing.T) {
	if s := classOf(t, dialectPostgres, "SELECT $1$a$ ' $a$, write_it() --'"); s.class != classOpaque {
		t.Fatalf("%+v", s)
	}
}

// H5: the server keeps 63 bytes of a name, so the event must too.
func TestPostgresNameIsCutAsTheServerCutsIt(t *testing.T) {
	long := "users_" + strings.Repeat("a", 57)
	for _, sql := range []string{
		"INSERT INTO " + long + "xxxxx VALUES (1)",
		`INSERT INTO "` + long + `xxxxx" VALUES (1)`,
		"UPDATE " + long + "xxxxx SET a = 1",
		"DELETE FROM " + long + "xxxxx",
		"TRUNCATE " + long + "xxxxx",
	} {
		s := classOf(t, dialectPostgres, sql)
		if s.class != classWrite || len(s.tables) != 1 || s.tables[0] != long {
			t.Errorf("%q: %+v", sql, s)
		}
		if s.text != sql {
			t.Errorf("the statement as sent must survive: %q", s.text)
		}
	}
	if s := classOf(t, dialectPostgres, "INSERT INTO app."+long+"xxxxx VALUES (1)"); s.tables[0] != "app."+long {
		t.Errorf("%+v", s)
	}
	if s := classOf(t, dialectPostgres, "INSERT INTO "+long+" VALUES (1)"); s.tables[0] != long {
		t.Errorf("a name at the limit is whole: %+v", s)
	}
	// Where a non-ASCII name is cut depends on the server's encoding.
	if s := classOf(t, dialectPostgres, "INSERT INTO "+strings.Repeat("é", 40)+" VALUES (1)"); s.verb != "INSERT" || !strings.Contains(s.reason, "long name") {
		t.Errorf("%+v", s)
	}
	// MySQL refuses a long name; it does not cut one.
	if s := classOf(t, dialectMySQL, "INSERT INTO "+long+"xxxxx VALUES (1)"); s.tables[0] != long+"xxxxx" {
		t.Errorf("%+v", s)
	}
}

func TestSessionTaintFromText(t *testing.T) {
	for _, tc := range []struct {
		d     dialect
		sql   string
		taint bool
	}{
		{dialectPostgres, "SET standard_conforming_strings = off", true},
		{dialectPostgres, "SET standard_conforming_strings TO DEFAULT", true},
		{dialectPostgres, "SET LOCAL standard_conforming_strings = 'off'", true},
		{dialectPostgres, `SET "standard_conforming_strings" = off`, true},
		{dialectPostgres, "SET standard_conforming_strings = on", false},
		{dialectPostgres, "SET standard_conforming_strings = 'on'", false},
		{dialectPostgres, "SET client_encoding = 'SJIS'", true},
		{dialectPostgres, "SET NAMES 'BIG5'", true},
		{dialectPostgres, "SET client_encoding = 'UTF8'", false},
		{dialectPostgres, "SET search_path = app, pg_catalog", true},
		{dialectPostgres, "SET search_path TO 'app', 'pg_catalog'", true},
		{dialectPostgres, "SET search_path = pg_catalog, app", false},
		{dialectPostgres, "SET search_path = app, public", false},
		{dialectPostgres, "SET application_name = 'x'", false},
		{dialectPostgres, "SELECT U&'\\0041' /* standard_conforming_strings */", true},
		{dialectMySQL, "SET sql_mode = 'ANSI_QUOTES'", true},
		{dialectMySQL, "SET SESSION sql_mode = 'ANSI'", true},
		{dialectMySQL, "SET @@sql_mode := 'NO_BACKSLASH_ESCAPES'", true},
		{dialectMySQL, "SET sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')", true},
		{dialectMySQL, "SET sql_mode = @x", true},
		{dialectMySQL, "SET sql_mode = 'STRICT_ALL_TABLES'", false},
		{dialectMySQL, "SET NAMES gbk", true},
		{dialectMySQL, "SET CHARACTER SET sjis", true},
		{dialectMySQL, "SET CHARSET big5", true},
		{dialectMySQL, "SET character_set_client = gbk", true},
		{dialectMySQL, "SET NAMES utf8mb4", false},
		{dialectMySQL, "SET NAMES 'utf8mb4' COLLATE 'utf8mb4_bin'", false},
		{dialectMySQL, "SET autocommit = 0", false},
	} {
		s := classOf(t, tc.d, tc.sql)
		if (s.taint != "") != tc.taint {
			t.Errorf("%v %q: taint %q, want %v", tc.d, tc.sql, s.taint, tc.taint)
		}
	}
}

func TestMayCommit(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want bool
	}{
		{"CALL p()", true},
		{"DO $$ BEGIN COMMIT; END $$", true},
		{"EXECUTE p", true},
		{"FROBNICATE", true},
		{"SELECT 'unterminated", true}, // no parser finished it
		{"SELECT write_it()", false},   // a function cannot commit
		{"INSERT INTO t VALUES (write_it())", false},
		{"INSERT INTO t VALUES (1)", false},
		{"SELECT 1", false},
	} {
		s := parseSQL(dialectPostgres, tc.sql)[0]
		if s.mayCommit() != tc.want {
			t.Errorf("%q: mayCommit %v: %+v", tc.sql, !tc.want, s)
		}
	}
}
