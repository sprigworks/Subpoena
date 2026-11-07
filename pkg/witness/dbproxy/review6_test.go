//subpoena:impl_derived
//subpoena:pure_logic

// Round 2 review 6, RESEARCH/ROUND2_REVIEW6_DB_20261106.md in the workspace: each
// case was a false pass against a real server, or the MySQL twin of one. The
// live package runs them for real; these pin the reading without a server.
package dbproxy

import (
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
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

func expectUnknown(t *testing.T, w *wire, verb string) {
	t.Helper()
	for _, e := range w.cap.snapshot() {
		if e.Verb == verb {
			if e.Outcome != witness.OutcomeUnknown {
				t.Fatalf("%s: %+v", verb, e)
			}
			if len(w.cap.faultList()) == 0 {
				t.Fatal("an unknown outcome with healthy capture reads as no row")
			}
			return
		}
	}
	t.Fatalf("no %s in %+v", verb, w.cap.snapshot())
}

// H4.
func TestPostgresPreparedTransactionSettlesAtItsTag(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN; INSERT INTO a VALUES (1); PREPARE TRANSACTION 'x'; ROLLBACK"))
	w.server(pgDone("BEGIN"), pgDone("INSERT 0 1"), pgDone("PREPARE TRANSACTION"), pgDone("ROLLBACK"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed INSERT" {
		t.Fatalf("%q", got)
	}

	w = pgReadyWire(t)
	w.client(pgQuery("BEGIN; INSERT INTO a VALUES (1); PREPARE TRANSACTION 'y'; SELECT 1/0"))
	w.server(pgDone("BEGIN"), pgDone("INSERT 0 1"), pgDone("PREPARE TRANSACTION"), pgError(), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed INSERT" {
		t.Fatalf("%q", got)
	}

	// PREPARE TRANSACTION in a failed block is answered ROLLBACK: the tag decides.
	w = pgReadyWire(t)
	w.client(pgQuery("INSERT INTO a VALUES (1); PREPARE TRANSACTION 'z'"))
	w.server(pgDone("INSERT 0 1"), pgDone("ROLLBACK"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "rolled_back INSERT" {
		t.Fatalf("%q", got)
	}
}

// H6: the server's copy of a name changes only when it says so.
func TestPostgresRefusedParseChangesNothing(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("s", "DELETE FROM a"), pgSync())
	w.server(frame('1'), pgReady('I'))
	w.client(pgParse("s", "SELECT 1"), pgSync())
	w.server(pgError(), pgReady('I'))
	w.client(pgBind("", "s"), pgExecute(""), pgSync())
	w.server(frame('2'), pgDone("DELETE 1"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed DELETE" {
		t.Fatalf("%q", got)
	}
	w.healthy()
}

func TestPostgresPipelinedRefusalSkipsToSync(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("s", "DELETE FROM a"), pgSync())
	w.server(frame('1'), pgReady('I'))
	// All one write: the Parse is refused, and the rest is skipped unanswered.
	w.client(pgParse("s", "SELECT 1"), pgBind("", "s"), pgExecute(""), pgClose('S', "s"), pgSync())
	w.server(pgError(), pgReady('I'))
	w.client(pgBind("", "s"), pgExecute(""), pgSync())
	w.server(frame('2'), pgDone("DELETE 1"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed DELETE" {
		t.Fatalf("%q", got)
	}
	w.healthy()
}

// The error can overtake the proxy: the rest of the pipeline reaches the queue
// after the server has already refused the head of it.
func TestPostgresErrorOvertakesThePipeline(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "SELECT 1/0"), pgBind("", ""), pgExecute(""))
	w.server(frame('1'), frame('2'), pgError())
	w.client(pgParse("", "DELETE FROM a"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(pgReady('I'))
	w.healthy()
	w.client(pgQuery("SELECT 1"))
	w.server(pgDone("SELECT 1"), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 0 {
		t.Fatalf("the skipped DELETE never ran: %q", got)
	}
}

func TestPostgresPipelinedParseBindExecute(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "DELETE FROM a"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("DELETE 1"), pgReady('I'))
	if got := w.outcomes(); len(got) != 1 || got[0] != "committed DELETE" {
		t.Fatalf("%q", got)
	}
}

func TestPostgresConfirmationWithNothingWaiting(t *testing.T) {
	for _, typ := range []byte{'1', '2', '3'} {
		w := pgReadyWire(t)
		w.server(frame(typ))
		if len(w.cap.faultList()) == 0 {
			t.Errorf("%q with nothing waiting must fault", typ)
		}
		// The wrong confirmation for what is waiting must not apply it.
		w = pgReadyWire(t)
		w.client(pgExecute("p"), pgSync())
		w.server(frame(typ))
		if f := w.cap.faultList(); len(f) != 1 || !strings.Contains(f[0], "nothing waiting") {
			t.Errorf("%q ahead of an Execute: %q", typ, f)
		}
	}
}

func TestPostgresParameterStatusWithoutTerminator(t *testing.T) {
	for _, body := range [][]byte{[]byte("name"), []byte("name\x00value")} {
		w := pgReadyWire(t)
		w.server(frame('S', body))
		if f := w.cap.faultList(); len(f) != 1 || !strings.Contains(f[0], "ParameterStatus") {
			t.Errorf("%q: %q", body, f)
		}
	}
}

// The connection drops before the server answers: what was pipelined still counts.
func TestPostgresDropKeepsUnconfirmedExecute(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "DELETE FROM a"), pgBind("", ""), pgExecute(""), pgSync())
	w.s.finish()
	e := w.first()
	if e.Outcome != witness.OutcomeUnknown || len(e.Tables) != 1 || e.Tables[0] != "a" {
		t.Fatalf("%+v", e)
	}
}

// The fixture's sql_prepare_rebind: PREPARE and DEALLOCATE share Parse's names.
func TestPostgresSQLPrepareRebindsTheName(t *testing.T) {
	for _, drop := range []string{"DEALLOCATE s", "DEALLOCATE PREPARE s", "DEALLOCATE ALL", "DISCARD ALL"} {
		w := pgReadyWire(t)
		w.client(pgParse("s", "SELECT 1"), pgSync())
		w.server(frame('1'), pgReady('I'))
		w.client(pgQuery(drop))
		w.server(pgDone(strings.Fields(drop)[0]), pgReady('I'))
		// A SELECT's tag, so nothing but the name can give it away.
		w.client(pgQuery("PREPARE s AS WITH d AS (DELETE FROM a RETURNING 1) SELECT 1"))
		w.server(pgDone("PREPARE"), pgReady('I'))
		w.client(pgBind("", "s"), pgExecute(""), pgSync())
		w.server(frame('2'), pgDone("SELECT 1"), pgReady('I'))
		found := false
		for _, e := range w.cap.snapshot() {
			found = found || (e.Opaque && e.Outcome == witness.OutcomeCommitted)
		}
		if !found {
			t.Errorf("%s: %+v", drop, w.cap.snapshot())
		}
	}
}

func parameterStatus(k, v string) []byte { return frame('S', cstr(k), cstr(v)) }

// H7: the server's report outranks the text, however the setting changed.
func TestPostgresParameterStatusTaints(t *testing.T) {
	for _, tc := range []struct {
		k, v  string
		taint bool
	}{
		{"standard_conforming_strings", "off", true},
		{"standard_conforming_strings", "on", false},
		{"client_encoding", "SJIS", true},
		{"client_encoding", "BIG5", true},
		{"client_encoding", "GBK", true},
		{"client_encoding", "UTF8", false},
		{"client_encoding", "LATIN1", false},
		{"search_path", `"$user", public`, false},
		{"search_path", "app, pg_catalog", true},
		{"TimeZone", "off", false},
	} {
		w := pgReadyWire(t)
		w.server(parameterStatus(tc.k, tc.v))
		w.client(pgQuery("SELECT 1"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		if got := w.first().Opaque; got != tc.taint {
			t.Errorf("%s=%s: opaque %v", tc.k, tc.v, got)
		}
	}
}

func TestPostgresTaintIsForGood(t *testing.T) {
	w := pgReadyWire(t)
	w.server(parameterStatus("standard_conforming_strings", "off"))
	w.server(parameterStatus("standard_conforming_strings", "on"))
	w.client(pgQuery("INSERT INTO a VALUES (1)"))
	w.server(pgDone("INSERT 0 1"), pgReady('I'))
	if e := w.first(); !e.Opaque || e.Outcome != witness.OutcomeCommitted {
		t.Fatalf("%+v", e)
	}
}

// A statement pipelined behind the SET is answered before ParameterStatus comes.
func TestPostgresTaintReachesPipelinedStatement(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "SET standard_conforming_strings = off"), pgBind("", ""), pgExecute(""),
		pgParse("", "SELECT 1"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("SET"), frame('1'), frame('2'), pgDone("SELECT 1"),
		parameterStatus("standard_conforming_strings", "off"), pgReady('I'))
	for _, e := range w.cap.snapshot() {
		if !e.Opaque {
			t.Fatalf("%+v", e)
		}
	}
	if len(w.cap.snapshot()) != 2 {
		t.Fatalf("%+v", w.cap.snapshot())
	}
}

// A suspended portal of a read, on a session that can't be read.
func TestPostgresTaintReachesSuspendedPortal(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgParse("", "SELECT 1"), pgBind("", ""), pgSync())
	w.server(frame('1'), frame('2'), pgReady('I'))
	w.server(parameterStatus("standard_conforming_strings", "off"))
	w.client(pgExecute(""), pgSync())
	w.server(frame('s'), pgReady('I'))
	if e := w.first(); !e.Opaque || e.Outcome != witness.OutcomeCommitted {
		t.Fatalf("%+v", e)
	}
}

func TestPostgresTaintFromText(t *testing.T) {
	w := pgReadyWire(t)
	w.client(pgQuery("SET search_path = app, pg_catalog"))
	w.server(pgDone("SET"), pgReady('I'))
	w.client(pgQuery("SELECT lower('x')"))
	w.server(pgDone("SELECT 1"), pgReady('I'))
	for _, e := range w.cap.snapshot() {
		if !e.Opaque {
			t.Fatalf("%+v", e)
		}
	}
}

func TestPostgresStartupSearchPath(t *testing.T) {
	for _, tc := range []struct {
		params string
		taint  bool
	}{
		{"user\x00u\x00search_path\x00app,pg_catalog\x00\x00", true},
		{"options\x00-csearch_path=app,pg_catalog\x00\x00", true},
		{"user\x00u\x00search_path\x00app\x00\x00", false},
		{"user\x00u\x00options\x00-cstatement_timeout=5\x00\x00", false},
		{"user\x00u\x00\x00", false},
	} {
		w := newPG(t)
		w.client(pgStartup(codeV3, []byte(tc.params)...))
		w.server(frame('R', []byte{0, 0, 0, 0}), pgReady('I'))
		if !strings.Contains(w.up.String(), tc.params) {
			t.Fatalf("the startup packet must reach the server: %q", w.up.String())
		}
		w.client(pgQuery("SELECT 1"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		if got := w.first().Opaque; got != tc.taint {
			t.Errorf("%q: opaque %v", tc.params, got)
		}
	}
}

// An answer that is not what the text says, on a statement read as harmless.
func TestPostgresTagMustFitARead(t *testing.T) {
	for _, tc := range []struct{ sql, tag string }{
		{"SELECT 1", "CALL"},
		{"SELECT 1", "CREATE TABLE"},
		{"BEGIN", "DO"},
		{"SHOW x", "DROP TABLE"},
	} {
		w := pgReadyWire(t)
		w.client(pgQuery(tc.sql))
		w.server(pgDone(tc.tag), pgReady('I'))
		if e := w.first(); !e.Opaque || e.Outcome != witness.OutcomeCommitted {
			t.Errorf("%q answered %q: %+v", tc.sql, tc.tag, e)
		}
	}
}

// M1.
func TestPostgresFailedRoutineOutsideATransaction(t *testing.T) {
	for _, sql := range []string{"CALL p()", "DO $$ BEGIN COMMIT; RAISE EXCEPTION 'x'; END $$"} {
		w := pgReadyWire(t)
		w.client(pgQuery(sql))
		w.server(pgError(), pgReady('I'))
		expectUnknown(t, w, strings.Fields(sql)[0])
	}
}

func TestPostgresFailedRoutineInsideATransactionFailed(t *testing.T) {
	// A routine called inside a transaction block cannot commit.
	w := pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("CALL p()"))
	w.server(pgError(), pgReady('E'))
	w.client(pgQuery("ROLLBACK"))
	w.server(pgDone("ROLLBACK"), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "failed CALL" {
		t.Fatalf("%q", got)
	}

	// The block ended earlier in the pipeline, with no ReadyForQuery to say so.
	w = pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgParse("", "COMMIT"), pgBind("", ""), pgExecute(""), pgParse("", "CALL p()"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("COMMIT"), frame('1'), frame('2'), pgError(), pgReady('I'))
	expectUnknown(t, w, "CALL")
}

func TestPostgresFailedFunctionIsFailed(t *testing.T) {
	// A function runs inside its statement, and goes with it.
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT write_it()"))
	w.server(pgError(), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "failed SELECT" {
		t.Fatalf("%q", got)
	}
}

func TestPostgresRolledBackRoutineOutsideATransaction(t *testing.T) {
	// The fixture's pipeline_call_commit_then_error.
	w := pgReadyWire(t)
	w.client(pgParse("", "CALL p()"), pgBind("", ""), pgExecute(""), pgParse("", "SELECT 1/0"), pgBind("", ""), pgExecute(""), pgSync())
	w.server(frame('1'), frame('2'), pgDone("CALL"), frame('1'), frame('2'), pgError(), pgReady('I'))
	expectUnknown(t, w, "CALL")

	// In a block it cannot commit, and the rollback is the whole story.
	w = pgReadyWire(t)
	w.client(pgQuery("BEGIN"))
	w.server(pgDone("BEGIN"), pgReady('T'))
	w.client(pgQuery("CALL p()"))
	w.server(pgDone("CALL"), pgReady('T'))
	w.client(pgQuery("ROLLBACK"))
	w.server(pgDone("ROLLBACK"), pgReady('I'))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "rolled_back CALL" {
		t.Fatalf("%q", got)
	}
}

func TestPostgresMoreResultsThanStatementsMayCommit(t *testing.T) {
	// Misread text: the extra result failed, and it could have been a routine.
	w := pgReadyWire(t)
	w.client(pgQuery("SELECT 1"))
	w.server(pgDone("SELECT 1"), pgError(), pgReady('I'))
	if len(w.cap.faultList()) == 0 {
		t.Fatalf("%+v", w.cap.snapshot())
	}
}

func myStatus(status uint16) []byte { return myOK(1, 0, status, 0) }

// H7's twin: the server's flag says backslash no longer escapes.
func TestMySQLNoBackslashEscapesTaints(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT 1"))
	w.server(myOK(1, 0, stAutocommit|myStatusNoBackslash, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|myStatusNoBackslash, 0))
	got := w.cap.snapshot()
	if len(got) != 2 || !got[1].Opaque {
		t.Fatalf("%+v", got)
	}
}

// MySQL lexes the second statement after running the first.
func TestMySQLTaintReachesLaterStatementInTheText(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SET sql_mode = 'ANSI_QUOTES'; SELECT 1"))
	w.server(myOK(1, 0, stAutocommit|myStatusMoreResults, 0), myOK(2, 0, stAutocommit, 0))
	for _, e := range w.cap.snapshot() {
		if !e.Opaque {
			t.Fatalf("%+v", e)
		}
	}
}

func TestMySQLPreparedSetTaints(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myPrepare("SET sql_mode = 'ANSI_QUOTES'"))
	w.server(myPrepareOK(1, 5, 0, 0))
	w.client(myQuery("SELECT 1"))
	w.server(myStatus(stAutocommit))
	if e := w.first(); !e.Opaque {
		t.Fatalf("%+v", e)
	}
}

func TestMySQLHandshakeCharsetTaints(t *testing.T) {
	for _, tc := range []struct {
		collation byte
		taint     bool
	}{{28, true}, {1, true}, {13, true}, {95, true}, {248, true}, {45, false}, {8, false}} {
		w := newMy(t)
		w.server(myGreeting(capProtocol41))
		resp := append(append(le32(capProtocol41), le32(0)...), tc.collation)
		w.client(packet(1, resp))
		w.server(myOK(2, 0, stAutocommit, 0))
		w.client(myQuery("SELECT 1"))
		w.server(myStatus(stAutocommit))
		if got := w.first().Opaque; got != tc.taint {
			t.Errorf("collation %d: opaque %v", tc.collation, got)
		}
	}
}

func TestMySQLChangeUserTaints(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(packet(0, []byte{0x11}, []byte("u\x00")))
	w.server(myOK(1, 0, stAutocommit, 0))
	w.client(myQuery("SELECT 1"))
	w.server(myStatus(stAutocommit))
	if e := w.first(); !e.Opaque {
		t.Fatalf("%+v", e)
	}
}

// M1's twin: a procedure's work stays when it fails, and ERR has no status.
func TestMySQLFailedRoutine(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("CALL p()"))
	w.server(myErr(1))
	expectUnknown(t, w, "CALL")

	// Inside a transaction too: a procedure may COMMIT.
	w = myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("CALL p()"))
	w.server(myErr(1))
	expectUnknown(t, w, "CALL")
	if got := w.outcomes(); len(got) < 1 || got[0] != "committed INSERT" {
		t.Fatalf("the procedure may have committed what came before: %q", got)
	}
}

func TestMySQLRolledBackRoutine(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("CALL p()"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 0))
	expectUnknown(t, w, "CALL")
}

func TestMySQLFailedFunctionIsFailed(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("SELECT write_it()"))
	w.server(myErr(1))
	w.healthy()
	if got := w.outcomes(); len(got) != 1 || got[0] != "failed SELECT" {
		t.Fatalf("%q", got)
	}
}

// A statement that commits implicitly did so before it failed.
func TestMySQLFailedDDLCommitsWhatCameBefore(t *testing.T) {
	w := myReadyWire(t, 0)
	w.client(myQuery("BEGIN"))
	w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
	w.client(myQuery("INSERT INTO a VALUES (1)"))
	w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
	w.client(myQuery("DROP TABLE no_such"))
	w.server(myErr(1))
	w.client(myQuery("ROLLBACK"))
	w.server(myOK(1, 0, stAutocommit, 0))
	if got := w.outcomes(); len(got) < 1 || got[0] != "committed INSERT" {
		t.Fatalf("%q", got)
	}
}
