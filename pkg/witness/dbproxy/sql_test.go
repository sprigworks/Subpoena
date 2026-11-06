//subpoena:spec_derived
//subpoena:pure_logic

// From the round 2 brief: table extraction from SQL text will be imperfect, so a
// statement that cannot be parsed over-reports, counting against every table and
// never silently passing. SQL forms from the PostgreSQL and MySQL manuals.
package dbproxy

import (
	"slices"
	"testing"
)

func both(sql string, want string, tables ...string) sqlCase {
	return sqlCase{sql: sql, want: want, tables: tables, pg: true, my: true}
}
func pgOnly(sql string, want string, tables ...string) sqlCase {
	return sqlCase{sql: sql, want: want, tables: tables, pg: true}
}
func myOnly(sql string, want string, tables ...string) sqlCase {
	return sqlCase{sql: sql, want: want, tables: tables, my: true}
}

type sqlCase struct {
	sql, want string // want: read, write, opaque, tx
	tables    []string
	pg, my    bool
}

func TestClassify(t *testing.T) {
	for _, tc := range []sqlCase{
		// Plain writes name their one table.
		both("INSERT INTO users (a, b) VALUES (1, 2)", "write", "users"),
		both("insert into Users values (1)", "write", "users"),
		both("INSERT INTO app.users VALUES (1)", "write", "app.users"),
		pgOnly(`INSERT INTO "Public"."Users" VALUES (1)`, "write", "Public.Users"),
		myOnly("INSERT INTO `Weird Name` VALUES (1)", "write", "Weird Name"),
		myOnly("INSERT LOW_PRIORITY IGNORE users VALUES (1)", "write", "users"),
		pgOnly("INSERT INTO t (a) VALUES ($1) ON CONFLICT (a) DO UPDATE SET a = EXCLUDED.a RETURNING a", "write", "t"),
		myOnly("INSERT INTO t (a) VALUES (?) ON DUPLICATE KEY UPDATE a = VALUES(a)", "write", "t"),
		both("INSERT INTO t SELECT * FROM u", "write", "t"),
		myOnly("REPLACE INTO t VALUES (1)", "write", "t"),
		both("UPDATE users SET a = 1 WHERE b = 2", "write", "users"),
		both("UPDATE users AS u SET a = 1", "write", "users"),
		both("UPDATE users u SET a = 1", "write", "users"),
		pgOnly("UPDATE ONLY users SET a = 1", "write", "users"),
		pgOnly("UPDATE users SET a = 1 FROM orders WHERE id = 2", "write", "users"),
		myOnly("UPDATE LOW_PRIORITY IGNORE users SET a = 1", "write", "users"),
		both("DELETE FROM users WHERE a = 1", "write", "users"),
		both("DELETE FROM users", "write", "users"),
		pgOnly("DELETE FROM ONLY users u USING orders o WHERE id = oid RETURNING id", "write", "users"),
		myOnly("DELETE LOW_PRIORITY QUICK IGNORE FROM users ORDER BY a LIMIT 1", "write", "users"),
		pgOnly("MERGE INTO t USING s ON id = sid WHEN MATCHED THEN DELETE", "write", "t"),
		pgOnly("TRUNCATE a, b", "write", "a", "b"),
		pgOnly("TRUNCATE TABLE ONLY a RESTART IDENTITY", "write", "a"),
		myOnly("TRUNCATE TABLE a", "write", "a"),
		pgOnly("COPY t (a, b) FROM STDIN", "write", "t"),
		pgOnly("COPY t TO STDOUT", "read"),
		pgOnly("COPY (SELECT 1) TO STDOUT", "read"),
		myOnly("LOAD DATA LOCAL INFILE 'x.csv' REPLACE INTO TABLE t", "write", "t"),
		both("CREATE TABLE t (a int)", "write", "t"),
		both("CREATE TEMPORARY TABLE IF NOT EXISTS t (a int)", "write", "t"),
		both("DROP TABLE IF EXISTS a, b", "write", "a", "b"),
		both("ALTER TABLE t ADD COLUMN b int", "write", "t"),

		// Comments and strings hide nothing and fake nothing.
		both("/* INSERT INTO x */ SELECT 1", "read"),
		both("-- DELETE FROM x\nSELECT 1", "read"),
		both("/* c */ -- d\n INSERT /* e */ INTO /* f */ t VALUES (1)", "write", "t"),
		both("SELECT 'DELETE FROM x'", "read"),
		both("SELECT 'it''s; DELETE FROM x'", "read"),
		pgOnly("SELECT $$DELETE FROM x$$", "read"),
		pgOnly("SELECT $tag$; DELETE FROM x; $tag$", "read"),
		pgOnly(`SELECT E'a\'; DELETE FROM x'`, "read"),
		myOnly(`SELECT 'a\'; DELETE FROM x'`, "read"),
		myOnly("# DELETE FROM x\nSELECT 1", "read"),
		pgOnly("/* a /* nested */ DELETE FROM x */ SELECT 1", "read"),

		// Reads and session commands write nothing.
		both("SELECT a, count(*) FROM t GROUP BY a", "read"),
		both("SELECT * FROM t WHERE a IN (1, 2) AND (b = 1 OR c = 2) ORDER BY a LIMIT 1", "read"),
		both("SELECT * FROM t FOR UPDATE", "read"),
		pgOnly("SELECT * FROM t FOR NO KEY UPDATE", "read"),
		pgOnly("WITH x AS (SELECT 1) SELECT * FROM x", "read"),
		both("(SELECT 1) UNION (SELECT 2)", "read"),
		both("SET x = 1", "read"),
		myOnly("SET autocommit = 0", "read"),
		both("SHOW tables", "read"),
		pgOnly("LISTEN x", "read"),
		both("EXPLAIN SELECT 1", "read"),
		pgOnly("EXPLAIN DELETE FROM t", "read"),
		pgOnly("VALUES (1)", "read"),
		myOnly("USE app", "read"),
		pgOnly("PREPARE p AS INSERT INTO t VALUES (1)", "read"),
		pgOnly("DECLARE c CURSOR FOR SELECT 1", "read"),

		// Transaction commands.
		both("BEGIN", "tx"),
		both("START TRANSACTION", "tx"),
		both("COMMIT", "tx"),
		both("ROLLBACK", "tx"),
		pgOnly("END", "tx"),
		pgOnly("ABORT", "tx"),
		both("SAVEPOINT a", "tx"),
		both("RELEASE SAVEPOINT a", "tx"),
		both("ROLLBACK TO SAVEPOINT a", "tx"),

		// What it cannot read counts against every table.
		both("INSERT INTO t VALUES ('unterminated", "opaque"),
		both("/* unterminated", "opaque"),
		pgOnly(`SELECT "unterminated`, "opaque"),
		pgOnly("SELECT $$unterminated", "opaque"),
		myOnly("SELECT `unterminated", "opaque"),
		myOnly("/*! DELETE FROM users */", "opaque"),
		myOnly("SELECT 1 /*!50001 , (DELETE FROM users) */", "opaque"),
		both("FROBNICATE users", "opaque"),
		both("INSERT", "opaque"),
		both("INSERT INTO", "opaque"),
		both("INSERT INTO (a)", "opaque"),
		both("UPDATE", "opaque"),
		both("DELETE users", "opaque"),
		both("DELETE FROM", "opaque"),
		myOnly("UPDATE a, b SET a.x = 1", "opaque"),
		myOnly("UPDATE a JOIN b ON a.i = b.i SET a.x = 1", "opaque"),
		myOnly("DELETE a, b FROM a JOIN b ON a.i = b.i", "opaque"),
		myOnly("DELETE FROM a, b USING a JOIN b", "opaque"),
		pgOnly("TRUNCATE a CASCADE", "opaque"),
		both("TRUNCATE", "opaque"),
		pgOnly("COPY t", "opaque"),
		myOnly("LOAD XML INFILE 'x' INTO TABLE t", "opaque"),
		pgOnly("EXECUTE p", "opaque"),
		myOnly("EXECUTE p USING @a", "opaque"),
		pgOnly("DO $$ BEGIN DELETE FROM t; END $$", "opaque"),
		both("CALL p()", "opaque"),
		both("GRANT ALL ON t TO u", "opaque"),
		both("CREATE VIEW v AS SELECT 1", "opaque"),
		both("CREATE TRIGGER x BEFORE INSERT ON t FOR EACH ROW SET NEW.a = 1", "opaque"),
		both("DROP VIEW v", "opaque"),
		both("ALTER USER u", "opaque"),
		myOnly("XA START 'x'", "opaque"),
		pgOnly("EXPLAIN ANALYZE DELETE FROM t", "opaque"),
		pgOnly("EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t", "opaque"),
		pgOnly("COPY (DELETE FROM t RETURNING *) TO STDOUT", "opaque"),

		// A qualified column can be a function called on the row, in PostgreSQL.
		pgOnly("UPDATE users SET a = o.a FROM orders o WHERE o.id = users.id", "opaque"),
		pgOnly("DELETE FROM ONLY users u USING orders o WHERE u.id = o.id RETURNING u.id", "opaque"),
		pgOnly("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", "opaque"),

		// A read in form can still write: what it might do is unknown.
		pgOnly("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", "opaque"),
		pgOnly("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", "opaque"),
		pgOnly("INSERT INTO t WITH d AS (DELETE FROM u RETURNING *) SELECT * FROM d", "opaque"),
		pgOnly("SELECT * INTO copy FROM t", "opaque"),
		myOnly("SELECT * FROM t INTO OUTFILE '/tmp/x'", "opaque"),
		both("SELECT delete_user(1)", "opaque"),
		both("SELECT app.delete_user(1)", "opaque"),
		pgOnly("SELECT * FROM delete_user(1)", "opaque"),
		pgOnly(`SELECT "delete_user"(1)`, "opaque"),
		pgOnly("SELECT dblink_exec('x', 'DELETE FROM t')", "opaque"),
		both("INSERT INTO t VALUES (write_elsewhere())", "opaque"),
		both("UPDATE t SET a = write_elsewhere()", "opaque"),
		both("DELETE FROM t WHERE a = write_elsewhere()", "opaque"),
		myOnly("SET @a = write_elsewhere()", "opaque"),

		// Well-known functions do not make a read opaque.
		both("SELECT count(*), max(a), lower(b), coalesce(c, 1), now() FROM t", "read"),
		pgOnly("SELECT nextval('s'), pg_advisory_lock(1), current_setting('x'), pg_catalog.version()", "read"),
		pgOnly("SELECT * FROM generate_series(1, 3), unnest($1::int[])", "read"),
		pgOnly("SELECT CAST(a AS varchar(10)), a = ANY ($1), EXISTS (SELECT 1) FROM t", "read"),
		myOnly("SELECT last_insert_id(), ifnull(a, 1), date_format(b, '%Y'), @@max_allowed_packet FROM t", "read"),
		both("INSERT INTO t (a, b) VALUES (now(), lower('X'))", "write", "t"),
	} {
		for _, d := range []dialect{dialectPostgres, dialectMySQL} {
			if (d == dialectPostgres && !tc.pg) || (d == dialectMySQL && !tc.my) {
				continue
			}
			got := parseSQL(d, tc.sql)
			if len(got) != 1 {
				t.Errorf("%v %q: %d statements, want 1: %+v", d, tc.sql, len(got), got)
				continue
			}
			s := got[0]
			if name := s.class.String(); name != tc.want {
				t.Errorf("%v %q: class %s (%s), want %s", d, tc.sql, name, s.reason, tc.want)
			}
			if tc.want == "opaque" && s.reason == "" {
				t.Errorf("%v %q: opaque with no reason", d, tc.sql)
			}
			if !slices.Equal(s.tables, tc.tables) {
				t.Errorf("%v %q: tables %q, want %q", d, tc.sql, s.tables, tc.tables)
			}
		}
	}
}

func TestSplitStatements(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want []string // verbs
	}{
		{"", nil},
		{";;", nil},
		{"-- only a comment", nil},
		{"SELECT 1", []string{"SELECT"}},
		{"SELECT 1;", []string{"SELECT"}},
		{"BEGIN; INSERT INTO t VALUES (1); COMMIT", []string{"BEGIN", "INSERT", "COMMIT"}},
		{"SELECT ';'; DELETE FROM t", []string{"SELECT", "DELETE"}},
		{"INSERT INTO t VALUES (';'); ; SELECT 1", []string{"INSERT", "SELECT"}},
	} {
		var got []string
		for _, s := range parseSQL(dialectPostgres, tc.sql) {
			got = append(got, s.verb)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: %q, want %q", tc.sql, got, tc.want)
		}
	}
	// A statement the tokenizer cannot finish takes the whole text with it: what
	// follows the break cannot be told apart.
	got := parseSQL(dialectPostgres, "SELECT 1; INSERT INTO t VALUES ('oops")
	if len(got) != 1 || got[0].class != classOpaque {
		t.Fatalf("got %+v", got)
	}
}

func TestTransactionCommands(t *testing.T) {
	for _, tc := range []struct {
		sql       string
		op        txOp
		savepoint string
	}{
		{"BEGIN", txBegin, ""},
		{"BEGIN WORK", txBegin, ""},
		{"START TRANSACTION READ ONLY", txBegin, ""},
		{"COMMIT", txCommit, ""},
		{"COMMIT AND CHAIN", txCommit, ""},
		{"END", txCommit, ""},
		{"ROLLBACK", txRollback, ""},
		{"ROLLBACK WORK", txRollback, ""},
		{"ROLLBACK AND CHAIN", txRollback, ""},
		{"ABORT", txRollback, ""},
		{"SAVEPOINT Sp1", txSavepoint, "sp1"},
		{`SAVEPOINT "Sp1"`, txSavepoint, "Sp1"},
		{"RELEASE sp1", txRelease, "sp1"},
		{"RELEASE SAVEPOINT sp1", txRelease, "sp1"},
		{"ROLLBACK TO sp1", txRollbackTo, "sp1"},
		{"ROLLBACK TO SAVEPOINT sp1", txRollbackTo, "sp1"},
		{"ROLLBACK WORK TO SAVEPOINT sp1", txRollbackTo, "sp1"},
		{"ROLLBACK TRANSACTION TO sp1", txRollbackTo, "sp1"},
		{"PREPARE TRANSACTION 'x'", txPrepare, ""},
		{"COMMIT PREPARED 'x'", txNone, ""},
		{"ROLLBACK PREPARED 'x'", txNone, ""},
	} {
		got := parseSQL(dialectPostgres, tc.sql)
		if len(got) != 1 || got[0].tx != tc.op || got[0].savepoint != tc.savepoint {
			t.Errorf("%q: %+v, want op %v savepoint %q", tc.sql, got, tc.op, tc.savepoint)
		}
	}
}

// Counts that say nothing about rows must not read as zero rows.
func TestNoCountStatements(t *testing.T) {
	for _, sql := range []string{"TRUNCATE t", "DROP TABLE t", "ALTER TABLE t DROP COLUMN a", "CREATE TABLE t AS SELECT 1"} {
		if s := parseSQL(dialectMySQL, sql); len(s) != 1 || !s[0].noCount {
			t.Errorf("%q: %+v", sql, s)
		}
	}
	if s := parseSQL(dialectMySQL, "DELETE FROM t"); s[0].noCount {
		t.Errorf("DELETE must take the server's count: %+v", s)
	}
}
