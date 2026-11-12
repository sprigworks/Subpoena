//subpoena:impl_derived
//subpoena:pure_logic

// Round 2 review 7, RESEARCH/ROUND2_REVIEW7_DB_20261106.md in the workspace. The
// live package runs these for real; here they pin the reading without a server.
package dbproxy

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// H1, H2, L2: a setting that changes lexing or lookup counts in any spelling, and
// only a value that is plainly safe keeps the session.
func TestReview7SetTaint(t *testing.T) {
	long := strings.Repeat("é", 40)
	for _, tc := range []struct {
		d     dialect
		sql   string
		taint bool
	}{
		{dialectPostgres, `SET search_path = s, E'pg\x5fcatalog', public`, true},
		{dialectPostgres, `SET search_path = s, $$pg_catalog$$`, true},
		{dialectPostgres, `SET search_path = s, 'pg_catalog'`, true},
		{dialectPostgres, `SET search_path = s, "pg_catalog"`, true},
		{dialectPostgres, `SET search_path = s, PG_CATALOG`, true},
		{dialectPostgres, `SET "search_path" = s, pg_catalog`, true},
		{dialectPostgres, `SET "SEARCH_PATH" = s, pg_catalog`, true},
		{dialectPostgres, `SET "search-path" = s, pg_catalog`, true},
		{dialectPostgres, `SET LOCAL search_path TO s, pg_catalog`, true},
		{dialectPostgres, `SET search_path = s pg_catalog`, true},
		{dialectPostgres, `SET search_path = s,`, true},
		{dialectPostgres, `SET search_path = 1`, true},
		{dialectPostgres, `SET search_path = 'it''s'`, true},
		{dialectPostgres, `SET SCHEMA E'x'`, true},
		{dialectPostgres, `SET U&"search\005fpath" = s, pg_catalog`, true},
		{dialectPostgres, `SET U&"sea\0072ch\005fpa\0074h" = s`, true},
		{dialectPostgres, `SET search_path = s, ` + long + `, pg_catalog`, true},
		{dialectPostgres, `SET standard_conforming_strings = E'o\x6e'`, true},
		{dialectPostgres, `SET standard_conforming_strings = $$on$$`, true},
		{dialectPostgres, `SET client_encoding = E'SJ\x49S'`, true},
		{dialectPostgres, `SET client_encoding = $$UTF8$$`, true},
		{dialectPostgres, `SET "client_encoding" = 'SJIS'`, true},
		{dialectPostgres, `SET NAMES`, true},
		{dialectPostgres, `SET a.b = search_path`, true},
		{dialectPostgres, `SELECT set_config('search_path', 's,pg_catalog', false)`, true},
		{dialectPostgres, `SELECT pg_catalog.set_config('client-encoding', 'SJIS', false)`, true},
		{dialectPostgres, `SELECT set_config(E'search\x5fpath', 's', false)`, true},
		{dialectPostgres, `SELECT set_config($1, 's', false)`, true},
		{dialectPostgres, `SELECT "set_config"('search_path', 's', false)`, true},
		{dialectPostgres, `SET search_path = "$user", public`, false},
		{dialectPostgres, `SET search_path = 'app', public`, false},
		{dialectPostgres, `SET search_path TO DEFAULT`, false},
		{dialectPostgres, `SET search_path = ''`, false},
		{dialectPostgres, `SET SCHEMA 'app'`, false},
		{dialectPostgres, `SET NAMES 'UTF8'`, false},
		{dialectPostgres, `SET standard_conforming_strings = 1`, false},
		{dialectPostgres, `SET TIME ZONE 'UTC'`, false},
		{dialectPostgres, `SET application_name = 'search_path'`, false},
		{dialectPostgres, `SELECT set_config('app.user', 'x', true)`, false},

		{dialectMySQL, "SET `sql_mode`='ANSI_QUOTES'", true},
		{dialectMySQL, `SET sql_mode='A\NSI_QUOTES'`, true},
		{dialectMySQL, "SET @@`sql_mode`='ANSI'", true},
		{dialectMySQL, "SET @@session.`SQL_MODE` = 'ANSI'", true},
		{dialectMySQL, "SET SESSION `sql-mode` = 'ANSI'", true},
		{dialectMySQL, "SET `character_set_client`=gbk", true},
		{dialectMySQL, "SET @@session.character_set_client = gbk", true},
		{dialectMySQL, "SET sql_mode = 4", true},
		{dialectMySQL, "SET sql_mode = 0x4", true},
		{dialectMySQL, "SET sql_mode = _utf8mb4'ANSI_QUOTES'", true},
		{dialectMySQL, "SET sql_mode = x'414e5349'", true},
		{dialectMySQL, "SET sql_mode = (SELECT 'ANSI')", true},
		{dialectMySQL, "SET sql_mode = DEFAULT", true},
		{dialectMySQL, "SET sql_mode = CONCAT('AN', 'SI')", true},
		{dialectMySQL, "SET sql_mode = CONCAT (@@sql_mode, ',STRICT_ALL_TABLES')", true},
		{dialectMySQL, "SET sql_mode = CONCAT(@@global.sql_mode, ',STRICT_ALL_TABLES')", true},
		{dialectMySQL, "SET sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES', ',ANSI')", true},
		{dialectMySQL, "SET sql_mode = CONCAT(@@sql_mode, @x)", true},
		{dialectMySQL, "SET sql_mode = 'STRICT_TRANS_TABLES,ANSI'", true},
		{dialectMySQL, "SET sql_mode = 'STRICT_ALL_TABLES''ANSI'", true},
		{dialectMySQL, "SET sql_mode = 'ROLLED_OUT_LATER'", true},
		{dialectMySQL, "SET a = 1, sql_mode = 'ANSI'", true},
		{dialectMySQL, "SET a = (1, 2), `sql_mode` = 'ANSI'", true},
		{dialectMySQL, "SET sql_mode", true},
		{dialectMySQL, `SET NAMES 'g\bk'`, true},
		{dialectMySQL, "SET NAMES gbk COLLATE gbk_bin", true},
		{dialectMySQL, "SET NAMES utf8mb4 WHATEVER", true},
		{dialectMySQL, "SET NAMES DEFAULT", true},
		{dialectMySQL, "SET CHARACTER SET gbk", true},
		{dialectMySQL, "SET /*! sql_mode */ = 'x'", true},
		{dialectMySQL, "SET NAMES latin2", false},
		{dialectMySQL, "SET NAMES 'latin2' COLLATE 'latin2_bin'", false},
		{dialectMySQL, "SET CHARACTER SET cp1251", false},
		{dialectMySQL, "SET character_set_connection = gbk", false},
		{dialectMySQL, "SET @@SESSION.sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483", false},
		{dialectMySQL, "SET sql_mode = CONCAT(@@session.sql_mode, ',NO_ZERO_DATE,NO_ZERO_IN_DATE', ',TRADITIONAL')", false},
		{dialectMySQL, "SET sql_mode = ''", false},
		{dialectMySQL, `SET sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_DATE"`, false},
		{dialectMySQL, "SET sql_mode = TRADITIONAL", false},
		{dialectMySQL, "SET @m = @@sql_mode", false},
		{dialectMySQL, "SET NAMES utf8mb4, sql_mode = ''", false},
		{dialectMySQL, "SET autocommit = 1", false},
	} {
		got := parseSQL(tc.d, tc.sql)
		taint := ""
		for i := range got {
			if got[i].taint != "" {
				taint = got[i].taint
			}
		}
		if (taint != "") != tc.taint {
			t.Errorf("%v %q: taint %q, want %v", tc.d, tc.sql, taint, tc.taint)
		}
	}
}

// A SET the witness could not read is opaque, and what it may have set still goes
// for what follows a Mark.
func TestReview7GlobalSetKeepsItsTaint(t *testing.T) {
	s := classOf(t, dialectMySQL, "SET @@`global`.sql_mode = 'ANSI'")
	if s.class != classOpaque || s.taint == "" {
		t.Fatalf("%+v", s)
	}
}

func TestReview7LoginSettings(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		taint      bool
	}{
		{"search_path", "s,pg_catalog,public", true},
		{"SEARCH_PATH", "s,pg_catalog,public", true},
		{"Search_Path", `s,"pg_catalog"`, true},
		{"search-path", "s,PG_CATALOG", true},
		{"search_path", `s,pg\_catalog`, true},
		{"search_path", "app,public", false},
		{"search_path", `"$user",public`, false},
		{"standard_conforming_strings", "off", true},
		{"STANDARD_CONFORMING_STRINGS", "off", true},
		{"standard_conforming_strings", "on", false},
		{"client_encoding", "SJIS", true},
		{"CLIENT-ENCODING", "BIG5", true},
		{"client_encoding", "UTF8", false},
		{"application_name", "pg_catalog", false},
		{"options", "-c search-path=s,pg_catalog,public", true},
		{"OPTIONS", "-c search_path=s,pg_catalog", true},
		{"options", "--search-path=s,pg_catalog", true},
		{"options", "-csearch_path=s,pg_catalog", true},
		{"options", `-c search\_path=s,pg\_catalog`, true},
		{"options", `-c Search_Path=s,\ pg_catalog`, true},
		{"options", "-c client-encoding=SJIS", true},
		{"options", "-c statement_timeout=5 -c standard-conforming-strings=off", true},
		{"options", "-ec search_path=s,pg_catalog", true}, // a switch it does not read
		{"options", "-B=1", true},
		{"options", "-c", true},
		{"options", "-c search_path", true},
		{"options", "-c search_path=app,public", false},
		{"options", "-c statement_timeout=5 --lock_timeout=1", false},
		{"options", "", false},
	} {
		w := newPG(t)
		w.client(pgStartup(3<<16, append(append(cstr(tc.key), cstr(tc.value)...), 0)...))
		if (w.s.(*pgSession).taint != "") != tc.taint {
			t.Errorf("%s=%q: taint %q, want %v", tc.key, tc.value, w.s.(*pgSession).taint, tc.taint)
		}
	}
}

// H3, F1: a keyword is excused only where no call can stand.
func TestReview7CallPositions(t *testing.T) {
	for _, tc := range []sqlCase{
		// H3 and what it would turn into if the excuses were looser.
		pgOnly("SELECT 1 AS a ORDER BY rollup(1)", "opaque"),
		pgOnly("SELECT 1 AS a ORDER BY cube(1)", "opaque"),
		pgOnly("SELECT row_number() OVER (PARTITION BY cube(1)) FROM t", "opaque"),
		pgOnly("SELECT 1 FROM t a JOIN t b ON conflict(1) = 1", "opaque"),
		pgOnly("SELECT 1 FROM t a JOIN t b ON conflict(1) WHERE true", "opaque"),
		pgOnly("INSERT INTO z SELECT 1 FROM a JOIN b ON conflict(1) ON CONFLICT DO NOTHING", "opaque"),
		pgOnly("UPDATE one SET a = CASE WHEN true THEN insert(1) ELSE 0 END", "opaque"),
		pgOnly("UPDATE one SET a = CASE WHEN x THEN 1 WHEN matched THEN insert(1) END", "opaque"),
		pgOnly("UPDATE one SET a = CASE WHEN CASE WHEN x THEN true END THEN insert(1) END", "opaque"),
		pgOnly("MERGE INTO t USING s ON true WHEN MATCHED THEN UPDATE SET a = CASE WHEN b THEN insert(1) ELSE 0 END", "opaque"),
		// A call where an operand could end, or seems to.
		pgOnly("SELECT DISTINCT ON (a) w(1) FROM t", "opaque"),
		pgOnly("SELECT DISTINCT ON (a) over(1) FROM t", "opaque"),
		pgOnly("SELECT DISTINCT ON (a) like(1, 2) FROM t", "opaque"),
		pgOnly("SELECT a FROM t WHERE NOT like(1, 2)", "opaque"),
		pgOnly("SELECT a FROM t WHERE like('a', 'b')", "opaque"),
		pgOnly("SELECT 1 FROM a, join(1)", "opaque"),
		pgOnly("SELECT 1 FROM join(1)", "opaque"),
		pgOnly("SELECT join(1)", "opaque"),
		pgOnly("SELECT 1 + join(1)", "opaque"),
		pgOnly("SELECT now() AT TIME ZONE join(1)", "opaque"),
		pgOnly("SELECT 'a' LIKE 'b' ESCAPE join(1)", "opaque"),
		pgOnly("SELECT sum(a) OVER (ROWS join(1) PRECEDING) FROM t", "opaque"),
		pgOnly("SELECT a FROM t FETCH FIRST join(1) ROWS ONLY", "opaque"),
		pgOnly("SELECT a FROM t GROUP BY ALL cube(1)", "opaque"),
		pgOnly("SELECT 1 OPERATOR(public.+) 2", "opaque"),
		pgOnly("SELECT a FROM t WHERE a OPERATOR(public.~) 'b'", "opaque"),
		pgOnly("SELECT a FROM t WHERE a OPERATOR(pg_catalog.###) 'b'", "opaque"),
		pgOnly("SELECT 1, w(1) AS x FROM t", "opaque"),
		pgOnly("SELECT 1, w(1) AS not FROM t", "opaque"),
		pgOnly("WITH t(a) AS (SELECT w()) SELECT a FROM t", "opaque"),
		pgOnly("WITH t AS NOT MATERIALIZED (SELECT w()) SELECT 1 FROM t", "opaque"),
		pgOnly("SELECT 1 FROM unnest(w(1)) AS t(id)", "opaque"),
		pgOnly("SELECT * FROM (VALUES (w(1))) AS v(id)", "opaque"),
		pgOnly("INSERT INTO o AS u (id) VALUES (w(1))", "opaque"),
		myOnly("WITH t(a) AS (SELECT w()) SELECT a FROM t", "opaque"),
		myOnly("SELECT 1, w(1) AS x FROM t", "opaque"),
		myOnly("SELECT * FROM (VALUES ROW(w(1))) AS v(id)", "opaque"),

		// F1: what is not a call.
		pgOnly("SELECT 1 FROM a JOIN (SELECT 1 AS id) b ON a.id = b.id", "read"),
		pgOnly("SELECT 1 FROM a x JOIN (SELECT 1 AS id) b ON true JOIN (SELECT 2) c ON x.id = c.id JOIN (SELECT 3) d USING (id) JOIN (SELECT 4) e ON TRUE", "read"),
		pgOnly(`SELECT 1 FROM "a" JOIN (SELECT 1) b ON true`, "read"),
		pgOnly("SELECT 1 FROM s.a JOIN (SELECT 1) b ON true", "read"),
		pgOnly("SELECT 1 FROM a NATURAL JOIN (SELECT 1 AS id) b", "read"),
		pgOnly("SELECT id FROM unnest(ARRAY[1,2]) AS t(id)", "read"),
		pgOnly("SELECT id FROM unnest(ARRAY[1,2]) t(id)", "read"),
		pgOnly("SELECT id FROM unnest(ARRAY[1,2]) WITH ORDINALITY AS t(id, n)", "read"),
		pgOnly("SELECT * FROM (VALUES (1, 'a')) AS v(id, x)", "read"),
		pgOnly(`SELECT * FROM (VALUES (1)) AS "data"("id")`, "read"),
		pgOnly(`SELECT * FROM (VALUES (1)) "data"("id")`, "read"),
		pgOnly("SELECT * FROM t x(a, b)", "read"),
		pgOnly("UPDATE o SET id = v.id FROM (VALUES (1)) AS v(id) WHERE o.id = v.id", "write", "o"),
		pgOnly("WITH t(a) AS (SELECT 1) SELECT a FROM t", "read"),
		pgOnly("WITH RECURSIVE t(a) AS (SELECT 1 UNION ALL SELECT a + 1 FROM t WHERE a < 3) SELECT a FROM t", "read"),
		pgOnly("WITH a(x) AS (SELECT 1), b(y) AS NOT MATERIALIZED (SELECT 2) SELECT 1 FROM a, b", "read"),
		pgOnly("WITH a AS NOT MATERIALIZED (SELECT 1), b AS MATERIALIZED (SELECT 2) SELECT 1 FROM a, b", "read"),
		pgOnly("INSERT INTO o AS u (id) VALUES (1)", "write", "o"),
		pgOnly("INSERT INTO o AS u (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = u.id", "write", "o"),
		pgOnly(`INSERT INTO "o" AS "u" ("id") VALUES (1)`, "write", "o"),
		pgOnly("INSERT INTO o AS u (update) VALUES (1)", "write", "o"), // a column, as it is with no alias
		pgOnly("SELECT id FROM t WHERE v LIKE ('a%')", "read"),
		pgOnly("SELECT id FROM t WHERE t.name LIKE ('a%') AND t.type NOT ILIKE ('a')", "read"),
		pgOnly("SELECT id FROM t WHERE name NOT LIKE ('a%')", "read"),
		pgOnly("SELECT id FROM t WHERE v LIKE 'a%' ESCAPE '!'", "read"),
		pgOnly("SELECT id FROM t WHERE $1 LIKE ($2)", "read"),
		pgOnly("SELECT trim(both 'x' from 'xax'), trim(leading 'x' from 'xa'), trim(trailing 'x' from 'ax')", "read"),
		pgOnly("SELECT now() AT TIME ZONE ('UTC')", "read"),
		pgOnly("SELECT TIMESTAMP WITH TIME ZONE '2020-01-01 00:00:00+00'", "read"),
		pgOnly("SELECT (DATE '2020-01-01', DATE '2020-01-02') OVERLAPS (DATE '2020-01-01', DATE '2020-01-03')", "read"),
		pgOnly("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1 WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)", "write", "t"),
		pgOnly("MERGE INTO t USING s ON true WHEN MATCHED AND CASE WHEN a THEN true END THEN DELETE WHEN NOT MATCHED AND b THEN INSERT (id) VALUES (1)", "write", "t"),
		pgOnly("INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO NOTHING", "write", "t"),
		pgOnly("SELECT a FROM t ORDER BY (a), (b)", "read"),
		pgOnly("ALTER TABLE z ADD CONSTRAINT f FOREIGN KEY (a) REFERENCES u (id)", "write", "z"),
		myOnly("ALTER TABLE z ADD CONSTRAINT f FOREIGN KEY (a) REFERENCES u (id)", "write", "z"),
		myOnly("SELECT * FROM (VALUES ROW(1)) AS v(id)", "read"),
		myOnly("SELECT * FROM (VALUES ROW(1)) v(id)", "read"),
		myOnly("WITH t(a) AS (SELECT 1) SELECT a FROM t", "read"),
		myOnly("WITH RECURSIVE t(a) AS (SELECT 1 UNION ALL SELECT a + 1 FROM t WHERE a < 3) SELECT a FROM t", "read"),
		myOnly("INSERT INTO t (a) VALUES (1) AS new(a) ON DUPLICATE KEY UPDATE a = new.a", "write", "t"),

		// ORM-shaped controls, as gorm, Prisma, Hibernate, Rails, Django, Ecto and
		// SQLAlchemy lay them out.
		pgOnly(`SELECT "users"."id", "users"."name" FROM "users" WHERE "users"."deleted_at" IS NULL AND ("users"."id" = $1) ORDER BY "users"."id" LIMIT $2 OFFSET $3`, "read"),
		pgOnly(`SELECT "public"."User"."id" FROM "public"."User" WHERE ("public"."User"."id" = $1 AND 1=1) LIMIT $2 OFFSET $3`, "read"),
		pgOnly(`SELECT "t0"."id", COUNT(*) AS "__count" FROM "users" AS "t0" LEFT OUTER JOIN "posts" AS "p1" ON "p1"."uid" = "t0"."id" GROUP BY "t0"."id" HAVING COUNT(*) > 1`, "read"),
		pgOnly(`select u1_0.id,u1_0.name from users u1_0 join (select p.uid from posts p where p.id=$1) s1_0 on u1_0.id=s1_0.uid where u1_0.id=any($2) for no key update`, "read"),
		pgOnly(`SELECT "users".* FROM "users" INNER JOIN (SELECT "posts"."uid" FROM "posts") "x" ON "x"."uid" = "users"."id" WHERE "users"."name" NOT IN ('a', 'b') LIMIT 1`, "read"),
		pgOnly(`SELECT u0."id" FROM "users" AS u0 LEFT OUTER JOIN LATERAL (SELECT 1) AS s1 ON TRUE WHERE (u0."id" = ANY($1)) FOR UPDATE SKIP LOCKED`, "read"),
		pgOnly(`UPDATE "users" SET "name" = "data"."name" FROM (VALUES (1, 'a'), (2, 'b')) AS "data"("id", "name") WHERE "users"."id" = "data"."id"`, "write", "users"),
		pgOnly(`INSERT INTO o (id) SELECT p0::int FROM (VALUES (1, 0), (2, 1)) AS imp_sen(p0, sen_counter) ORDER BY sen_counter RETURNING o.id, o.id AS id__1`, "write", "o"),
		pgOnly(`INSERT INTO "users" ("id", "name") VALUES ($1, $2) ON CONFLICT ("id") DO UPDATE SET "name" = EXCLUDED."name" RETURNING "id"`, "write", "users"),
		pgOnly(`INSERT INTO "users" ("id") VALUES (DEFAULT) ON CONFLICT ON CONSTRAINT users_pkey DO NOTHING RETURNING "id"`, "write", "users"),
		pgOnly(`SELECT CAST($1 AS text), COALESCE(a, 0), EXTRACT(YEAR FROM b), a BETWEEN 1 AND 2 FROM t`, "read"),
		myOnly("SELECT `users`.`id` FROM `users` INNER JOIN (SELECT `uid` FROM `posts`) `x` ON `x`.`uid` = `users`.`id` WHERE `users`.`id` = 1 LIMIT 1", "read"),
		myOnly("INSERT INTO `users` (`id`) VALUES (1) ON DUPLICATE KEY UPDATE `id` = VALUES(`id`)", "write", "users"),
		myOnly("SELECT COUNT(*) FROM `users` LEFT JOIN `posts` ON `posts`.`uid` = `users`.`id` WHERE `users`.`name` LIKE ('a%')", "read"),
	} {
		wantClass(t, tc)
	}
}

// wantClass holds one statement to its class on each engine it names.
func wantClass(t *testing.T, tc sqlCase) {
	t.Helper()
	for _, d := range []dialect{dialectPostgres, dialectMySQL} {
		if (d == dialectPostgres && !tc.pg) || (d == dialectMySQL && !tc.my) {
			continue
		}
		s := classOf(t, d, tc.sql)
		if s.class.String() != tc.want || (tc.want == "write" && strings.Join(s.tables, ",") != strings.Join(tc.tables, ",")) {
			t.Errorf("%v %q: %s %v (%s), want %s %v", d, tc.sql, s.class, s.tables, s.reason, tc.want, tc.tables)
		}
	}
}

// M2, and the rest of its class: a word the grammar would take as a type is only
// a keyword in its one position.
func TestReview7Types(t *testing.T) {
	for _, tc := range []sqlCase{
		pgOnly("SELECT 1::double", "opaque"),
		pgOnly("SELECT CAST(1 AS double)", "opaque"),
		pgOnly("SELECT double '1'", "opaque"),
		pgOnly("SELECT x '1'", "opaque"),
		pgOnly("SELECT b '1'", "opaque"),
		pgOnly("SELECT e '1'", "opaque"),
		pgOnly("SELECT n '1'", "opaque"),
		pgOnly("SELECT zone '1'", "opaque"),
		pgOnly("SELECT by '1'", "opaque"),
		pgOnly("SELECT set '1'", "opaque"),
		pgOnly("SELECT like '1'", "opaque"),
		pgOnly("SELECT ilike '1'", "opaque"),
		pgOnly("SELECT escape '1'", "opaque"),
		pgOnly("SELECT names '1'", "opaque"),
		pgOnly("UPDATE t SET a = names '1'", "opaque"),
		pgOnly("SELECT 1::pg_catalog.mydomain", "opaque"),
		pgOnly("SELECT 1::public.int", "opaque"),
		pgOnly("SELECT 1::pg_catalog.a.b", "opaque"),
		pgOnly("SELECT 1::double precision, CAST(1 AS double precision), X'1F', B'1', N'a', E'a'", "read"),
		pgOnly("SELECT a FROM t WHERE a NOT LIKE 'x' AND b ILIKE 'y' ORDER BY 1", "read"),
		pgOnly("SELECT uuid '00000000-0000-0000-0000-000000000000', text 'a', int '1'", "read"),
		pgOnly("SET ROLE 'bob'", "read"),
		pgOnly("SET LOCAL ROLE 'bob'", "read"),
		pgOnly("SET SESSION AUTHORIZATION 'bob'", "read"),
	} {
		wantClass(t, tc)
	}
}

// L1: what a driver and a client send.
func TestReview7ListedBuiltins(t *testing.T) {
	for _, tc := range []sqlCase{
		pgOnly("select $1::text::regtype::oid", "read"),
		pgOnly("SELECT 'a'::regclass, 1::oid, 'a'::name, '127.0.0.1'::inet, 'a'::pg_catalog.text", "read"),
		pgOnly(`SELECT j #>> '{a}', j #> '{a}', j ? 'a', j ?| k, j ?& k, j #- '{a}', ARRAY[1] && ARRAY[1], v @@ q, 5 & 1, 5 | 1, 1 << 2, 8 >> 1 FROM t`, "read"),
		pgOnly(`SELECT pg_catalog.pg_get_userbyid(c.relowner), pg_catalog.pg_table_is_visible(c.oid) FROM pg_catalog.pg_class c WHERE c.relname OPERATOR(pg_catalog.~) '^(x)$' COLLATE pg_catalog.default`, "read"),
		pgOnly("SELECT pg_get_userbyid(1), pg_catalog.pg_get_viewdef(1), json_build_object('a', 1), quote_ident('a')", "read"),
		myOnly("SELECT JSON_OBJECT('a', 1), JSON_ARRAY(1), JSON_LENGTH(j), JSON_UNQUOTE(j), JSON_CONTAINS(j, '1') FROM t", "read"),
		// The rest stays opaque: the list is of what is shown inert.
		pgOnly("SELECT 1 # 2", "opaque"),
		pgOnly("SELECT query_to_xml('DELETE FROM t', true, true, '')", "opaque"),
		pgOnly("SELECT pg_catalog.pg_read_file('x')", "opaque"),
		pgOnly("SELECT 1::regconfig", "opaque"),
		myOnly("SELECT JSON_OBJECT ('a', 1)", "opaque"),
	} {
		wantClass(t, tc)
	}
}

// H7: LOAD DATA's SET clause runs for every row; the column list and its other
// clauses are not expressions.
func TestReview7LoadData(t *testing.T) {
	for _, tc := range []sqlCase{
		myOnly("LOAD DATA INFILE 'f' INTO TABLE z (a) SET b = f()", "opaque"),
		myOnly("LOAD DATA INFILE 'f' INTO TABLE z CHARACTER SET latin1 (a) SET b = f()", "opaque"),
		myOnly("LOAD DATA INFILE 'f' INTO TABLE z (a) SET b = (SELECT f())", "opaque"),
		myOnly("LOAD DATA INFILE 'f' INTO TABLE z SET b = f()", "opaque"),
		myOnly("LOAD DATA INFILE 'f' INTO TABLE z", "write", "z"),
		myOnly("LOAD DATA LOCAL INFILE 'f' REPLACE INTO TABLE z CHARACTER SET utf8mb4 FIELDS TERMINATED BY ',' LINES TERMINATED BY '\\n' IGNORE 1 LINES (a, @b) SET c = UPPER(@b)", "write", "z"),
		myOnly("LOAD DATA INFILE 'f' INTO TABLE z IGNORE 1 ROWS (a, b)", "write", "z"),
	} {
		wantClass(t, tc)
	}
}

// H8: a change that routes rows between tables, seen on the wire, is opaque as
// RENAME is. A claim's table is otherwise whatever the statement names.
func TestReview7Routing(t *testing.T) {
	for _, tc := range []sqlCase{
		pgOnly("ALTER TABLE child INHERIT users", "opaque"),
		pgOnly("ALTER TABLE st.moved SET SCHEMA public", "opaque"),
		pgOnly("ALTER TABLE p ATTACH PARTITION p_a FOR VALUES FROM (0) TO (10)", "opaque"),
		pgOnly("CREATE TABLE c () INHERITS (users)", "opaque"),
		pgOnly("CREATE TABLE c (a int) INHERITS (users)", "opaque"),
		pgOnly("CREATE TABLE p_a PARTITION OF p FOR VALUES FROM (0) TO (10)", "opaque"),
		pgOnly("ALTER TABLE child NO INHERIT users", "write", "child"),
		pgOnly("ALTER TABLE z ADD CHECK (a > 0) NO INHERIT", "write", "z"),
		pgOnly("ALTER TABLE z SET (fillfactor = 70)", "write", "z"),
		pgOnly("CREATE TABLE z (inherits int)", "write", "z"),
		pgOnly("CREATE TABLE p (id int) PARTITION BY RANGE (id)", "write", "p"),
		// The relation itself installed off the listener: only the name is seen.
		pgOnly("INSERT INTO v VALUES (1)", "write", "v"),
	} {
		wantClass(t, tc)
	}
	limit := false
	for _, m := range alwaysMissed {
		limit = limit || (strings.Contains(m, "updatable view") && strings.Contains(m, "partition") && strings.Contains(m, "only as good as the name"))
	}
	if !limit {
		t.Fatal("Missed must state that a claim is only as good as the name in the statement")
	}
}

// H5: LOCK TABLES commits before it opens the table, so its ERR has committed
// what came before. So may anything not known to leave the transaction alone.
func TestReview7FailedStatementThatMayCommit(t *testing.T) {
	for _, tc := range []struct {
		sql, want string
	}{
		{"LOCK TABLES no_such WRITE", "committed INSERT"},
		{"UNLOCK TABLES", "committed INSERT"},
		{"RESET MASTER", "committed INSERT"},
		{"ANALYZE TABLE no_such", "committed INSERT"},
		{"DROP TABLE no_such", "committed INSERT"},
		{"SELECT * FROM no_such", "rolled_back INSERT"},
		{"INSERT INTO no_such VALUES (1)", "rolled_back INSERT"},
		{"SET x = 1", "rolled_back INSERT"},
		{"ROLLBACK TO no_such", "rolled_back INSERT"},
	} {
		w := myReadyWire(t, 0)
		w.client(myQuery("START TRANSACTION"))
		w.server(myOK(1, 0, stAutocommit|stInTrans, 0))
		w.client(myQuery("INSERT INTO a VALUES (1)"))
		w.server(myOK(1, 1, stAutocommit|stInTrans, 0))
		w.client(myQuery(tc.sql))
		w.server(myErr(1))
		w.client(myQuery("ROLLBACK"))
		w.server(myOK(1, 0, stAutocommit, 0))
		if got := w.outcomes(); !slices.Contains(got, tc.want) {
			t.Errorf("%q: %v, want %s", tc.sql, got, tc.want)
		}
	}
}

// H6: MySQL compares savepoint names without case, quoted or not, and a second
// savepoint of a name replaces the first.
func TestReview7MySQLSavepointNames(t *testing.T) {
	run := func(second, back string) []string {
		w := myReadyWire(t, 0)
		for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", "INSERT INTO t VALUES (1)", second, back, "COMMIT"} {
			w.client(myQuery(q))
			status := uint16(stAutocommit | stInTrans)
			if q == "COMMIT" {
				status = stAutocommit
			}
			w.server(myOK(1, 0, status, 0))
		}
		return w.outcomes()
	}
	for _, tc := range []struct {
		second, back, want string
	}{
		{"SAVEPOINT `A`", "ROLLBACK TO a", "committed INSERT"},
		{"SAVEPOINT A", "ROLLBACK TO `a`", "committed INSERT"},
		{"SAVEPOINT a", "ROLLBACK TO SAVEPOINT A", "committed INSERT"},
		{"SAVEPOINT `á`", "ROLLBACK TO a", "committed INSERT"},  // a _ci collation folds accents
		{"SAVEPOINT `a `", "ROLLBACK TO a", "committed INSERT"}, // and pads with spaces
		{"SAVEPOINT b", "ROLLBACK TO A", "rolled_back INSERT"},
		{"SAVEPOINT b", "ROLLBACK TO `a`", "rolled_back INSERT"},
	} {
		if got := run(tc.second, tc.back); !slices.Contains(got, tc.want) {
			t.Errorf("%s, %s: %v, want %s", tc.second, tc.back, got, tc.want)
		}
	}
}

// Only the one of that name goes: a savepoint between them stays.
func TestReview7MySQLSavepointBetweenStays(t *testing.T) {
	w := myReadyWire(t, 0)
	for _, q := range []string{"START TRANSACTION", "SAVEPOINT a", "SAVEPOINT b", "SAVEPOINT a", "INSERT INTO t VALUES (1)", "ROLLBACK TO b", "COMMIT"} {
		w.client(myQuery(q))
		status := uint16(stAutocommit | stInTrans)
		if q == "COMMIT" {
			status = stAutocommit
		}
		w.server(myOK(1, 0, status, 0))
	}
	w.want("rolled_back INSERT")
}

// Postgres keeps both, and a quoted name is its own.
func TestReview7PostgresSavepointNames(t *testing.T) {
	w := pgReadyWire(t)
	for _, q := range [][2]string{{"BEGIN", "BEGIN"}, {"SAVEPOINT a", "SAVEPOINT"}, {"INSERT INTO t VALUES (1)", "INSERT 0 1"},
		{`SAVEPOINT "A"`, "SAVEPOINT"}, {`ROLLBACK TO a`, "ROLLBACK"}, {"COMMIT", "COMMIT"}} {
		w.client(pgQuery(q[0]))
		status := byte('T')
		if q[0] == "COMMIT" {
			status = 'I'
		}
		w.server(pgDone(q[1]), pgReady(status))
	}
	w.want("rolled_back INSERT")
}

// M1: a routine can swap what a prepared name holds, and neither a rollback nor a
// failure takes that back.
func TestReview7OpaqueStatementForgetsPreparedNames(t *testing.T) {
	setup := func(t *testing.T) *wire {
		w := pgReadyWire(t)
		w.client(pgParse("s7", "SELECT 1"), pgBind("p7", "s7"), pgSync())
		w.server(frame('1'), frame('2'), pgReady('I'))
		return w
	}
	check := func(t *testing.T, w *wire, frames ...[]byte) {
		t.Helper()
		w.client(frames...)
		w.server(frame('2'), pgDone("SELECT 1"), pgReady('I'))
		found := false
		for _, e := range w.cap.snapshot() {
			found = found || (e.Verb == "EXECUTE" && e.Opaque)
		}
		if !found {
			t.Fatalf("a name a routine could have changed read as what it held: %+v", w.cap.snapshot())
		}
	}
	t.Run("after a rollback", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("BEGIN; SELECT rp(); ROLLBACK"))
		w.server(pgDone("BEGIN"), pgDone("SELECT 1"), pgDone("ROLLBACK"), pgReady('I'))
		check(t, w, pgBind("", "s7"), pgExecute(""), pgSync())
	})
	t.Run("after a failure", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("SELECT rp()"))
		w.server(pgError(), pgReady('I'))
		check(t, w, pgBind("", "s7"), pgExecute(""), pgSync())
	})
	t.Run("a portal too", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("SELECT rp()"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		w.client(pgExecute("p7"), pgSync())
		w.server(pgDone("SELECT 1"), pgReady('I'))
		last := w.cap.snapshot()
		if e := last[len(last)-1]; !e.Opaque {
			t.Fatalf("%+v", last)
		}
	})
	t.Run("a fast-path call", func(t *testing.T) {
		w := setup(t)
		w.client(frame('F'))
		w.server(frame('V'), pgReady('I'))
		check(t, w, pgBind("", "s7"), pgExecute(""), pgSync())
	})
	t.Run("a read leaves them", func(t *testing.T) {
		w := setup(t)
		w.client(pgQuery("SELECT lower('x')"))
		w.server(pgDone("SELECT 1"), pgReady('I'))
		w.client(pgBind("", "s7"), pgExecute(""), pgSync())
		w.server(frame('2'), pgDone("SELECT 1"), pgReady('I'))
		for _, e := range w.cap.snapshot() {
			if e.Opaque {
				t.Fatalf("%+v", e)
			}
		}
	})
}

// The lists in classify.go and the files the live tests hold against a real server
// must be the same lists.
func TestReview7ListsMatchTestdata(t *testing.T) {
	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	for file, list := range map[string]map[string]bool{
		"testdata/pg-keywords.txt":         pgKeywords,
		"testdata/pg-listed-funcs.txt":     pgSafeFuncs,
		"testdata/pg-listed-types.txt":     pgTypes,
		"testdata/pg-listed-operators.txt": pgOperators,
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Fields(string(b)); !slices.Equal(got, keys(list)) {
			t.Errorf("%s does not match the list in classify.go", file)
		}
	}
}
