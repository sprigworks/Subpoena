//subpoena:impl_derived
//subpoena:pure_logic

// SQL settings and login parameters that affect parsing or name lookup.
package dbproxy

import (
	"strings"
	"testing"
)

// H1, H2, L2: a setting that changes lexing or lookup counts in any spelling, and
// only a value that is plainly safe keeps the session.
func TestSetTaint(t *testing.T) {
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
func TestGlobalSetKeepsItsTaint(t *testing.T) {
	s := classOf(t, dialectMySQL, "SET @@`global`.sql_mode = 'ANSI'")
	if s.class != classOpaque || s.taint == "" {
		t.Fatalf("%+v", s)
	}
}

func TestLoginSettings(t *testing.T) {
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
