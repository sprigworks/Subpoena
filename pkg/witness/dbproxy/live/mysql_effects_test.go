//subpoena:impl_derived
//subpoena:pure_logic

// MySQL witness verdicts checked against rows read through a direct connection.
package live

import (
	"database/sql"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/harness"
)

func TestMySQLIndirectWrites(t *testing.T) {
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
func TestMySQLCommentEdges(t *testing.T) {
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

func TestMySQLReadOnlyControls(t *testing.T) {
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

func TestMySQLSessionAndTransactionWrites(t *testing.T) {
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
func TestMySQLEndOfSessionIsNotARollback(t *testing.T) {
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

func TestMySQLStatementsWithoutClaimedRows(t *testing.T) {
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
