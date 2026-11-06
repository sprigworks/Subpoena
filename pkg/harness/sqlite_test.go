//subpoena:spec_derived
//subpoena:pure_logic

// The SQLite absence checks, from the brief's "Not a trigger" and
// "Inconclusive is a first-class verdict" notes: a denied request may write an
// audit row to the same file, so the claim is about commits and tables.
package harness

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

type fakeDB struct {
	change witness.SQLiteChange
	saw    *[]witness.FileEvent
}

func (d fakeDB) Path() string { return "/r/app.db" }
func (d fakeDB) Change(events []witness.FileEvent) witness.SQLiteChange {
	if d.saw != nil {
		*d.saw = events
	}
	return d.change
}

func TestNoCommitVerdicts(t *testing.T) {
	gap := errors.New("queue overflowed")
	healthy := healthFile{unknownFile: wroteTo()}
	sick := healthFile{unknownFile: wroteTo(), err: gap}
	schema := []string{"audit", "users"}
	none := witness.SQLiteChange{Verdict: witness.SQLiteNoChange, Exact: true, Schema: schema}
	audit := witness.SQLiteChange{Verdict: witness.SQLiteCommitted, Exact: true, Tables: []string{"audit"}, Schema: schema}
	netAudit := audit
	netAudit.Exact = false
	unknown := witness.SQLiteChange{Verdict: witness.SQLiteUnknown, Reason: "journal"}
	unread := witness.SQLiteChange{Verdict: witness.SQLiteCommitted, Pages: []uint32{3}, TableError: "bad tree"}
	for _, tc := range []struct {
		name   string
		w      witness.FileWitness
		c      witness.SQLiteChange
		tables []string
		want   Verdict
	}{
		{"nothing, healthy", healthy, none, nil, Pass},
		{"nothing, unhealthy", sick, none, nil, Inconclusive},
		{"nothing, no health", wroteTo(), none, nil, Inconclusive},
		{"commit", healthy, audit, nil, Fail},
		{"commit, unhealthy", sick, audit, nil, Fail},
		{"the audit row is not the claim", healthy, audit, []string{"users"}, Pass},
		{"the table is the claim", healthy, audit, []string{"audit"}, Fail},
		{"case does not hide it", healthy, audit, []string{"AUDIT"}, Fail},
		{"named on a net diff still fails", healthy, netAudit, []string{"audit"}, Fail},
		{"not named, but the list is a floor", healthy, netAudit, []string{"users"}, Inconclusive},
		{"tables unread", healthy, unread, []string{"users"}, Inconclusive},
		{"tables unread, no table claim", healthy, unread, nil, Fail},
		{"unknown", healthy, unknown, nil, Inconclusive},
		{"unknown, with a table", healthy, unknown, []string{"users"}, Inconclusive},
		{"a table the database never had", healthy, none, []string{"usres"}, Inconclusive},
		{"unwatched", healthFile{unknownFile: unknownFile{roots: []string{"/else"}}}, none, nil, Inconclusive},
		{"unhealthy, audit only", sick, audit, []string{"users"}, Inconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := fakeDB{change: tc.c}
			got, err := NoCommit(tc.w, db, "trace", tc.tables...)
			if got != tc.want || (err == nil) != (got == Pass) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			fatal, _ := runRequire(func(tb testing.TB) { RequireNoCommit(tb, tc.w, db, "trace", tc.tables...) })
			if (fatal != "") != (tc.want != Pass) {
				t.Fatalf("RequireNoCommit fatal = %q", fatal)
			}
			f := &cleanupTB{}
			if CheckNoCommit(f, tc.w, db, "trace", tc.tables...) != (tc.want == Pass) {
				t.Fatalf("CheckNoCommit: %v", f.errs)
			}
			if tc.want == Fail && !strings.HasPrefix(f.errs[0], TagWitness+":") {
				t.Fatalf("a commit seen is witness evidence: %v", f.errs)
			}
			if tc.want == Inconclusive && !strings.HasPrefix(f.errs[0], TagInconclusive+":") {
				t.Fatalf("errs %v", f.errs)
			}
		})
	}
}

func TestNoCommitHandsTheReaderWhatTheWitnessSaw(t *testing.T) {
	var saw []witness.FileEvent
	w := healthFile{unknownFile: wroteTo("/r/app.db-wal")}
	NoCommit(w, fakeDB{change: witness.SQLiteChange{Verdict: witness.SQLiteNoChange}, saw: &saw}, "trace")
	if len(saw) != 1 {
		t.Fatalf("saw %+v", saw)
	}
}

// End to end: a real SQLite in another process writes an audit row and leaves
// users alone. The file was written, the claim about users holds, and the
// claim about audit does not.
func TestRequireNoCommitAgainstARealDatabase(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err == nil {
		err = exec.Command(py, "-I", "-c", "import sqlite3").Run()
	}
	if err != nil {
		if os.Getenv("SUBPOENA_SQLITE_REQUIRE") != "" {
			t.Fatal(err)
		}
		t.Skip("python3 with sqlite3 is not here")
	}
	root := t.TempDir()
	path := filepath.Join(root, "app.db")
	run := func(sql string) {
		t.Helper()
		src := "import sqlite3, sys\nc = sqlite3.connect(sys.argv[1], isolation_level=None)\nc.executescript(sys.argv[2])\nc.close()\n"
		if out, err := exec.Command(py, "-I", "-c", src, path, sql).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	run("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT); CREATE TABLE audit(what TEXT); INSERT INTO users(name) VALUES('ann');")
	db, err := witness.WatchSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := witness.NewFileWatch(root)
	if err != nil {
		t.Fatal(err)
	}
	run("INSERT INTO audit VALUES('denied');")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if v, _ := NoWrite(w, "trace", path); v != Fail {
		t.Fatalf("the file was written: %v", v)
	}
	RequireNoCommit(t, w, db, "trace", "users")
	if v, err := NoCommit(w, db, "trace", "audit"); v != Fail {
		t.Fatalf("got %v, %v", v, err)
	}
	if v, _ := NoCommit(w, db, "trace"); v != Fail {
		t.Fatalf("a commit happened: %v", v)
	}
}
