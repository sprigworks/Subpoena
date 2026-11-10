//subpoena:spec_derived
//subpoena:pure_logic

// The SQLite reader, from the brief's "Not a trigger" note and SQLite's file
// format (https://www.sqlite.org/fileformat2.html, wal format, journal format).
// Every database here is made by a real SQLite, in another process, because
// the point is what a real one leaves on disk. Written before the reader.
package witness

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The program behind sqliteProc: one connection, one statement per line, one
// JSON answer per line, so a test decides when the connection closes.
const sqliteDriver = `
import json, sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None)
for line in sys.stdin:
    try:
        rows = c.execute(line).fetchall()
        print(json.dumps({"rows": [[str(v) for v in r] for r in rows]}), flush=True)
    except Exception as e:
        print(json.dumps({"error": str(e)}), flush=True)
c.close()
`

type sqliteProc struct {
	t     *testing.T
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
	open  bool
}

func needSQLite(t *testing.T) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err == nil {
		err = exec.Command(py, "-I", "-c", "import sqlite3").Run()
	}
	if err != nil {
		if os.Getenv("SUBPOENA_SQLITE_REQUIRE") != "" {
			t.Fatalf("python3 with sqlite3: %v", err)
		}
		t.Skipf("python3 with sqlite3 is not here: %v", err)
	}
	return py
}

func openSQLite(t *testing.T, path string) *sqliteProc {
	t.Helper()
	cmd := exec.Command(needSQLite(t), "-I", "-c", sqliteDriver, path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &sqliteProc{t: t, cmd: cmd, stdin: stdin, out: bufio.NewReader(stdout), open: true}
	t.Cleanup(p.close)
	return p
}

func (p *sqliteProc) exec(statements ...string) [][]string {
	p.t.Helper()
	var rows [][]string
	for _, s := range statements {
		fmt.Fprintln(p.stdin, s)
		line, err := p.out.ReadString('\n')
		if err != nil {
			p.t.Fatalf("%s: %v", s, err)
		}
		var ans struct {
			Rows  [][]string `json:"rows"`
			Error string     `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &ans); err != nil {
			p.t.Fatalf("%s: %v", s, err)
		}
		if ans.Error != "" {
			p.t.Fatalf("%s: %s", s, ans.Error)
		}
		rows = ans.Rows
	}
	return rows
}

// close ends the connection; the last one out checkpoints and removes a WAL.
func (p *sqliteProc) close() {
	if p.open {
		p.open = false
		p.stdin.Close()
		p.cmd.Wait()
	}
}

// fixture makes a database with the tables most tests use, in the given
// journal mode, and leaves it closed.
func fixture(t *testing.T, mode string, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.db")
	p := openSQLite(t, path)
	p.exec("PRAGMA journal_mode=" + mode)
	p.exec("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)",
		"CREATE TABLE audit(id INTEGER PRIMARY KEY, what TEXT)",
		"CREATE INDEX users_name ON users(name)",
		"INSERT INTO users(name) VALUES('ann')")
	p.exec(extra...)
	p.close()
	return path
}

func baseline(t *testing.T, path string) *SQLiteDB {
	t.Helper()
	d, err := WatchSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func wantTables(t *testing.T, c SQLiteChange, want ...string) {
	t.Helper()
	if !slices.Equal(c.Tables, want) {
		t.Fatalf("tables %v, want %v (%+v)", c.Tables, want, c)
	}
}

func wantVerdict(t *testing.T, c SQLiteChange, want SQLiteVerdict) {
	t.Helper()
	if c.Verdict != want {
		t.Fatalf("verdict %s, want %s (%+v)", c.Verdict, want, c)
	}
}

// The file events the reader is told of, as a healthy witness would give them.
func written(paths ...string) []FileEvent {
	var out []FileEvent
	for _, p := range paths {
		out = append(out, FileEvent{Op: FileWrite, Path: p})
	}
	return out
}

// ---- WAL mode ----

func TestWALCommitNamesTheTable(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users") // the WAL is opened
	d := baseline(t, path)
	p.exec("INSERT INTO audit(what) VALUES('denied')")
	c := d.Change(nil)
	wantVerdict(t, c, SQLiteCommitted)
	wantTables(t, c, "audit")
	if c.Basis != BasisWALFrames || !c.Exact || c.Commits != 1 {
		t.Fatalf("%+v", c)
	}
	if !c.Changed("AUDIT") || c.Changed("users") {
		t.Fatalf("Changed: %+v", c)
	}
	if !c.Knows("users") || c.Knows("no_such_table") {
		t.Fatalf("Knows: %+v", c)
	}
}

func TestWALReadsAreNoChange(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("SELECT count(*) FROM audit")
	c := d.Change(nil)
	wantVerdict(t, c, SQLiteNoChange)
	if !c.Exact {
		t.Fatalf("%+v", c)
	}
}

// The heart of it: bytes reached the WAL and nothing was committed. A spilled
// transaction writes frames with no commit frame.
func TestWALRolledBackFramesAreNoChange(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("PRAGMA cache_size=5", "PRAGMA cache_spill=1", "SELECT * FROM users")
	d := baseline(t, path)
	wal := path + "-wal"
	sizeBefore := fileSize(t, wal)
	p.exec("BEGIN", "INSERT INTO users(name) SELECT hex(zeroblob(2000)) FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<200) SELECT i FROM n)")
	if fileSize(t, wal) == sizeBefore {
		t.Fatal("the transaction did not spill; the test proves nothing")
	}
	inFlight := d.Change(written(wal))
	wantVerdict(t, inFlight, SQLiteNoChange)
	if inFlight.Uncommitted == 0 {
		t.Fatalf("frames with no commit go uncounted: %+v", inFlight)
	}
	p.exec("ROLLBACK")
	wantVerdict(t, d.Change(written(wal)), SQLiteNoChange)
	// The next commit reuses those frames; it is the only commit.
	p.exec("INSERT INTO audit(what) VALUES('x')")
	c := d.Change(written(wal))
	wantVerdict(t, c, SQLiteCommitted)
	wantTables(t, c, "audit")
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

func TestWALCommitsBeforeTheBaselineDoNotCount(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("INSERT INTO users(name) VALUES('before')", "INSERT INTO audit(what) VALUES('before')")
	d := baseline(t, path)
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
	p.exec("INSERT INTO audit(what) VALUES('after')")
	c := d.Change(nil)
	wantTables(t, c, "audit")
	if c.Commits != 1 {
		t.Fatalf("%+v", c)
	}
}

// A commit frame that does not verify is not a commit, as SQLite's own
// recovery would have it: frames count only while the checksum chain holds.
func TestWALFrameWithABadChecksumIsNotACommit(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	wal := path + "-wal"
	size := fileSize(t, wal)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	if fileSize(t, wal) == size {
		t.Fatal("nothing reached the WAL")
	}
	f, err := os.OpenFile(wal, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0xff, 0xff, 0xff, 0xff}, size+100); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
}

// A WAL with a torn header means nothing: SQLite ignores it, and so must the
// reader, or stale frames would read as commits.
func TestWALWithABadHeaderIsIgnored(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	wal := path + "-wal"
	f, err := os.OpenFile(wal, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0xff}, 12); err != nil {
		t.Fatal(err)
	}
	c := d.Change(nil)
	if c.Verdict == SQLiteCommitted {
		t.Fatalf("frames behind a bad header were read: %+v", c)
	}
}

func TestWALOverflowPagesBelongToTheirTable(t *testing.T) {
	big := strings.Repeat("x", 20000)
	path := fixture(t, "WAL", "CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT)",
		"INSERT INTO docs(body) VALUES('"+big+"')")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	// Same length, different end: only overflow pages hold the change.
	p.exec("UPDATE docs SET body = substr(body, 1, 19990) || 'yyyyyyyyyy'")
	c := d.Change(nil)
	wantTables(t, c, "docs")
	if !c.Exact {
		t.Fatalf("%+v", c)
	}
}

func TestIndexPagesBelongToTheirTable(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("UPDATE users SET name='bob'")
	wantTables(t, d.Change(nil), "users")
}

// A page's owner can change inside the window: it must be named under each.
// users frees pages, audit reuses them, and both are named.
func TestAPageThatChangesHandsNamesBothTables(t *testing.T) {
	path := fixture(t, "WAL", "INSERT INTO users(name) SELECT hex(zeroblob(1500)) FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<60) SELECT i FROM n)")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("DELETE FROM users WHERE id > 1")
	p.exec("INSERT INTO audit(what) SELECT hex(zeroblob(1500)) FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<30) SELECT i FROM n)")
	c := d.Change(nil)
	wantTables(t, c, "audit", "users")
	if c.Commits != 2 || !c.Exact {
		t.Fatalf("%+v", c)
	}
}

// A table made and dropped inside the window is gone from the end state, and
// the frames still name it.
func TestATableThatCameAndWentIsNamed(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("CREATE TABLE brief(x)", "INSERT INTO brief VALUES(1)", "DROP TABLE brief")
	c := d.Change(nil)
	if !c.Changed("brief") || !c.Changed(SQLiteSchemaTable) {
		t.Fatalf("%+v", c)
	}
}

func TestSchemaChangeIsNamed(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("CREATE TABLE fresh(x)")
	c := d.Change(nil)
	if !c.Changed(SQLiteSchemaTable) {
		t.Fatalf("%+v", c)
	}
	if !c.Knows("fresh") {
		t.Fatalf("%+v", c)
	}
}

// A commit to one table touches page 1's header and nothing else there; that
// is not a schema change.
func TestAHeaderOnlyChangeOnPageOneIsNotTheSchema(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	// Growing the file changes the header's page count.
	p.exec("INSERT INTO audit(what) SELECT hex(zeroblob(1500)) FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<30) SELECT i FROM n)")
	c := d.Change(nil)
	if !slices.Contains(c.Pages, 1) {
		t.Fatalf("page 1 did not change; the test proves nothing: %+v", c)
	}
	wantTables(t, c, "audit")
}

func TestWithoutRowidAndAutovacuum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	p := openSQLite(t, path)
	p.exec("PRAGMA auto_vacuum=FULL", "PRAGMA journal_mode=WAL",
		"CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID",
		"CREATE TABLE other(x)", "INSERT INTO kv VALUES('a','b')")
	d := baseline(t, path)
	p.exec("INSERT INTO kv VALUES('c','d')")
	c := d.Change(nil)
	wantTables(t, c, "kv")
	if !c.Exact {
		t.Fatalf("%+v", c)
	}
}

// The usual end of a WAL: the last connection checkpoints and removes it. The
// frames are gone, so only the pages can answer, and no commit count exists.
func TestWALGoneAfterLastCloseFallsBackToPages(t *testing.T) {
	path := fixture(t, "WAL")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	p.close()
	if _, err := os.Stat(path + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("the WAL is still here: %v", err)
	}
	c := d.Change(written(path+"-wal", path))
	wantVerdict(t, c, SQLiteCommitted)
	wantTables(t, c, "audit")
	if c.Basis != BasisPageDiff || c.Exact {
		t.Fatalf("frames are gone, so a change undone in the window cannot be ruled out: %+v", c)
	}
}

// Writes reached the WAL, the frames are gone, and the pages match: something
// may have been committed and undone. Silence here would be a guess.
func TestWALGoneWithWritesAndNoNetChangeIsUnknown(t *testing.T) {
	path := fixture(t, "WAL")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("UPDATE users SET name='zed'", "UPDATE users SET name='ann'")
	p.close()
	wantVerdict(t, d.Change(written(path+"-wal", path)), SQLiteUnknown)
}

// With no write to the WAL, and the same pages, nothing was committed, whatever
// the connection did: a reader opening and closing leaves no frames.
func TestWALModeWithNoWritesIsNoChange(t *testing.T) {
	path := fixture(t, "WAL")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	p.close()
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
}

func TestWALCheckpointMidWindowFallsBackToPages(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("INSERT INTO audit(what) VALUES('one')", "PRAGMA wal_checkpoint(TRUNCATE)", "INSERT INTO users(name) VALUES('two')")
	c := d.Change(written(path, path+"-wal"))
	wantVerdict(t, c, SQLiteCommitted)
	wantTables(t, c, "audit", "users")
	if c.Exact {
		t.Fatalf("%+v", c)
	}
}

// No main-file write means no checkpoint ran, so the WAL holds every commit of
// the window, even though it did not exist at the baseline.
func TestAWALBornInTheWindowHoldsEveryCommit(t *testing.T) {
	path := fixture(t, "WAL")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	c := d.Change(written(path + "-wal"))
	wantVerdict(t, c, SQLiteCommitted)
	wantTables(t, c, "audit")
	if c.Basis != BasisWALFrames || !c.Exact || c.Commits != 1 {
		t.Fatalf("%+v", c)
	}
}

// ---- Rollback journal mode ----

func TestJournalCommitNamesTheTable(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("INSERT INTO audit(what) VALUES('denied')")
	c := d.Change(written(path, path+"-journal"))
	wantVerdict(t, c, SQLiteCommitted)
	wantTables(t, c, "audit")
	if c.Basis != BasisPageDiff || !c.Exact || c.Commits != 1 {
		t.Fatalf("one commit: its pages are every page it changed: %+v", c)
	}
}

func TestJournalRollbackIsNoChange(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("BEGIN", "INSERT INTO users(name) VALUES('x')", "ROLLBACK")
	wantVerdict(t, d.Change(written(path+"-journal")), SQLiteNoChange)
}

// A spilled transaction writes the database itself before rolling back: the
// file was written, and the rollback restored it. Pages and counter then match
// the baseline, as they do after a commit undone by restoring the file (see
// TestJournalCommitThenRestoreIsUnknown), so with the writes seen the files
// cannot say which it was. Round 2 review 6, M4.
func TestJournalSpilledRollbackIsUnknownOnceWritesWereSeen(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p := openSQLite(t, path)
	p.exec("PRAGMA cache_size=5", "PRAGMA cache_spill=1", "BEGIN",
		"INSERT INTO users(name) SELECT hex(zeroblob(2000)) FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<200) SELECT i FROM n)")
	during, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(during) == string(before) {
		t.Fatal("the transaction did not spill; the test proves nothing")
	}
	wantVerdict(t, d.Change(written(path, path+"-journal")), SQLiteUnknown) // in flight
	p.exec("ROLLBACK")
	wantVerdict(t, d.Change(written(path, path+"-journal")), SQLiteUnknown)
	wantVerdict(t, d.Change(written(path+"-journal")), SQLiteNoChange) // the database itself never written
}

// A transaction still open at the read: the journal is there, and what the
// pages will end up as is not yet decided.
func TestAnOpenJournalIsUnknown(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("BEGIN", "INSERT INTO users(name) VALUES('x')")
	wantVerdict(t, d.Change(nil), SQLiteUnknown)
	if _, err := WatchSQLite(path); err == nil {
		t.Fatal("a baseline cannot be taken across an open transaction")
	}
}

func TestJournalModesThatKeepTheFile(t *testing.T) {
	for _, mode := range []string{"PERSIST", "TRUNCATE"} {
		t.Run(mode, func(t *testing.T) {
			path := fixture(t, mode)
			p := openSQLite(t, path)
			p.exec("PRAGMA journal_mode=" + mode)
			d := baseline(t, path)
			wantVerdict(t, d.Change(nil), SQLiteNoChange)
			p.exec("INSERT INTO audit(what) VALUES('x')")
			c := d.Change(nil)
			wantVerdict(t, c, SQLiteCommitted)
			wantTables(t, c, "audit")
		})
	}
}

// Two commits, and a page diff sees only the end of them: a change undone by
// the second is invisible, so the table list is a floor.
func TestSeveralJournalCommitsAreNotExact(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("UPDATE users SET name='zed'", "UPDATE users SET name='ann'", "INSERT INTO audit(what) VALUES('x')")
	c := d.Change(written(path))
	wantVerdict(t, c, SQLiteCommitted)
	if c.Exact || c.Commits != 3 {
		t.Fatalf("%+v", c)
	}
}

// The counter says committed even when the end state matches.
func TestJournalChangeUndoneIsStillCommitted(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("UPDATE users SET name='zed'", "UPDATE users SET name='ann'")
	c := d.Change(written(path))
	wantVerdict(t, c, SQLiteCommitted)
	if c.Exact {
		t.Fatalf("%+v", c)
	}
}

func TestJournalDropTableNamesIt(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("DROP TABLE audit")
	c := d.Change(written(path))
	if !c.Changed(SQLiteSchemaTable) || !c.Knows("audit") {
		t.Fatalf("%+v", c)
	}
}

// ---- What cannot be read ----

func TestABaselineNeedsASQLiteFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := WatchSQLite(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("no file, no baseline")
	}
	bad := filepath.Join(dir, "bad.db")
	if err := os.WriteFile(bad, []byte(strings.Repeat("not sqlite", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WatchSQLite(bad); err == nil {
		t.Fatal("not a SQLite file (or an encrypted one): no reading it")
	}
}

// SQLite makes the file empty and fills it on the first write.
func TestAnEmptyFileIsADatabaseWithNoPagesYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d := baseline(t, path)
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
	p := openSQLite(t, path)
	p.exec("CREATE TABLE t(x)")
	c := d.Change(written(path))
	wantVerdict(t, c, SQLiteCommitted)
	if !c.Changed(SQLiteSchemaTable) {
		t.Fatalf("%+v", c)
	}
}

func TestADatabaseGoneOrReplacedIsUnknown(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	if err := os.WriteFile(path, []byte(strings.Repeat("garbage!", 1024)), 0o644); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteUnknown)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteUnknown)
}

// A b-tree the reader cannot walk leaves the page answer standing, and says
// the table answer is not one.
func TestABrokenTreeFallsBackToPageLevel(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	p.close()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Page 1's b-tree header follows the 100-byte file header: an unknown
	// page type there means the schema cannot be read.
	if _, err := f.WriteAt([]byte{0x7f}, 100); err != nil {
		t.Fatal(err)
	}
	c := d.Change(written(path))
	wantVerdict(t, c, SQLiteCommitted)
	if c.Exact || len(c.Tables) != 0 || len(c.Pages) == 0 || c.TableError == "" {
		t.Fatalf("%+v", c)
	}
}

// The header's change counter is what proves a rollback-mode commit.
func TestChangeCounterIsReadFromTheHeader(t *testing.T) {
	path := fixture(t, "DELETE")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := binary.BigEndian.Uint32(b[24:])
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(b[24:]); got != before+1 {
		t.Fatalf("counter %d -> %d", before, got)
	}
	if c := d.Change(nil); c.Commits != 1 {
		t.Fatalf("%+v", c)
	}
}
