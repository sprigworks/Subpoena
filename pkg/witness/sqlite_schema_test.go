//subpoena:impl_derived
//subpoena:pure_logic

// Round 2 review 6: what the reader must not call proof. Every database here
// is real SQLite in another process, and secure_delete is OFF, SQLite's upstream
// default, because a build that zeroes freed pages hides a drop's fault.
package witness

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// H1: a virtual table owns no pages, so what its rows did is not on any page
// of its own, and its name must say so.
func TestAVirtualTableIsMarkedVirtual(t *testing.T) {
	for _, tc := range []struct{ name, mode, create, insert string }{
		{"fts5 wal", "WAL", "CREATE VIRTUAL TABLE v USING fts5(body)", "INSERT INTO v VALUES('secret')"},
		{"fts5 rollback", "DELETE", "CREATE VIRTUAL TABLE v USING fts5(body)", "INSERT INTO v VALUES('secret')"},
		{"rtree wal", "WAL", "CREATE VIRTUAL TABLE v USING rtree(id,x0,x1)", "INSERT INTO v VALUES(1,0,1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fixture(t, tc.mode, tc.create)
			p := openSQLite(t, path)
			p.exec("SELECT * FROM users")
			d := baseline(t, path)
			if c := d.Change(nil); !c.IsVirtual("V") || c.IsVirtual("users") {
				t.Fatalf("before any commit: %+v", c)
			}
			p.exec(tc.insert)
			c := d.Change(nil)
			wantVerdict(t, c, SQLiteCommitted)
			if !c.IsVirtual("v") || c.Changed("v") {
				t.Fatalf("%+v", c)
			}
		})
	}
}

// H2: each of these leaves every page of victim's tree as it was, or writes
// only the schema, and victim no longer reads as it did.
func TestATableChangedWithoutItsPagesBeingWrittenIsNamed(t *testing.T) {
	junk := []string{
		"CREATE TABLE victim(a,b)", "CREATE TABLE evil(a,b)", "CREATE TABLE junk(a)",
		"INSERT INTO victim VALUES(1,'real')", "INSERT INTO evil VALUES(2,'forged')",
		"INSERT INTO junk WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<200) SELECT hex(zeroblob(150)) FROM c",
		"DROP TABLE junk", // a freelist with a trunk, so a freed root is not rewritten
	}
	swap := []string{"BEGIN", "ALTER TABLE victim RENAME TO t", "ALTER TABLE evil RENAME TO victim", "ALTER TABLE t RENAME TO evil", "COMMIT"}
	for _, tc := range []struct {
		name string
		act  []string
	}{
		{"drop", []string{"DROP TABLE victim"}},
		{"rename", []string{"ALTER TABLE victim RENAME TO gone"}},
		{"swap", swap},
		{"add column", []string{"ALTER TABLE victim ADD COLUMN role DEFAULT 'admin'"}},
	} {
		for _, mode := range []string{"WAL", "DELETE"} {
			t.Run(tc.name+" "+mode, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "app.db")
				p := openSQLite(t, path)
				p.exec("PRAGMA secure_delete=OFF", "PRAGMA journal_mode="+mode)
				p.exec(junk...)
				p.exec("PRAGMA wal_checkpoint(TRUNCATE)")
				d := baseline(t, path)
				p.exec(tc.act...)
				c := d.Change(written(path, path+"-wal"))
				if !c.Changed("victim") {
					t.Fatalf("victim not named: %+v", c)
				}
				if tc.name != "drop" && tc.name != "rename" && !c.Knows("victim") {
					t.Fatalf("%+v", c)
				}
			})
		}
	}
}

// An unrelated table stays unnamed, so a claim about it can still pass.
func TestASchemaChangeNamesOnlyItsTable(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("ALTER TABLE audit ADD COLUMN extra DEFAULT 'x'")
	c := d.Change(nil)
	if !c.Changed("audit") || c.Changed("users") || !c.Exact {
		t.Fatalf("%+v", c)
	}
}

// The two checks, one at a time, with nothing written on any page of a table.
func TestAttributeNamesAPageThatChangedHandsAndARowThatChanged(t *testing.T) {
	v := sqliteView{pageSize: 512, usable: 512, pages: [][]byte{make([]byte, 512), make([]byte, 512)}}
	got := map[string]bool{}
	before := &sqliteMap{owners: map[uint32]string{2: "a"}}
	after := &sqliteMap{owners: map[uint32]string{2: ownerFree}}
	if err := attribute(nil, v, v, before, after, got); err != nil || !got["a"] {
		t.Fatalf("owner: %v, %v", err, got)
	}
	got = map[string]bool{}
	before = &sqliteMap{rows: map[string]schemaRow{"k": {typ: "table", name: "a", tbl: "a", root: 2}}}
	after = &sqliteMap{rows: map[string]schemaRow{"k": {typ: "table", name: "a", tbl: "a", root: 3}}}
	if err := attribute(nil, v, v, before, after, got); err != nil || !got["a"] {
		t.Fatalf("row: %v, %v", err, got)
	}
	got = map[string]bool{}
	before.rows = nil
	if err := attribute(nil, v, v, before, after, got); err != nil || !got["a"] {
		t.Fatalf("new row: %v, %v", err, got)
	}
}

// Text encoding sits in the header, not on a table's page. Flipped by hand,
// every row reads differently and no table's tree was touched.
func TestAHeaderThatChangesDecodingLeavesNoTableList(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(b[24:], binary.BigEndian.Uint32(b[24:])+1) // as one commit would
	binary.BigEndian.PutUint32(b[56:], 2)                                 // UTF-16le
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	c := d.Change(written(path))
	if c.Exact || c.TableError == "" {
		t.Fatalf("%+v", c)
	}
}

// H3: SQLite resolves a symlink and puts its WAL beside the real file.
func TestASymlinkedDatabaseIsReadAtItsRealPath(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(real, "app.db")
	p := openSQLite(t, file)
	p.exec("PRAGMA journal_mode=WAL", "CREATE TABLE users(a)", "PRAGMA wal_checkpoint(TRUNCATE)")
	p.close()
	link := filepath.Join(dir, "app.db")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	d := baseline(t, link)
	if d.Path() != file {
		t.Fatalf("Path = %s", d.Path())
	}
	q := openSQLite(t, link)
	q.exec("INSERT INTO users VALUES('intruder')")
	c := d.Change(nil)
	wantVerdict(t, c, SQLiteCommitted)
	if !c.Changed("users") {
		t.Fatalf("%+v", c)
	}
}

// The same through a directory: the events are spelled at the real path, which
// is where the reader now looks for them.
func TestASymlinkedDirectoryKeepsTheWitnessOnTheRealPath(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join(dir, "releases", "1")
	if err := os.MkdirAll(rel, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "1"), filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	spelled := filepath.Join(dir, "current", "app.db")
	p := openSQLite(t, spelled)
	p.exec("PRAGMA journal_mode=WAL", "CREATE TABLE users(a)", "INSERT INTO users VALUES('ann')", "PRAGMA wal_checkpoint(TRUNCATE)")
	p.close()
	d := baseline(t, spelled)
	file := filepath.Join(rel, "app.db")
	if d.Path() != file {
		t.Fatalf("Path = %s", d.Path())
	}
	q := openSQLite(t, spelled)
	q.exec("UPDATE users SET a='bob'", "UPDATE users SET a='ann'", "PRAGMA wal_checkpoint(TRUNCATE)")
	wantVerdict(t, d.Change(written(file+"-wal")), SQLiteUnknown)
}

func TestAPathThatStopsBeingTheFileIsUnknown(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	c := d.Change(nil)
	wantVerdict(t, c, SQLiteUnknown)
	if !strings.Contains(c.Reason, "resolves") {
		t.Fatalf("%+v", c)
	}
}

// A WAL or journal at the end of a symlink is written outside what the file
// witness watches, so the reader refuses to take it for the file it looks like.
func TestASymlinkAtTheWALsNameIsRefused(t *testing.T) {
	for _, suffix := range []string{"-wal", "-journal"} {
		path := fixture(t, "DELETE")
		out := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.WriteFile(out, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(out, path+suffix); err != nil {
			t.Fatal(err)
		}
		if _, err := WatchSQLite(path); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("%s: %v", suffix, err)
		}
	}
}

// M3: a rename of a directory above the database moved it with no event naming
// it, and a page comparison across that cannot be trusted.
func TestARenameAboveTheDatabaseCountsAsAWrite(t *testing.T) {
	if wroteTo([]FileEvent{{Op: FileRename, Path: "/r/data", IsDir: true}}, "/r/data/app.db") != true {
		t.Fatal("a rename above the path must count")
	}
	if wroteTo([]FileEvent{{Op: FileRename, Path: "/r/other", IsDir: true}}, "/r/data/app.db") {
		t.Fatal("a rename elsewhere must not")
	}
}

// M4: commit, then copy the original bytes back. The counter says nothing
// happened, and only the writes seen say otherwise.
func TestJournalCommitThenRestoreIsUnknown(t *testing.T) {
	path := fixture(t, "DELETE")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("UPDATE users SET name='mallory'")
	p.close()
	if err := os.WriteFile(path, before, 0o644); err != nil {
		t.Fatal(err)
	}
	c := d.Change(written(path))
	wantVerdict(t, c, SQLiteUnknown)
	if c.Exact {
		t.Fatalf("%+v", c)
	}
	wantVerdict(t, d.Change(nil), SQLiteNoChange) // with no writes, nothing says otherwise
}

// M4's other half: the same undoing, then one more commit. The counter reads
// one, and the pages show only the second commit, through a real witness.
func TestJournalRestoreThenCommitIsNotExact(t *testing.T) {
	path := fixture(t, "DELETE")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := baseline(t, path)
	w := watch(t, filepath.Dir(path))
	p := openSQLite(t, path)
	p.exec("UPDATE users SET name='mallory'")
	p.close()
	if err := os.WriteFile(path, before, 0o644); err != nil {
		t.Fatal(err)
	}
	q := openSQLite(t, path)
	q.exec("INSERT INTO audit(what) VALUES('denied')")
	q.close()
	w.Stop()
	c := d.Change(w.Wrote(""))
	if c.Commits != 1 || c.Exact || c.Changed("users") {
		t.Fatalf("%+v", c)
	}
}

// One ordinary commit keeps Exact, so a table claim beside it can still pass.
func TestJournalOneCommitStaysExactThroughAWitness(t *testing.T) {
	for _, mode := range []string{"DELETE", "TRUNCATE", "PERSIST"} {
		path := fixture(t, mode)
		d := baseline(t, path)
		w := watch(t, filepath.Dir(path))
		p := openSQLite(t, path)
		p.exec("PRAGMA journal_mode="+mode, "INSERT INTO audit(what) VALUES('denied')")
		p.close()
		w.Stop()
		c := d.Change(w.Wrote(""))
		if c.Commits != 1 || !c.Exact || !c.Changed("audit") || c.Changed("users") {
			t.Fatalf("%s: %+v", mode, c)
		}
	}
}

// L2: a frame with a good checksum can name any page. It must be refused, not
// allocated: a fatal out-of-memory cannot be recovered.
func TestAForgedWALFrameIsRefused(t *testing.T) {
	path := fixture(t, "WAL")
	d := baseline(t, path)
	const ps = 4096
	order := binary.LittleEndian
	hdr := make([]byte, walHdrSize)
	binary.BigEndian.PutUint32(hdr[0:], walMagicLE)
	binary.BigEndian.PutUint32(hdr[4:], 3007000)
	binary.BigEndian.PutUint32(hdr[8:], ps)
	binary.BigEndian.PutUint32(hdr[16:], 1)
	binary.BigEndian.PutUint32(hdr[20:], 2)
	s0, s1 := walChecksum(order, 0, 0, hdr[:24])
	binary.BigEndian.PutUint32(hdr[24:], s0)
	binary.BigEndian.PutUint32(hdr[28:], s1)
	frame := make([]byte, walFrameHdr)
	binary.BigEndian.PutUint32(frame[0:], 0xfffffff0)
	binary.BigEndian.PutUint32(frame[4:], 1)
	binary.BigEndian.PutUint32(frame[8:], 1)
	binary.BigEndian.PutUint32(frame[12:], 2)
	data := make([]byte, ps)
	s0, s1 = walChecksum(order, s0, s1, frame[:8])
	s0, s1 = walChecksum(order, s0, s1, data)
	binary.BigEndian.PutUint32(frame[16:], s0)
	binary.BigEndian.PutUint32(frame[20:], s1)
	if err := os.WriteFile(path+"-wal", slices.Concat(hdr, frame, data), 0o644); err != nil {
		t.Fatal(err)
	}
	c := d.Change(nil)
	wantVerdict(t, c, SQLiteUnknown)
	if !strings.Contains(c.Reason, "past anything") {
		t.Fatalf("%+v", c)
	}
}
