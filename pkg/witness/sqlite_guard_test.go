//subpoena:impl_derived
//subpoena:pure_logic

// The reader's guards, written after reading the implementation: each one
// exists to kill a mutant of a fail-closed branch. sqliteProc and the fixtures
// are in sqlite_test.go.
package witness

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A -wal file beside a rollback-mode database is not part of it: SQLite does
// not read it, so its commits are not this database's.
func TestAStaleWALBesideARollbackDatabaseIsIgnored(t *testing.T) {
	other := fixture(t, "WAL")
	p := openSQLite(t, other)
	p.exec("INSERT INTO users(name) VALUES('elsewhere')")
	stale, err := os.ReadFile(other + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	if err := os.WriteFile(path+"-wal", stale, 0o644); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
}

// The salts are not under the frame checksum, so a frame can verify and still
// belong to an older life of the WAL.
func TestAFrameWithOtherSaltsEndsTheLog(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	wal := path + "-wal"
	size := fileSize(t, wal)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	f, err := os.OpenFile(wal, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	at := max(size, walHdrSize) + 8 // the first new frame's salt-1
	was := make([]byte, 1)
	if _, err := f.ReadAt(was, at); err != nil {
		t.Fatal(err)
	}
	// The salt is random: a fixed byte equals it one run in 256, and then
	// nothing has changed. Flip the bit instead.
	if _, err := f.WriteAt([]byte{was[0] ^ 0xff}, at); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
}

// A main file written and a WAL from another generation mean a checkpoint ran:
// the frames do not hold everything.
func TestAWALOfAnotherGenerationAfterACheckpointIsNotExact(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("INSERT INTO users(name) VALUES('a')")
	d := baseline(t, path)
	p.exec("INSERT INTO audit(what) VALUES('one')", "PRAGMA wal_checkpoint(RESTART)", "INSERT INTO audit(what) VALUES('two')")
	c := d.Change(written(path))
	if c.Basis != BasisPageDiff || c.Exact {
		t.Fatalf("%+v", c)
	}
	// Told of no main-file write, it believes the frames: which is why the
	// reader must be given a healthy witness's events.
	if c := d.Change(nil); c.Basis != BasisWALFrames {
		t.Fatalf("%+v", c)
	}
}

func TestABadPageSizeIsAnError(t *testing.T) {
	path := fixture(t, "DELETE")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0x03, 0xe8}, 16); err != nil { // 1000: not a power of two
		t.Fatal(err)
	}
	if _, err := WatchSQLite(path); err == nil {
		t.Fatal("no reading pages of an impossible size")
	}
}

func TestAWALOfAnotherPageSizeIsUnknown(t *testing.T) {
	other := filepath.Join(t.TempDir(), "small.db")
	p := openSQLite(t, other)
	p.exec("PRAGMA page_size=1024", "PRAGMA journal_mode=WAL", "CREATE TABLE t(x)", "INSERT INTO t VALUES(1)")
	stale, err := os.ReadFile(other + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	path := fixture(t, "WAL")
	d := baseline(t, path)
	if err := os.WriteFile(path+"-wal", stale, 0o644); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteUnknown)
}

// Pages that change with no change-counter bump are not an ordinary commit:
// the table list stands, and is not called exact.
func TestPagesChangedWithoutACommitAreNotExact(t *testing.T) {
	path := fixture(t, "DELETE")
	d := baseline(t, path)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The last byte of the last page: free space in some b-tree page.
	if _, err := f.WriteAt([]byte{0x5a}, fileSize(t, path)-1); err != nil {
		t.Fatal(err)
	}
	c := d.Change(written(path))
	wantVerdict(t, c, SQLiteCommitted)
	if c.Exact {
		t.Fatalf("%+v", c)
	}
}

// A database that first got its WAL in the window, on a file that was empty.
func TestAWALOnAnEmptyBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d := baseline(t, path)
	p := openSQLite(t, path)
	p.exec("PRAGMA journal_mode=WAL", "CREATE TABLE t(x)")
	c := d.Change(written(path, path+"-wal"))
	wantVerdict(t, c, SQLiteCommitted)
	if !c.Changed(SQLiteSchemaTable) {
		t.Fatalf("%+v", c)
	}
}

func TestAScanFindingCountsAsAWrite(t *testing.T) {
	path := "/r/db-wal"
	if !wroteTo([]FileEvent{{Op: FileCreate, Path: path, Source: SourceScan}}, path) {
		t.Fatal("a file found by a scan may have been written before its watch landed")
	}
	if wroteTo([]FileEvent{{Op: FileCreate, Path: path, Source: SourceInotify}}, path) {
		t.Fatal("a create alone writes nothing")
	}
}

// The stored header checksum is what vouches for the WAL. A wrong one voids
// every frame, though the frames chain from the header's true sum.
func TestAWALWhoseStoredChecksumIsWrongIsIgnored(t *testing.T) {
	path := fixture(t, "WAL")
	p := openSQLite(t, path)
	p.exec("SELECT * FROM users")
	d := baseline(t, path)
	p.exec("INSERT INTO audit(what) VALUES('x')")
	f, err := os.OpenFile(path+"-wal", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b [1]byte
	if _, err := f.ReadAt(b[:], 24); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{b[0] ^ 0xff}, 24); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
}

// A real database with its magic gone, which is how an encrypted one looks: the
// rest may parse, and it still must not be read.
func TestWithoutTheMagicItIsNotADatabase(t *testing.T) {
	path := fixture(t, "DELETE")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{'X'}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := WatchSQLite(path); err == nil {
		t.Fatal("read a file that does not say it is SQLite")
	}
}

// A page nothing owns means the owner map is wrong, so its table list is too.
func TestAChangedPageNoOneOwnsIsAnError(t *testing.T) {
	v := sqliteView{pageSize: 512, usable: 512, pages: [][]byte{make([]byte, 512), make([]byte, 512)}}
	owned := map[uint32]string{2: "t"}
	if err := attribute(map[uint32]bool{2: true}, v, v, &sqliteMap{owners: owned}, &sqliteMap{owners: owned}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := attribute(map[uint32]bool{2: true}, v, v, &sqliteMap{}, &sqliteMap{}, map[string]bool{}); err == nil {
		t.Fatal("a page with no owner on either side went unreported")
	}
}

// SQLite deletes a WAL beside an empty database, unread.
func TestAWALBesideAnEmptyFileIsIgnored(t *testing.T) {
	other := fixture(t, "WAL")
	p := openSQLite(t, other)
	p.exec("INSERT INTO users(name) VALUES('elsewhere')")
	stale, err := os.ReadFile(other + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "new.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d := baseline(t, path)
	if err := os.WriteFile(path+"-wal", stale, 0o644); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, d.Change(nil), SQLiteNoChange)
}

// The soundness claim, against SQLite's own answer: a table whose rows differ
// after a commit is always named. Random writes, one commit per round, one
// baseline per round, in both journal modes.
func TestEveryTableWhoseRowsChangedIsNamed(t *testing.T) {
	for _, mode := range []string{"WAL", "DELETE"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "app.db")
			p := openSQLite(t, path)
			tables := []string{"a", "b", "c"}
			p.exec("PRAGMA journal_mode=" + mode)
			for _, tb := range tables {
				p.exec(fmt.Sprintf("CREATE TABLE %s(id INTEGER PRIMARY KEY, v TEXT)", tb), fmt.Sprintf("CREATE INDEX %s_v ON %s(v)", tb, tb))
			}
			dump := func(tb string) string {
				return fmt.Sprint(p.exec("SELECT * FROM " + tb))
			}
			rng := rand.New(rand.NewSource(7))
			named := 0
			for round := 0; round < 60; round++ {
				before := map[string]string{}
				for _, tb := range tables {
					before[tb] = dump(tb)
				}
				d := baseline(t, path)
				tb := tables[rng.Intn(len(tables))]
				size := []int{10, 900, 5000, 20000}[rng.Intn(4)]
				v := strings.Repeat(string(rune('a'+rng.Intn(26))), size)
				p.exec([]string{
					fmt.Sprintf("INSERT INTO %s(v) VALUES('%s')", tb, v),
					fmt.Sprintf("UPDATE %s SET v='%s' WHERE id IN (SELECT id FROM %s ORDER BY random() LIMIT 1)", tb, v, tb),
					fmt.Sprintf("DELETE FROM %s WHERE id IN (SELECT id FROM %s ORDER BY random() LIMIT 2)", tb, tb),
				}[rng.Intn(3)])
				c := d.Change(written(path + "-wal"))
				if c.TableError != "" {
					t.Fatalf("round %d: %s", round, c.TableError)
				}
				for _, name := range tables {
					if dump(name) != before[name] {
						if !c.Changed(name) {
							t.Fatalf("round %d: %s changed and was not named: %+v", round, name, c)
						}
						named++
					}
				}
			}
			if named < 30 {
				t.Fatalf("only %d rounds changed anything", named)
			}
		})
	}
}
