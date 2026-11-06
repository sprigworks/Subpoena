package witness

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// SQLiteVerdict is what the reader can say about a window.
type SQLiteVerdict string

const (
	// SQLiteNoChange means no transaction was committed in the window.
	SQLiteNoChange SQLiteVerdict = "no-change"
	// SQLiteCommitted means at least one transaction was committed.
	SQLiteCommitted SQLiteVerdict = "committed"
	// SQLiteUnknown means the files cannot settle it. See Reason.
	SQLiteUnknown SQLiteVerdict = "unknown"
)

// SQLiteBasis says what a change was read from.
type SQLiteBasis string

const (
	// BasisWALFrames means the WAL still held every commit of the window, in
	// order. It sees a change that a later commit undid.
	BasisWALFrames SQLiteBasis = "wal-frames"
	// BasisPageDiff means the frames are gone, or the database has none: the
	// baseline's pages were compared with the end's. Only the net result of
	// the window is visible. In rollback mode there is no other basis: a
	// commit deletes (or blanks) the journal, and the journal holds the old
	// pages of one transaction at most.
	BasisPageDiff SQLiteBasis = "page-diff"
)

// SQLiteSchemaTable names the schema's own b-tree in SQLiteChange.Tables.
const SQLiteSchemaTable = "sqlite_schema"

// SQLiteChange is what the database's files say happened since the baseline.
type SQLiteChange struct {
	Verdict SQLiteVerdict
	Reason  string // why, for Unknown, or how the verdict was reached
	Basis   SQLiteBasis
	// Commits is the number of committed transactions the files show, zero
	// when they do not say. From a WAL, commit frames. From rollback-mode
	// files, the header's change counter, which undercounts a connection in
	// locking_mode=EXCLUSIVE.
	Commits int
	// Pages are the page numbers committed in the window. Page 1 is here for
	// a change to the header alone.
	Pages []uint32
	// Tables are the tables whose b-trees, indexes and overflow chains
	// included, hold one of Pages, before or after, sorted. A table is named
	// if a page of its tree was written, so a page rewritten unchanged, or
	// moved by auto_vacuum or VACUUM, names a table no row of which changed.
	// That is the safe direction. Rows are not read.
	Tables []string
	// Exact means Tables omits nothing: every committed page of the window
	// was seen. Without it a table not listed may have changed and been
	// restored, so no absence rests on Tables.
	Exact bool
	// TableError is why tables could not be named, if they could not: Pages
	// is then the answer. Empty otherwise.
	TableError string
	// Uncommitted counts frames past the last commit: a transaction that
	// spilled and has not committed, or that rolled back.
	Uncommitted int
	// Schema is every table seen in the database at any point read.
	Schema []string
}

// Changed reports whether table is in Tables. SQLite compares names without
// regard to case.
func (c SQLiteChange) Changed(table string) bool { return nameIn(c.Tables, table) }

// Knows reports whether the schema held table at some point read. A table the
// database never had cannot change, so a claim about it proves nothing.
func (c SQLiteChange) Knows(table string) bool { return nameIn(c.Schema, table) }

func nameIn(names []string, name string) bool {
	return slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) })
}

// SQLiteReader reads what a database's files say happened; SQLiteDB is one.
type SQLiteReader interface {
	// Path is the database's absolute path.
	Path() string
	// Change reports what happened since the baseline, given what a healthy
	// file witness saw.
	Change(events []FileEvent) SQLiteChange
}

var _ SQLiteReader = (*SQLiteDB)(nil)

// SQLiteDB is one SQLite database with a baseline taken: the reader of the
// WAL and the rollback journal behind the file witness. It reads the files
// and nothing else, with no triggers, no connection, and no SQLite library.
//
// A bare "the file was written" cannot carry a claim about a database: a
// denied request can write an audit row to the same file, a read can open it
// for writing, and a rolled-back transaction can write to it. So this says
// whether anything was committed, and to which tables.
//
// It needs the file witness: in WAL mode, a commit that a checkpoint has since
// folded in and undone is visible only as a write to the WAL. Pass Change what
// a healthy FileWatch saw, or use harness.NoCommit, which does.
//
// The baseline is a copy of the database's pages, held in memory. That is a
// before and after comparison, unlike the file witness, and the format leaves
// no other way: a commit in rollback mode erases the journal, and a checkpoint
// erases a WAL's frames. Where the frames survive they are read instead.
//
// Take a baseline and read only while the code under test is not writing: the
// reader takes no locks, and a read across a commit fails or, if the commit
// lands between the files' reads, retries. If the code under test runs in this
// process, a read closes a descriptor on the database, and POSIX then drops
// every lock this process holds on that file, SQLite's included, so never read
// mid-transaction there.
type SQLiteDB struct {
	path string
	base *sqliteImage
}

// WatchSQLite takes a baseline of the database at path. It fails if the file
// is not a SQLite database (an encrypted one is not, to this reader), or if a
// transaction is open.
func WatchSQLite(path string) (*SQLiteDB, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite witness: %w", err)
	}
	img, err := readSQLiteImage(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite witness: %w", err)
	}
	if img.journal != "" {
		return nil, fmt.Errorf("sqlite witness: %s: %s", path, img.journal)
	}
	return &SQLiteDB{path: path, base: img}, nil
}

// Path is the database's path.
func (d *SQLiteDB) Path() string { return d.path }

// sqliteImage is the committed state of a database: the main file with the
// WAL's committed frames laid over it.
type sqliteImage struct {
	view    sqliteView
	counter uint32 // the header's file change counter, from the main file
	walMode bool   // the header's read and write versions say WAL
	wal     *walLog
	journal string // set when a rollback journal shows a live transaction
}

// sqliteView is the pages of one committed state, indexed by page number less
// one. A nil page does not exist.
type sqliteView struct {
	pageSize int
	usable   int
	pages    [][]byte
}

func (v sqliteView) page(n uint32) []byte {
	if n == 0 || int(n) > len(v.pages) {
		return nil
	}
	return v.pages[n-1]
}

// walLog is what a WAL holds: frames up to the last commit that verifies.
type walLog struct {
	salt1, salt2 uint32
	pageSize     int
	frames       []walFrame // committed frames only
	uncommitted  int        // valid frames past the last commit
}

type walFrame struct {
	pgno   uint32
	dbSize uint32 // nonzero on a commit frame: the database's size in pages
	data   []byte
}

const (
	sqliteMagic   = "SQLite format 3\x00"
	sqliteHdrSize = 100
	walMagicLE    = 0x377f0682
	walMagicBE    = 0x377f0683
	walHdrSize    = 32
	walFrameHdr   = 24
	journalHdr    = 28
)

var journalMagic = []byte{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7}

// readSQLiteImage reads the three files as one state. Nothing locks them, so
// it reads until two looks at their sizes and times agree around a read. On
// failure the image is empty, never nil.
func readSQLiteImage(path string) (*sqliteImage, error) {
	const tries = 20
	for i := 0; ; i++ {
		img, stable, err := readSQLiteOnce(path)
		switch {
		case err != nil:
			return &sqliteImage{}, err
		case stable:
			return img, nil
		case i == tries:
			return &sqliteImage{}, fmt.Errorf("%s: the files kept changing while being read", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// readSQLiteOnce reads the files once. stable is false if they moved meanwhile.
func readSQLiteOnce(path string) (img *sqliteImage, stable bool, err error) {
	before, err := sqliteStamp(path)
	if err != nil {
		return nil, false, err
	}
	main, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	wal, err := readIfThere(path + "-wal")
	if err != nil {
		return nil, false, err
	}
	journal, err := readIfThere(path + "-journal")
	if err != nil {
		return nil, false, err
	}
	after, err := sqliteStamp(path)
	if err != nil {
		return nil, false, err
	}
	if before != after {
		return nil, false, nil
	}
	img, err = buildSQLiteImage(path, main, wal, journal)
	return img, true, err
}

type sqliteFileStamp struct {
	size int64
	time time.Time
}

func sqliteStamp(path string) ([3]sqliteFileStamp, error) {
	var out [3]sqliteFileStamp
	for i, p := range []string{path, path + "-wal", path + "-journal"} {
		st, err := os.Stat(p)
		switch {
		case err == nil:
			out[i] = sqliteFileStamp{st.Size(), st.ModTime()}
		case i > 0 && errors.Is(err, os.ErrNotExist):
		default:
			return out, err
		}
	}
	return out, nil
}

func readIfThere(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// buildSQLiteImage decodes the files.
//
//subpoena:enforcement_point
func buildSQLiteImage(path string, main, wal, journal []byte) (*sqliteImage, error) {
	img := &sqliteImage{wal: parseWAL(wal), journal: liveJournal(journal)}
	mainSize := 0
	var dbPages uint32
	if len(main) != 0 {
		if len(main) < sqliteHdrSize || string(main[:len(sqliteMagic)]) != sqliteMagic {
			return nil, fmt.Errorf("%s: not a SQLite database", path) //subpoena:enforcement
		}
		mainSize = int(binary.BigEndian.Uint16(main[16:]))
		if mainSize == 1 {
			mainSize = 65536
		}
		if mainSize < 512 || mainSize&(mainSize-1) != 0 {
			return nil, fmt.Errorf("%s: page size %d", path, mainSize) //subpoena:enforcement
		}
		img.counter = binary.BigEndian.Uint32(main[24:])
		img.walMode = main[18] == 2 || main[19] == 2
		dbPages = uint32(len(main) / mainSize)
		// The header's count holds only if the counter beside it is current.
		if n := binary.BigEndian.Uint32(main[28:]); n != 0 && img.counter == binary.BigEndian.Uint32(main[92:]) {
			dbPages = min(n, dbPages)
		}
	}
	if len(main) == 0 || !img.walMode {
		// SQLite does not read a WAL beside a rollback-mode database, and
		// deletes one beside an empty file: its frames are not this
		// database's state.
		img.wal = nil //subpoena:enforcement
	}
	pageSize := mainSize
	if img.wal != nil {
		pageSize = img.wal.pageSize
	}
	if pageSize == 0 {
		return img, nil // an empty database with no pages yet
	}
	if mainSize != 0 && pageSize != mainSize {
		return nil, fmt.Errorf("%s: WAL page size %d, database %d", path, pageSize, mainSize) //subpoena:enforcement
	}
	img.view.pageSize = pageSize
	for n := uint32(0); n < dbPages; n++ {
		img.view.pages = append(img.view.pages, main[int(n)*pageSize:(int(n)+1)*pageSize])
	}
	if img.wal != nil {
		img.view = img.view.apply(img.wal.frames)
	}
	img.view.setUsable()
	return img, nil
}

// setUsable reads the reserved space from page 1, which a WAL may have replaced.
func (v *sqliteView) setUsable() {
	v.usable = v.pageSize
	if p := v.page(1); len(p) >= sqliteHdrSize {
		v.usable -= int(p[20])
	}
}

// apply is the view with frames laid over it, up to the last commit in them.
func (v sqliteView) apply(frames []walFrame) sqliteView {
	out := v
	out.pages = slices.Clone(v.pages)
	for _, f := range frames {
		if int(f.pgno) > len(out.pages) {
			out.pages = append(out.pages, make([][]byte, int(f.pgno)-len(out.pages))...)
		}
		out.pages[f.pgno-1] = f.data
		out.pageSize = len(f.data)
		if f.dbSize != 0 {
			if int(f.dbSize) < len(out.pages) {
				out.pages = out.pages[:f.dbSize]
			}
		}
	}
	out.setUsable()
	return out
}

// parseWAL reads a WAL as SQLite's recovery does: a header that verifies, then
// frames for as long as their salts match the header and their checksums
// chain. Frames count once a commit frame closes them. A WAL with no valid
// header is nil: SQLite ignores it, whatever follows.
//
//subpoena:enforcement_point
func parseWAL(b []byte) *walLog {
	if len(b) < walHdrSize {
		return nil
	}
	magic := binary.BigEndian.Uint32(b)
	if magic != walMagicLE && magic != walMagicBE {
		return nil
	}
	var order binary.ByteOrder = binary.LittleEndian
	if magic == walMagicBE {
		order = binary.BigEndian
	}
	pageSize := int(binary.BigEndian.Uint32(b[8:]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil
	}
	s0, s1 := walChecksum(order, 0, 0, b[:24])
	if s0 != binary.BigEndian.Uint32(b[24:]) || s1 != binary.BigEndian.Uint32(b[28:]) {
		return nil //subpoena:enforcement
	}
	l := &walLog{salt1: binary.BigEndian.Uint32(b[16:]), salt2: binary.BigEndian.Uint32(b[20:]), pageSize: pageSize}
	pending := 0
	for off := walHdrSize; off+walFrameHdr+pageSize <= len(b); off += walFrameHdr + pageSize {
		h := b[off : off+walFrameHdr]
		data := b[off+walFrameHdr : off+walFrameHdr+pageSize]
		if binary.BigEndian.Uint32(h[8:]) != l.salt1 || binary.BigEndian.Uint32(h[12:]) != l.salt2 {
			break //subpoena:enforcement
		}
		s0, s1 = walChecksum(order, s0, s1, h[:8])
		s0, s1 = walChecksum(order, s0, s1, data)
		if s0 != binary.BigEndian.Uint32(h[16:]) || s1 != binary.BigEndian.Uint32(h[20:]) {
			break //subpoena:enforcement
		}
		f := walFrame{pgno: binary.BigEndian.Uint32(h), dbSize: binary.BigEndian.Uint32(h[4:]), data: data}
		if f.pgno == 0 {
			break
		}
		l.frames = append(l.frames, f)
		pending++
		if f.dbSize != 0 {
			pending = 0
		}
	}
	l.uncommitted = pending
	l.frames = l.frames[:len(l.frames)-pending]
	return l
}

// walChecksum is the WAL's running checksum over b, a multiple of 8 bytes.
func walChecksum(order binary.ByteOrder, s0, s1 uint32, b []byte) (uint32, uint32) {
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:]) + s1
		s1 += order.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}

// liveJournal describes a rollback journal that shows a transaction in
// progress, or "" if it shows none: the file is missing, empty (truncate mode),
// or begins with 28 zero bytes (persist mode's blanked header). A journal not
// yet synced starts with zeros where its magic will go, but its nonce and sizes
// are written, so the whole header is what counts. A journal is live whatever
// its magic: the transaction may yet commit, or be rolled back, or, if its
// process died, be rolled back by the next connection.
func liveJournal(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := b[:min(journalHdr, len(b))]
	if !bytes.ContainsFunc(h, func(r rune) bool { return r != 0 }) {
		return ""
	}
	if bytes.HasPrefix(b, journalMagic) {
		return "a synced rollback journal: a transaction is committing, or its process died"
	}
	return "a rollback journal: a transaction is open"
}

// Change reports what the files say since the baseline. events is what a
// healthy file witness saw; it decides the cases the files alone cannot (see
// SQLiteDB). Call it after the witness stopped and the code under test is done.
//
//subpoena:enforcement_point
func (d *SQLiteDB) Change(events []FileEvent) SQLiteChange {
	end, err := readSQLiteImage(d.path)
	if err != nil {
		return SQLiteChange{Verdict: SQLiteUnknown, Reason: err.Error()} //subpoena:enforcement
	}
	if end.journal != "" {
		return SQLiteChange{Verdict: SQLiteUnknown, Reason: end.journal} //subpoena:enforcement
	}
	c := SQLiteChange{}
	if end.wal != nil {
		c.Uncommitted = end.wal.uncommitted
	}
	if frames, ok := d.framesSince(end, events); ok {
		c.Basis = BasisWALFrames
		d.readFrames(&c, frames)
	} else {
		c.Basis = BasisPageDiff
		d.readPages(&c, end, events)
	}
	if c.Verdict == "" {
		c.Verdict = SQLiteNoChange
		if len(c.Pages) != 0 || c.Commits != 0 {
			c.Verdict = SQLiteCommitted
		}
	}
	return c
}

// framesSince returns the frames committed since the baseline, if the WAL
// provably still holds all of them: it is the same WAL, grown; or it is a newer
// one and the main file was not written, so no checkpoint ran in the window,
// and a WAL cannot restart without one having finished.
//
//subpoena:enforcement_point
func (d *SQLiteDB) framesSince(end *sqliteImage, events []FileEvent) ([]walFrame, bool) {
	b, e := d.base.wal, end.wal
	if e == nil {
		return nil, false
	}
	if b != nil && b.salt1 == e.salt1 && b.salt2 == e.salt2 {
		if len(e.frames) < len(b.frames) {
			return nil, false // a WAL does not lose commits: this one was tampered with
		}
		return e.frames[len(b.frames):], true
	}
	if wroteTo(events, d.path) {
		return nil, false //subpoena:enforcement
	}
	return e.frames, true
}

// wroteTo reports whether events show path's content changing. A file found by
// a scan may have been written any number of times before the watch landed.
func wroteTo(events []FileEvent, path string) bool {
	return slices.ContainsFunc(events, func(e FileEvent) bool {
		return e.Path == path && (e.Op == FileWrite || e.Op == FileRename || e.Source == SourceScan)
	})
}

// readFrames fills c from frames: every committed page of the window, commit
// by commit, so a page's owner is read on each side of the commit that wrote
// it. A page that passes from one table to another inside the window, or a
// table that came and went, is named.
func (d *SQLiteDB) readFrames(c *SQLiteChange, frames []walFrame) {
	tables, schema, pages := map[string]bool{}, map[string]bool{}, map[uint32]bool{}
	view := d.base.view
	owners, err := sqliteOwners(view, schema)
	start := 0
	for i, f := range frames {
		if f.dbSize == 0 {
			continue
		}
		c.Commits++
		commit := frames[start : i+1]
		start = i + 1
		next := view.apply(commit)
		nextOwners, nextErr := sqliteOwners(next, schema)
		if err == nil {
			err = nextErr
		}
		changed := map[uint32]bool{}
		for _, cf := range commit {
			changed[cf.pgno] = true
		}
		// A shrink frees the pages past the new end with no frame for them.
		for n := len(next.pages) + 1; n <= len(view.pages); n++ {
			changed[uint32(n)] = true
		}
		for p := range changed {
			pages[p] = true
		}
		if err == nil {
			err = attribute(changed, view, next, owners, nextOwners, tables)
		}
		view, owners = next, nextOwners
	}
	c.finish(pages, tables, schema, err)
}

// readPages fills c from a comparison of the baseline's pages with the end's.
//
//subpoena:enforcement_point
func (d *SQLiteDB) readPages(c *SQLiteChange, end *sqliteImage, events []FileEvent) {
	before, after := d.base.view, end.view
	changed := map[uint32]bool{}
	for n := 1; n <= max(len(before.pages), len(after.pages)); n++ {
		if !bytes.Equal(before.page(uint32(n)), after.page(uint32(n))) {
			changed[uint32(n)] = true
		}
	}
	tables, schema := map[string]bool{}, map[string]bool{}
	bo, err := sqliteOwners(before, schema)
	ao, aerr := sqliteOwners(after, schema)
	if err == nil {
		err = aerr
	}
	if err == nil {
		err = attribute(changed, before, after, bo, ao, tables)
	}
	c.finish(changed, tables, schema, err)
	if d.base.walMode || end.walMode {
		// Frames are gone. Every commit in WAL mode writes the WAL, so with no
		// such write the pages are the whole story; with one, a change undone
		// before the checkpoint is possible and nothing can rule it out.
		c.Exact = false
		if len(changed) == 0 && wroteTo(events, d.path+"-wal") {
			c.Verdict = SQLiteUnknown //subpoena:enforcement
			c.Reason = "the WAL was written and its frames are gone; the pages match the baseline, but a change made and undone cannot be ruled out"
		}
		if len(changed) == 0 && c.Verdict == "" {
			c.Exact = true
		}
		return
	}
	// Rollback mode: a commit bumps the header's counter, a rollback restores
	// it, so the counter says what happened whatever the pages show.
	c.Commits = int(end.counter - d.base.counter)
	switch {
	case c.Commits > 1:
		c.Exact = false //subpoena:enforcement
		c.Reason = "several commits: a change undone by a later one leaves no mark on the pages"
	case c.Commits == 0 && len(changed) != 0:
		c.Exact = false //subpoena:enforcement
		c.Reason = "the pages changed and the change counter did not: this was not an ordinary commit"
	}
}

// finish records what was read. A table list resting on a failed walk is no
// list, so only the pages stand.
//
//subpoena:enforcement_point
func (c *SQLiteChange) finish(pages map[uint32]bool, tables, schema map[string]bool, err error) {
	if len(pages) != 0 {
		c.Pages = sortedPages(pages)
	}
	if err != nil {
		c.TableError = err.Error() //subpoena:enforcement
		return                     //subpoena:enforcement
	}
	c.Exact = true
	c.Tables = sortedNames(tables)
	c.Schema = sortedNames(schema)
}

func sortedPages(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func sortedNames(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Page owners that are not tables.
const (
	ownerFree   = "\x00freelist"
	ownerPtrmap = "\x00ptrmap"
	ownerLock   = "\x00lock"
)

// attribute adds to tables the owners of changed pages on each side of a
// change. A changed page owned by nothing on both sides means the map is wrong
// and is an error, so a table cannot go missing unnoticed.
//
//subpoena:enforcement_point
func attribute(changed map[uint32]bool, before, after sqliteView, bo, ao map[uint32]string, tables map[string]bool) error {
	for p := range changed {
		if p == 1 {
			// Page 1 is the file header and the root of the schema. Only the
			// part after the header is the schema.
			b, a := before.page(1), after.page(1)
			if len(b) < sqliteHdrSize || len(a) < sqliteHdrSize || !bytes.Equal(b[sqliteHdrSize:], a[sqliteHdrSize:]) {
				tables[SQLiteSchemaTable] = true //subpoena:enforcement
			}
			continue
		}
		o1, ok1 := bo[p]
		o2, ok2 := ao[p]
		if !ok1 && !ok2 {
			return fmt.Errorf("page %d changed and nothing owns it", p) //subpoena:enforcement
		}
		for _, o := range []string{o1, o2} {
			if o != "" && o[0] != 0 {
				tables[o] = true //subpoena:enforcement
			}
		}
	}
	return nil
}

// sqliteOwners maps every page of a view to what owns it, walking the schema
// and each b-tree, overflow chains included, then the freelist. Table and
// index names are added to schema, and an index's pages go to its table. A page
// claimed twice, a pointer out of range or a page of the wrong type is an
// error: the map would not be sound.
func sqliteOwners(v sqliteView, schema map[string]bool) (map[uint32]string, error) {
	owners := map[uint32]string{}
	if len(v.pages) == 0 {
		return owners, nil
	}
	w := &btreeWalk{v: v, owners: owners}
	rows, err := w.walkSchema()
	if err != nil {
		return nil, err
	}
	schema[SQLiteSchemaTable] = true
	for _, r := range rows {
		if r.typ == "table" {
			schema[r.tbl] = true
		}
		if (r.typ == "table" || r.typ == "index") && r.root != 0 {
			if err := w.walk(uint32(r.root), r.tbl, nil); err != nil {
				return nil, fmt.Errorf("%s %s: %w", r.typ, r.name, err)
			}
		}
	}
	if err := w.freelist(); err != nil {
		return nil, err
	}
	w.special()
	return owners, nil
}

type schemaRow struct {
	typ, name, tbl string
	root           int64
}

type btreeWalk struct {
	v      sqliteView
	owners map[uint32]string
}

func (w *btreeWalk) claim(p uint32, owner string) error {
	if p == 0 || int(p) > len(w.v.pages) || w.v.page(p) == nil {
		return fmt.Errorf("page %d is out of range", p)
	}
	if o, ok := w.owners[p]; ok {
		return fmt.Errorf("page %d is claimed twice (%q)", p, strings.TrimPrefix(o, "\x00"))
	}
	w.owners[p] = owner
	return nil
}

func (w *btreeWalk) walkSchema() ([]schemaRow, error) {
	var rows []schemaRow
	err := w.walk(1, SQLiteSchemaTable, func(payload []byte) error {
		r, err := parseSchemaRow(payload)
		if err == nil {
			rows = append(rows, r)
		}
		return err
	})
	return rows, err
}

// walk claims the tree rooted at p for owner, and hands each table-leaf
// cell's payload to leaf, if it is set.
func (w *btreeWalk) walk(p uint32, owner string, leaf func([]byte) error) error {
	if err := w.claim(p, owner); err != nil {
		return err
	}
	b := w.v.page(p)
	h := 0
	if p == 1 {
		h = sqliteHdrSize
	}
	if len(b) < h+8 {
		return fmt.Errorf("page %d is short", p)
	}
	kind := b[h]
	cells := int(binary.BigEndian.Uint16(b[h+3:]))
	ptrs := h + 8
	interior := kind == 2 || kind == 5
	if interior {
		ptrs = h + 12
	} else if kind != 10 && kind != 13 {
		return fmt.Errorf("page %d has b-tree type %d", p, kind)
	}
	for i := 0; i < cells; i++ {
		if ptrs+2*i+2 > len(b) {
			return fmt.Errorf("page %d: cell %d is past the page", p, i)
		}
		off := int(binary.BigEndian.Uint16(b[ptrs+2*i:]))
		if off >= w.v.usable || off >= len(b) {
			return fmt.Errorf("page %d: cell %d at %d", p, i, off)
		}
		cell := b[off:min(len(b), w.v.usable)]
		if interior {
			if len(cell) < 4 {
				return fmt.Errorf("page %d: cell %d is short", p, i)
			}
			if err := w.walk(binary.BigEndian.Uint32(cell), owner, leaf); err != nil {
				return err
			}
		}
		if kind == 5 {
			continue // key only: no payload
		}
		if interior {
			cell = cell[4:]
		}
		size, n := sqliteVarint(cell)
		if n == 0 {
			return fmt.Errorf("page %d: cell %d has a bad size", p, i)
		}
		cell = cell[n:]
		if kind == 13 {
			_, n := sqliteVarint(cell)
			if n == 0 {
				return fmt.Errorf("page %d: cell %d has a bad key", p, i)
			}
			cell = cell[n:]
		}
		payload, err := w.payload(cell, size, kind == 13, owner, leaf != nil)
		if err != nil {
			return fmt.Errorf("page %d: cell %d: %w", p, i, err)
		}
		if leaf != nil && kind == 13 {
			if err := leaf(payload); err != nil {
				return fmt.Errorf("page %d: cell %d: %w", p, i, err)
			}
		}
	}
	if interior {
		return w.walk(binary.BigEndian.Uint32(b[h+8:]), owner, leaf)
	}
	return nil
}

// payload follows a cell's overflow chain, claiming it for owner. keep says
// the bytes are wanted.
func (w *btreeWalk) payload(cell []byte, size uint64, table bool, owner string, keep bool) ([]byte, error) {
	u := uint64(w.v.usable)
	x := u - 35
	if !table {
		x = (u-12)*64/255 - 23
	}
	local := size
	if size > x {
		m := (u-12)*32/255 - 23
		local = m + (size-m)%(u-4)
		if local > x {
			local = m
		}
	}
	if local > uint64(len(cell)) {
		return nil, fmt.Errorf("payload of %d runs off the page", local)
	}
	var out []byte
	if keep {
		out = append(out, cell[:local]...)
	}
	if local == size {
		return out, nil
	}
	if local+4 > uint64(len(cell)) {
		return nil, errors.New("overflow pointer runs off the page")
	}
	next := binary.BigEndian.Uint32(cell[local:])
	left := size - local
	for left > 0 {
		if err := w.claim(next, owner); err != nil {
			return nil, fmt.Errorf("overflow: %w", err)
		}
		b := w.v.page(next)
		n := min(left, u-4)
		if keep {
			out = append(out, b[4:4+n]...)
		}
		left -= n
		next = binary.BigEndian.Uint32(b)
	}
	return out, nil
}

func (w *btreeWalk) freelist() error {
	h := w.v.page(1)
	trunk := binary.BigEndian.Uint32(h[32:])
	for trunk != 0 {
		if err := w.claim(trunk, ownerFree); err != nil {
			return fmt.Errorf("freelist: %w", err)
		}
		b := w.v.page(trunk)
		n := int(binary.BigEndian.Uint32(b[4:]))
		if 8+4*n > len(b) {
			return fmt.Errorf("freelist trunk %d lists %d pages", trunk, n)
		}
		for i := 0; i < n; i++ {
			if err := w.claim(binary.BigEndian.Uint32(b[8+4*i:]), ownerFree); err != nil {
				return fmt.Errorf("freelist: %w", err)
			}
		}
		trunk = binary.BigEndian.Uint32(b)
	}
	return nil
}

// special claims the pages no tree reaches: the lock-byte page, and in an
// auto_vacuum database the pointer maps.
func (w *btreeWalk) special() {
	lock := uint32(0x40000000/w.v.pageSize) + 1
	if int(lock) <= len(w.v.pages) {
		w.owners[lock] = ownerLock
	}
	if binary.BigEndian.Uint32(w.v.page(1)[52:]) == 0 {
		return
	}
	step := uint32(w.v.usable/5) + 1
	for at := uint32(2); int(at) <= len(w.v.pages); at += step {
		p := at
		if p == lock {
			p++ // the map that would land on the lock page sits just after it
		}
		w.owners[p] = ownerPtrmap
	}
}

// sqliteVarint decodes SQLite's big-endian varint, n being 0 if b is too short.
func sqliteVarint(b []byte) (v uint64, n int) {
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// parseSchemaRow reads a sqlite_schema record: type, name, tbl_name, rootpage.
func parseSchemaRow(p []byte) (schemaRow, error) {
	var r schemaRow
	hdr, n := sqliteVarint(p)
	if n == 0 || hdr > uint64(len(p)) {
		return r, errors.New("schema row: bad header")
	}
	types := p[n:hdr]
	body := p[hdr:]
	var col [4][]byte
	var ints [4]int64
	for i := range col {
		t, n := sqliteVarint(types)
		if n == 0 {
			return r, errors.New("schema row: too few columns")
		}
		types = types[n:]
		size := serialSize(t)
		if size > uint64(len(body)) {
			return r, errors.New("schema row: column runs off the record")
		}
		col[i] = body[:size]
		for _, c := range col[i] {
			ints[i] = ints[i]<<8 | int64(c)
		}
		switch t {
		case 8:
			ints[i] = 0
		case 9:
			ints[i] = 1
		}
		body = body[size:]
	}
	r.typ, r.name, r.tbl, r.root = string(col[0]), string(col[1]), string(col[2]), ints[3]
	return r, nil
}

// serialSize is the size of a record column of serial type t.
func serialSize(t uint64) uint64 {
	switch {
	case t <= 4:
		return t
	case t == 5:
		return 6
	case t == 6 || t == 7:
		return 8
	case t <= 11:
		return 0
	case t%2 == 0:
		return (t - 12) / 2
	}
	return (t - 13) / 2
}
