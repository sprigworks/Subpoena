package witness

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ByRoot means the event was seen under a directory the test watches, not tied
// to any trace or process. Like ByDestination it is returned for every trace:
// the safe direction for an absence claim, exact when one trace is in flight.
const ByRoot Attribution = "root"

// FileOp is what a file witness saw happen to a path.
type FileOp string

const (
	// FileCreate is a new name: a file, directory, symlink or hard link.
	FileCreate FileOp = "create"
	// FileWrite is a change to a file's content, truncation included.
	FileWrite FileOp = "write"
	// FileRename is one side of a rename; see FileEvent.Rename.
	FileRename FileOp = "rename"
	// FileUnlink is a name removed: unlink or rmdir.
	FileUnlink FileOp = "unlink"
)

// FileSource says how a file witness came to know of an event.
type FileSource string

const (
	// SourceInotify means the kernel queued the event.
	SourceInotify FileSource = "inotify"
	// SourceScan means a scan of a new directory found the entry: it was
	// there before the directory's watch landed, or arrived with a directory
	// moved in. Its Op is FileCreate whatever was done to it. The same name
	// can be reported by the scan and by inotify; count events, not files.
	SourceScan FileSource = "scan"
	// SourceStat means no kernel event named the path, but Stop found it
	// differing from what the capture's start saw: its size, mtime, ctime,
	// identity or existence. It is how a change inotify does not report shows
	// up (see FileWatch), and it over-reports: a chmod or a new hard link moves
	// ctime too. It says the file changed since the start, not when or how.
	SourceStat FileSource = "stat"
)

// Sides of a rename, in FileEvent.Rename.
const (
	RenameFrom = "from"
	RenameTo   = "to"
)

// FileEvent is one observed change under a watched root. It carries no PID:
// inotify has none to give.
type FileEvent struct {
	Op     FileOp
	Path   string // absolute, spelled from the root as it was given
	Root   string // the watched root Path is under
	IsDir  bool
	Source FileSource
	// Rename is RenameFrom or RenameTo on a FileRename. Each side is its own
	// event; Cookie, nonzero, ties the two. A rename across the edge of the
	// watched tree has only one side.
	Rename      string
	Cookie      uint32
	TraceID     string // set only by a witness that can attribute to a trace
	Attribution Attribution
	SeenAt      time.Time // when the witness read the event, not when it happened
}

// Within reports whether the event's path is path or lies below it.
func (e FileEvent) Within(path string) bool { return pathWithin(e.Path, path) }

// Touches reports whether the event says something happened to path: it is
// path, it lies below path, or it renamed a directory above path, which moved
// path without any event naming it.
func (e FileEvent) Touches(path string) bool {
	return e.Within(path) || (e.Op == FileRename && pathWithin(path, e.Path))
}

// pathWithin reports whether p is dir or lies below it, comparing cleaned paths.
func pathWithin(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if p == dir || dir == string(filepath.Separator) {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

// FileWitness reports changes to files, as Witness does for processes and
// NetworkWitness for connections, under the same rules: independent of the
// application, over-reporting rather than under-reporting, and able to certify
// absence only through HealthReporter.
type FileWitness interface {
	// Wrote returns the file changes seen on behalf of traceID. Implementations
	// must err toward over-reporting: an absence claim built on this must
	// never pass because the witness was unsure.
	Wrote(traceID string) []FileEvent
	// Covers reports whether the witness watched path, an absolute path. A
	// path it did not watch can never appear in Wrote, so no absence rests on
	// it: a typo or another spelling of the path must not read as a pass, and
	// neither must a path that crosses a symlink, whose writes are spelled
	// another way or land outside the root.
	Covers(path string) bool
	// Roots are the directories watched. None means nothing was, so a claim
	// about "anything under the roots" has nothing under it.
	Roots() []string
	// SilentCloses are the files opened for writing and closed with no write
	// seen. See FileCoverage. No absence rests on such a file.
	SilentCloses() []string
}

// GapKind says why a capture is incomplete.
type GapKind string

const (
	// GapOverflow is IN_Q_OVERFLOW: the kernel's queue filled, and an unknown
	// number of events anywhere under every root were dropped.
	GapOverflow GapKind = "overflow"
	// GapWatchLimit is a directory with no watch because the per-user limit
	// (fs.inotify.max_user_watches) ran out. Nothing in it is seen from then on.
	GapWatchLimit GapKind = "watch-limit"
	// GapRoot is a root that vanished, moved, was replaced or was unmounted.
	GapRoot GapKind = "root"
	// GapScan is a directory that could not be watched or read, or was gone
	// before its watch landed: what happened inside it is unknown.
	GapScan GapKind = "scan"
	// GapRead is a failed read of the inotify queue, an event that did not
	// decode, or one from a watch the witness does not know.
	GapRead GapKind = "read"
	// GapBound is a capture cut short by a limit: writers still going when
	// Stop had read all it owed, or more events than the witness will hold.
	GapBound GapKind = "bound"
)

// FileGap is one known hole in a capture.
type FileGap struct {
	Kind   GapKind
	Path   string // the directory concerned; empty when it is not one directory
	Detail string
}

func (g FileGap) String() string {
	if g.Path == "" {
		return fmt.Sprintf("%s: %s", g.Kind, g.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", g.Kind, g.Path, g.Detail)
}

// FileCoverage says what a FileWatch capture might have missed. Gaps fail
// Health. The other fields do not, because a clean capture has them too: they
// are the witness's limits on this run, to log next to an absence claim.
type FileCoverage struct {
	Roots    []string
	Watches  int // directories under watch at the last count
	NewDirs  int // directories watched after the capture began
	Scanned  int // entries found by scanning new directories
	Events   int // events recorded, scan findings included
	Stat     int // of those, changes only the check at Stop found (SourceStat)
	Overflow int // IN_Q_OVERFLOW events
	Gaps     []FileGap
	// MaxWatchLag is the longest a new directory went unwatched, an upper
	// bound: from the directory's birth, or from the last time the queue was
	// seen empty if that is later, to its watch landing. A file created and
	// removed inside a new directory within this long left no trace: inotify
	// had no watch there, and the scan came after it was gone. No gap is
	// raised for it, because no sign of it exists.
	MaxWatchLag time.Duration
	// SilentCloses are files closed after being opened for writing with no
	// write seen since the last close. Most are harmless (SQLite opens
	// read-write and may only read), but a change made through mmap or Linux
	// native AIO reaches inotify in no other way, so NoWrite is Inconclusive
	// about a path holding one.
	SilentCloses []string
}

// String is the coverage in one line, for a log.
func (c FileCoverage) String() string {
	return fmt.Sprintf("roots=%v watches=%d new_dirs=%d scanned=%d events=%d stat=%d overflows=%d gaps=%d max_watch_lag=%s silent_closes=%d",
		c.Roots, c.Watches, c.NewDirs, c.Scanned, c.Events, c.Stat, c.Overflow, len(c.Gaps), c.MaxWatchLag, len(c.SilentCloses))
}
