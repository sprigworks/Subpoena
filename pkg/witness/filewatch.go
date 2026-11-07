package witness

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// FileWatch is the tier-1 file witness: inotify on watched directories,
// recursive, reporting what the kernel queued. It needs no root, and the
// application cannot unsay what the kernel queued, though it can avoid the
// queue: see the limits. It reports events, not a before and after comparison:
// a file written and restored is still a write. Behind the events is one weaker
// check: Stop compares every file that was there at the start with what the
// start saw, and reports a difference no event explains (SourceStat).
//
// inotify has no PID, and unprivileged fanotify gives none either, so nothing
// ties an event to a process or a trace. Wrote returns every event for every
// trace (ByRoot), as Sinkhole's Dialed does: safe for an absence claim, exact
// when one trace is in flight. Point the root at what the claim is about, and
// stop the code under test before calling Stop.
//
// Limits, deliberately visible (witnesses/README.md has them all):
//   - Inotify is told of writes made through a path under a watched directory.
//     A write through a hard link outside the root, a change made on another
//     host (NFS), or one in a layer below an overlay mount queues nothing, and
//     is caught only by the check at Stop.
//   - A change through mmap, or by Linux native AIO (io_submit), queues nothing
//     either, whatever the application's privileges: inotify cannot see them.
//     The check at Stop sees the timestamps they move, and a descriptor closed
//     before Stop is in FileCoverage.SilentCloses. Neither is proof: a store to
//     a mapped page already dirty when the capture began moves no timestamp,
//     so through a mapping held open past Stop it leaves no sign at all.
//   - A file created and removed inside a new directory before that
//     directory's watch landed leaves no trace; see FileCoverage.MaxWatchLag.
//   - Attribute changes (chmod, chown, utimes) queue nothing; the check at
//     Stop reports them as writes to files that were there at the start.
//   - Symlinks are not followed. A path crossing one is not covered.
type FileWatch struct {
	roots    []string
	hooks    fileHooks
	state    *inotifyState // owned by the reader once started
	stop     func()        // asks the reader to drain and finish
	stopping atomic.Bool   // set before the stop byte is written
	done     chan struct{}

	mu        sync.Mutex
	events    []FileEvent
	gaps      []FileGap
	coverage  FileCoverage
	silent    map[string]bool
	symlinks  map[string]bool // every symlink seen under a root
	capped    bool            // events stopped being kept
	finished  bool
	started   time.Time
	stopped   time.Time
	stopOnce  sync.Once
	lastEmpty time.Time // when the queue was last seen empty
}

var (
	_ FileWitness    = (*FileWatch)(nil)
	_ HealthReporter = (*FileWatch)(nil)
)

// fileHooks replace the system in tests.
type fileHooks struct {
	hold      chan struct{} // the reader waits on this before its first read
	addWatch  func(fd int, path string, mask uint32) (int, error)
	readDir   func(string) ([]os.DirEntry, error)
	read      func(fd int, buf []byte) (int, error) // the read of the queue
	maxQueue  int                                   // the most events a queue can hold
	maxEvents int                                   // the most events kept
}

// The most events and gaps a capture keeps. At 500 bytes or so an event this is
// half a gigabyte; past it the capture has a gap, and memory stays bounded.
const (
	maxFileEvents = 1 << 20
	maxFileGaps   = 1024
)

// NewFileWatch watches each root, a directory, and everything under it, and
// starts recording. A root that cannot be watched is an error. A subdirectory
// that cannot be watched is a gap: the capture runs, and Health fails. Two
// spellings of one directory, as two roots or one inside the other, are refused:
// the kernel keeps one watch and one spelling, so a claim on the other could
// never match an event.
func NewFileWatch(roots ...string) (*FileWatch, error) { return newFileWatch(fileHooks{}, roots...) }

func newFileWatch(h fileHooks, roots ...string) (*FileWatch, error) {
	if len(roots) == 0 {
		return nil, errors.New("file witness: no roots")
	}
	if h.readDir == nil {
		h.readDir = os.ReadDir
	}
	if h.maxEvents == 0 {
		h.maxEvents = maxFileEvents
	}
	w := &FileWatch{hooks: h, done: make(chan struct{}), silent: map[string]bool{}, symlinks: map[string]bool{}, started: time.Now(), lastEmpty: time.Now()}
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, fmt.Errorf("file witness: %w", err)
		}
		w.roots = append(w.roots, abs)
	}
	w.coverage.Roots = slices.Clone(w.roots)
	if err := w.start(); err != nil {
		return nil, fmt.Errorf("file witness: %w", err)
	}
	return w, nil
}

// record adds an event seen now. Called by the reader only.
//
//subpoena:enforcement_point
func (w *FileWatch) record(e FileEvent) {
	e.Attribution, e.SeenAt = ByRoot, time.Now()
	e.Root = w.rootOf(e.Path)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coverage.Events++
	switch e.Source {
	case SourceScan:
		w.coverage.Scanned++
	case SourceStat:
		w.coverage.Stat++
	}
	if len(w.events) >= w.hooks.maxEvents {
		if !w.capped {
			w.capped = true
			w.gaps = append(w.gaps, FileGap{Kind: GapBound, Detail: fmt.Sprintf("more than %d events: later ones were not kept", w.hooks.maxEvents)}) //subpoena:enforcement
		}
		return
	}
	w.events = append(w.events, e)
}

func (w *FileWatch) rootOf(path string) string {
	best := ""
	for _, r := range w.roots {
		if pathWithin(path, r) && len(r) > len(best) {
			best = r
		}
	}
	return best
}

// gap records a hole in the capture. A hole is for good: later events do not
// fill it. Past maxFileGaps the first ones stand for the rest.
//
//subpoena:enforcement_point
func (w *FileWatch) gap(kind GapKind, path, detail string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.gaps) < maxFileGaps {
		w.gaps = append(w.gaps, FileGap{Kind: kind, Path: path, Detail: detail}) //subpoena:enforcement
	}
}

// noteSymlink records a symlink under a root. Called by the reader, or before
// it starts.
func (w *FileWatch) noteSymlink(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.symlinks[path] = true
}

// Stop ends the capture: it reads everything the kernel had queued when Stop
// was called, which is every change made before then, checks each root is
// still the directory it watched, and compares the files that were there at
// the start with what the start saw. A change made during Stop may go unseen, so
// stop only after the code under test is done: if writers are still going
// when Stop has read all it owes, it returns anyway, with a gap. Call it before
// asking Wrote or Health; later calls return the same result.
func (w *FileWatch) Stop() error {
	w.stopOnce.Do(func() {
		w.stop()
		<-w.done
		w.state.close()
		w.mu.Lock()
		w.finished, w.stopped = true, time.Now()
		w.mu.Unlock()
	})
	return w.Health()
}

// Wrote returns every event seen under the roots, whatever the trace: inotify
// cannot tell one trace from another.
func (w *FileWatch) Wrote(string) []FileEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.events)
}

// Covers reports whether path, an absolute path, lies under a root and crosses
// no symlink below it. The test is on the spelling: a path that reaches a root
// through a symlink is not covered, since no event would ever carry that
// spelling, and one that goes on through a symlink inside the root is not
// either, since a write there is spelled another way or lands outside. Every
// symlink under the roots is known once Stop has run.
func (w *FileWatch) Covers(path string) bool {
	if !filepath.IsAbs(path) || w.rootOf(filepath.Clean(path)) == "" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !crossesSymlink(path, slices.Collect(maps.Keys(w.symlinks)))
}

// crossesSymlink reports whether path is one of links or lies below one.
func crossesSymlink(path string, links []string) bool {
	return slices.ContainsFunc(links, func(l string) bool { return pathWithin(path, l) })
}

// Roots are the directories watched, as they were given.
func (w *FileWatch) Roots() []string { return slices.Clone(w.roots) }

// SilentCloses are the files closed with no write seen: see FileCoverage.
func (w *FileWatch) SilentCloses() []string { return w.Coverage().SilentCloses }

// Health reports whether the capture is complete: stopped, and with no gap
// along the way. A later success does not erase a gap. nil means no known
// fault, not freedom from the limits in FileCoverage.
//
//subpoena:enforcement_point
func (w *FileWatch) Health() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.gaps) != 0 {
		return fmt.Errorf("file witness: %d gap(s), first: %s", len(w.gaps), w.gaps[0]) //subpoena:enforcement
	}
	if !w.finished {
		return errors.New("file witness: capture has not stopped") //subpoena:enforcement
	}
	return nil
}

// Coverage says what this capture might have missed. Log it next to an
// absence claim.
//
//subpoena:enforcement_point
func (w *FileWatch) Coverage() FileCoverage {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.coverage
	c.Roots = slices.Clone(c.Roots)
	c.Gaps = slices.Clone(w.gaps)                       //subpoena:enforcement
	c.SilentCloses = slices.Sorted(maps.Keys(w.silent)) //subpoena:enforcement
	return c
}

// WriteLog writes a stopped capture as witness-file lines (docs/ports.md W7): a
// start record naming the roots, one FileLine per event, and a stop record with
// the capture's health and coverage. It is how a test in another language gets
// the capture; ReadLog reads it back.
func (w *FileWatch) WriteLog(dst io.Writer) error {
	if err := w.WriteStart(dst); err != nil {
		return err
	}
	return w.WriteEnd(dst)
}

// WriteStart writes the start record, which can be done at any time: a process
// that writes it once attached and WriteEnd once stopped leaves an open window
// if it is killed between them, and a reader's Health fails on that.
func (w *FileWatch) WriteStart(dst io.Writer) error {
	return json.NewEncoder(dst).Encode(Record{Time: w.started.UTC(), Record: RecordStart, Roots: w.roots, Captures: []string{CaptureFile}})
}

// WriteEnd writes the rest of WriteLog, after WriteStart: the events and the
// stop record. JSON cannot carry a name that is not UTF-8: it would be read
// back as another name and an exact-path claim would miss it. So such a capture
// is written as unhealthy, and WriteEnd returns the fault.
//
//subpoena:enforcement_point
func (w *FileWatch) WriteEnd(dst io.Writer) error {
	w.mu.Lock()
	finished := w.finished
	links := slices.Sorted(maps.Keys(w.symlinks))
	w.mu.Unlock()
	if !finished {
		return errors.New("file witness: capture has not stopped")
	}
	enc := json.NewEncoder(dst)
	var unnamed error
	check := func(p string) {
		if unnamed == nil && !utf8.ValidString(p) {
			unnamed = fmt.Errorf("file witness: the name %q is not UTF-8, so the log cannot carry it", p) //subpoena:enforcement
		}
	}
	coverage := w.Coverage()
	for _, p := range slices.Concat(w.roots, links, coverage.SilentCloses) {
		check(p)
	}
	for _, e := range w.Wrote("") {
		check(e.Path)
		if err := enc.Encode(FileLine{
			Time: e.SeenAt.UTC(), FileOp: string(e.Op), Path: e.Path, Root: e.Root, IsDir: e.IsDir, Source: string(e.Source),
			Rename: e.Rename, Cookie: e.Cookie, TraceID: e.TraceID, Attribution: string(e.Attribution),
		}); err != nil {
			return err
		}
	}
	stop := Record{Time: w.stopped.UTC(), Record: RecordStop, Healthy: true, Coverage: coverage.String(), SilentCloses: coverage.SilentCloses, Symlinks: links}
	if err := errors.Join(w.Health(), unnamed); err != nil {
		stop.Healthy, stop.Error = false, err.Error()
	}
	return errors.Join(enc.Encode(stop), unnamed)
}
