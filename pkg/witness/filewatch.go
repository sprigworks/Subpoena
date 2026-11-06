package witness

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// FileWatch is the tier-1 file witness: inotify on watched directories,
// recursive, reporting what the kernel queued. It needs no root, and the
// application cannot unsay what the kernel queued. It reports events, not a
// before and after comparison: a file written and restored is still a write.
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
//     host (NFS), or one in a layer below an overlay mount is not seen.
//   - A change through mmap is not seen as a write; see
//     FileCoverage.SilentCloses.
//   - A file created and removed inside a new directory before that
//     directory's watch landed leaves no trace; see FileCoverage.MaxWatchLag.
//   - Attribute changes (chmod, chown, utimes) are not reported.
//   - Symlinks are not followed.
type FileWatch struct {
	roots []string
	hooks fileHooks
	state *inotifyState // owned by the reader once started
	stop  func()        // asks the reader to drain and finish
	done  chan struct{}

	mu        sync.Mutex
	events    []FileEvent
	gaps      []FileGap
	coverage  FileCoverage
	silent    map[string]bool
	finished  bool
	stopOnce  sync.Once
	lastEmpty time.Time // when the queue was last seen empty
}

var (
	_ FileWitness    = (*FileWatch)(nil)
	_ HealthReporter = (*FileWatch)(nil)
)

// fileHooks replace the system in tests.
type fileHooks struct {
	hold     chan struct{} // the reader waits on this before its first read
	addWatch func(fd int, path string, mask uint32) (int, error)
	readDir  func(string) ([]os.DirEntry, error)
}

// NewFileWatch watches each root, a directory, and everything under it, and
// starts recording. A root that cannot be watched is an error. A subdirectory
// that cannot be watched is a gap: the capture runs, and Health fails.
func NewFileWatch(roots ...string) (*FileWatch, error) { return newFileWatch(fileHooks{}, roots...) }

func newFileWatch(h fileHooks, roots ...string) (*FileWatch, error) {
	if len(roots) == 0 {
		return nil, errors.New("file witness: no roots")
	}
	if h.readDir == nil {
		h.readDir = os.ReadDir
	}
	w := &FileWatch{hooks: h, done: make(chan struct{}), silent: map[string]bool{}, lastEmpty: time.Now()}
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
func (w *FileWatch) record(e FileEvent) {
	e.Attribution, e.SeenAt = ByRoot, time.Now()
	e.Root = w.rootOf(e.Path)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, e)
	w.coverage.Events++
	if e.Source == SourceScan {
		w.coverage.Scanned++
	}
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
// fill it.
//
//subpoena:enforcement_point
func (w *FileWatch) gap(kind GapKind, path, detail string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gaps = append(w.gaps, FileGap{Kind: kind, Path: path, Detail: detail}) //subpoena:enforcement
}

// Stop ends the capture: it reads everything the kernel has queued, which is
// every change made before Stop was called, then checks each root is still
// the directory it watched. A change made during Stop may go unseen, so stop
// only after the code under test is done. Call it before asking Wrote or
// Health; later calls return the same result.
func (w *FileWatch) Stop() error {
	w.stopOnce.Do(func() {
		w.stop()
		<-w.done
		w.mu.Lock()
		w.finished = true
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

// Covers reports whether path, an absolute path, lies under a root. The test
// is on the spelling: a path that reaches a root through a symlink is not
// covered, since no event would ever carry that spelling.
func (w *FileWatch) Covers(path string) bool {
	return filepath.IsAbs(path) && w.rootOf(filepath.Clean(path)) != ""
}

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
	c.Gaps = slices.Clone(w.gaps) //subpoena:enforcement
	c.SilentCloses = nil
	for p := range w.silent {
		c.SilentCloses = append(c.SilentCloses, p) //subpoena:enforcement
	}
	sort.Strings(c.SilentCloses)
	return c
}
