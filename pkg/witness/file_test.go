//subpoena:spec_derived
//subpoena:pure_logic

// The file witness, from the "New witnesses" section of the round 2 brief and
// witnesses/README.md: what inotify saw on a watched root, and Inconclusive
// when it could not see. Written before the implementation.
package witness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func watch(t *testing.T, roots ...string) *FileWatch {
	t.Helper()
	w, err := NewFileWatch(roots...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Stop() })
	return w
}

// held starts a witness whose reader does nothing until the returned function
// is called, so the test decides what lands in the queue before it is read.
func held(t *testing.T, h fileHooks, roots ...string) (*FileWatch, func()) {
	t.Helper()
	h.hold = make(chan struct{})
	w, err := newFileWatch(h, roots...)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			close(h.hold)
		}
	}
	t.Cleanup(func() {
		release()
		w.Stop()
	})
	return w, release
}

func saw(events []FileEvent, op FileOp, path string) bool {
	return slices.ContainsFunc(events, func(e FileEvent) bool { return e.Op == op && e.Path == path })
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Another process does the work, so nothing here depends on this process
// cooperating with the witness.
func TestFileWatchSeesEachKindFromAnotherProcess(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	gone := filepath.Join(root, "gone")
	write(t, old, "x")
	write(t, gone, "x")
	w := watch(t, root)
	before := time.Now()
	sh := fmt.Sprintf(`cd %q && echo new > made && echo more >> old && mv old moved && rm gone`, root)
	if out, err := exec.Command("sh", "-c", sh).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := w.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	got := w.Wrote("any")
	for _, want := range []struct {
		op   FileOp
		path string
	}{
		{FileCreate, filepath.Join(root, "made")},
		{FileWrite, filepath.Join(root, "made")},
		{FileWrite, old},
		{FileRename, old},
		{FileRename, filepath.Join(root, "moved")},
		{FileUnlink, gone},
	} {
		if !saw(got, want.op, want.path) {
			t.Errorf("no %s of %s in %+v", want.op, want.path, got)
		}
	}
	for _, e := range got {
		if e.Attribution != ByRoot || e.Root != root || e.Source != SourceInotify || e.TraceID != "" {
			t.Errorf("event %+v", e)
		}
		if e.SeenAt.Before(before) || e.SeenAt.After(time.Now()) {
			t.Errorf("SeenAt %v is not the time of reading", e.SeenAt)
		}
	}
}

// inotify reports nothing but a path, so the safe answer for every trace is
// everything, as Sinkhole's is.
func TestFileWatchReturnsEveryEventForEveryTrace(t *testing.T) {
	root := t.TempDir()
	w := watch(t, root)
	write(t, filepath.Join(root, "f"), "x")
	w.Stop()
	a, b := w.Wrote("a"), w.Wrote("b")
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("a=%d b=%d events", len(a), len(b))
	}
}

func TestFileRenameSidesAreTied(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a"), "x")
	w := watch(t, root)
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	var from, to FileEvent
	for _, e := range w.Wrote("") {
		switch e.Rename {
		case RenameFrom:
			from = e
		case RenameTo:
			to = e
		}
	}
	if from.Path != filepath.Join(root, "a") || to.Path != filepath.Join(root, "b") || from.Cookie == 0 || from.Cookie != to.Cookie {
		t.Fatalf("from %+v to %+v", from, to)
	}
}

func TestFileWatchIsRecursiveAndFollowsNewDirectories(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	write(t, filepath.Join(deep, "old-tree"), "x")
	made := filepath.Join(root, "new", "dir")
	if err := os.MkdirAll(made, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(made, "new-tree"), "x")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	got := w.Wrote("")
	if !saw(got, FileCreate, filepath.Join(deep, "old-tree")) {
		t.Errorf("missed a file in an existing subdirectory: %+v", got)
	}
	if !saw(got, FileCreate, filepath.Join(made, "new-tree")) {
		t.Errorf("missed a file in a new directory: %+v", got)
	}
	if !slices.ContainsFunc(got, func(e FileEvent) bool { return e.IsDir && e.Path == made && e.Op == FileCreate }) {
		t.Errorf("no directory create for %s: %+v", made, got)
	}
}

// The race the spec names: a directory created and written before its watch
// lands. The reader is held, so the watch cannot land until everything inside
// the tree is already done; only a scan can find it.
func TestAWriteBeforeTheWatchLandsIsFoundByTheScan(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	sub := filepath.Join(root, "d", "e", "f")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	early := filepath.Join(sub, "early")
	write(t, early, "x")
	release()
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := w.Health(); err != nil {
		t.Fatalf("a scan that worked is no gap: %v", err)
	}
	if !slices.ContainsFunc(w.Wrote(""), func(e FileEvent) bool {
		return e.Path == early && e.Source == SourceScan && e.Op == FileCreate
	}) {
		t.Fatalf("the scan missed %s: %+v", early, w.Wrote(""))
	}
	if c := w.Coverage(); c.NewDirs < 3 || c.Scanned < 1 {
		t.Fatalf("coverage %+v", c)
	}
}

// After the scan the directory is watched: later writes are seen as writes.
func TestANewDirectoryStaysWatchedAfterItsScan(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	sub := filepath.Join(root, "d")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	release()
	waitFor(t, func() bool { return w.Coverage().NewDirs == 1 })
	f := filepath.Join(sub, "later")
	write(t, f, "x")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(w.Wrote(""), func(e FileEvent) bool {
		return e.Path == f && e.Op == FileWrite && e.Source == SourceInotify
	}) {
		t.Fatalf("no inotify write of %s: %+v", f, w.Wrote(""))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

// A directory gone before its watch landed may have held anything: neither
// inotify nor a scan can say, so it is a gap, not silence.
func TestADirectoryGoneBeforeItsWatchIsAGap(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	sub := filepath.Join(root, "brief")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(sub, "secret"), "x")
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	release()
	w.Stop()
	if err := w.Health(); err == nil {
		t.Fatal("a directory never watched cannot be called empty")
	}
	if !hasGap(w, GapScan, sub) {
		t.Fatalf("gaps %+v", w.Coverage().Gaps)
	}
}

func hasGap(w *FileWatch, kind GapKind, path string) bool {
	return slices.ContainsFunc(w.Coverage().Gaps, func(g FileGap) bool {
		return g.Kind == kind && (path == "" || g.Path == path)
	})
}

// The lag bound is what stands between "nothing was seen" and "nothing
// happened" for a file made and removed before the watch landed.
func TestCoverageBoundsTheTimeANewDirectoryWentUnwatched(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	if err := os.Mkdir(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	const lag = 60 * time.Millisecond
	time.Sleep(lag)
	release()
	w.Stop()
	// Birth times come from a coarse clock, so they read early, never late.
	if got := w.Coverage().MaxWatchLag; got < lag {
		t.Fatalf("MaxWatchLag = %v, want at least %v", got, lag)
	}
}

// A real overflow: more events than the kernel will queue, with nobody reading.
func TestQueueOverflowFailsHealthAndKeepsWhatWasSeen(t *testing.T) {
	limit := 16384
	if b, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			limit = n
		}
	}
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	f, err := os.Create(filepath.Join(root, "flood"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Each pair differs from its neighbour, so the kernel cannot merge them.
	other := filepath.Join(root, "other")
	for i := 0; i < limit+16; i++ {
		if _, err := f.WriteString("x"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(other, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	release()
	w.Stop()
	err = w.Health()
	if err == nil || !strings.Contains(err.Error(), string(GapOverflow)) {
		t.Fatalf("Health = %v", err)
	}
	if c := w.Coverage(); c.Overflow == 0 || !hasGap(w, GapOverflow, "") {
		t.Fatalf("coverage %+v", c)
	}
	if len(w.Wrote("")) == 0 {
		t.Fatal("the overflow must not erase what was seen")
	}
}

// A limit met at the start, on a subdirectory, leaves a capture that runs and
// says so.
func TestARootThatVanishesFailsHealth(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	f := filepath.Join(root, "f")
	write(t, f, "x")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	if err := w.Health(); err == nil || !strings.Contains(err.Error(), string(GapRoot)) {
		t.Fatalf("Health = %v", err)
	}
	if !saw(w.Wrote(""), FileUnlink, f) {
		t.Fatalf("what was seen before the root went must stay: %+v", w.Wrote(""))
	}
}

func TestARootMovedAwayFailsHealth(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	if err := os.Rename(root, filepath.Join(dir, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	if !hasGap(w, GapRoot, root) || w.Health() == nil {
		t.Fatalf("Health %v, gaps %+v", w.Health(), w.Coverage().Gaps)
	}
}

// inotify on the root says nothing when a directory above it moves, and the
// paths the witness would report are then wrong. Only Stop can notice.
func TestARootReplacedThroughItsParentFailsHealth(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	if err := os.Rename(parent, filepath.Join(dir, "away")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil { // same path, another directory
		t.Fatal(err)
	}
	w.Stop()
	if !hasGap(w, GapRoot, root) || w.Health() == nil {
		t.Fatalf("Health %v, gaps %+v", w.Health(), w.Coverage().Gaps)
	}
}

func TestHealthNeedsAStoppedCapture(t *testing.T) {
	root := t.TempDir()
	w := watch(t, root)
	if err := w.Health(); err == nil {
		t.Fatal("a running capture cannot certify absence")
	}
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := w.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("a second Stop: %v", err)
	}
}

// Everything done before Stop is in the capture, however little time the
// reader had: this is what lets a test stop and then trust an empty answer.
func TestStopDrainsTheQueue(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	const n = 500
	for i := 0; i < n; i++ {
		write(t, filepath.Join(root, "f"+strconv.Itoa(i)), "x")
	}
	release()
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	got := w.Wrote("")
	for i := 0; i < n; i++ {
		if !saw(got, FileCreate, filepath.Join(root, "f"+strconv.Itoa(i))) {
			t.Fatalf("missing f%d of %d events", i, len(got))
		}
	}
}

func TestAMissingRootIsAnError(t *testing.T) {
	if _, err := NewFileWatch(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("no watch, no witness")
	}
	f := filepath.Join(t.TempDir(), "file")
	write(t, f, "x")
	if _, err := NewFileWatch(f); err == nil {
		t.Fatal("a root is a directory")
	}
	if _, err := NewFileWatch(); err == nil {
		t.Fatal("no roots: nothing would ever be seen")
	}
}

func TestCoversIsAboutWatchedRootsOnly(t *testing.T) {
	root := t.TempDir()
	w := watch(t, root)
	for path, want := range map[string]bool{
		root:                         true,
		filepath.Join(root, "a/b"):   true,
		root + "-sibling":            false,
		filepath.Dir(root):           false,
		"relative":                   false,
		filepath.Join(root, "../up"): false,
	} {
		if got := w.Covers(path); got != want {
			t.Errorf("Covers(%q) = %v", path, got)
		}
	}
}

func TestTouches(t *testing.T) {
	e := FileEvent{Op: FileWrite, Path: "/r/a/b"}
	for path, want := range map[string]bool{"/r/a/b": true, "/r/a": true, "/r": true, "/r/a/b/c": false, "/r/a/bc": false, "/r/x": false} {
		if got := e.Touches(path); got != want {
			t.Errorf("write of /r/a/b touches %s = %v", path, got)
		}
	}
	// Moving a directory moves what is in it, with no event naming it.
	mv := FileEvent{Op: FileRename, Path: "/r/a", IsDir: true}
	if !mv.Touches("/r/a/secret") {
		t.Error("a rename above a path touches it")
	}
	if (FileEvent{Op: FileCreate, Path: "/r/a", IsDir: true}).Touches("/r/a/secret") {
		t.Error("making a directory does not touch what might later be in it")
	}
}

// Renaming a watched directory keeps it watched, under its new name.
func TestARenamedDirectoryReportsItsNewPath(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a", "in")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return saw(w.Wrote(""), FileRename, filepath.Join(root, "b")) })
	f := filepath.Join(root, "b", "in", "f")
	write(t, f, "x")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if !saw(w.Wrote(""), FileCreate, f) {
		t.Fatalf("no event under the new name: %+v", w.Wrote(""))
	}
}

// A tree moved in from outside the root arrives whole, with no create for any
// file in it: only the scan can name them.
func TestATreeMovedInIsScanned(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	tree := filepath.Join(outside, "tree", "sub")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(tree, "f"), "x")
	w := watch(t, root)
	if err := os.Rename(filepath.Join(outside, "tree"), filepath.Join(root, "tree")); err != nil {
		t.Fatal(err)
	}
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if !saw(w.Wrote(""), FileCreate, filepath.Join(root, "tree", "sub", "f")) {
		t.Fatalf("the moved-in file went unseen: %+v", w.Wrote(""))
	}
}

// A tree moved out is outside the root: what happens to it there is not
// reported under the path it left.
func TestATreeMovedOutStopsReporting(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	away := filepath.Join(outside, "sub")
	if err := os.Rename(sub, away); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return saw(w.Wrote(""), FileRename, sub) })
	// Let the reader settle the rename as one-sided, then touch the tree.
	waitFor(t, func() bool { return w.Coverage().Watches == 1 })
	write(t, filepath.Join(away, "after"), "x")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := w.Health(); err != nil {
		t.Fatal(err)
	}
	if saw(w.Wrote(""), FileCreate, filepath.Join(sub, "after")) {
		t.Fatalf("reported a file outside the root: %+v", w.Wrote(""))
	}
}

// An mmap write reaches inotify only as a close after opening for writing.
func TestACloseWithNoWriteIsReportedAsPossiblyMissed(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "f")
	write(t, f, "x")
	touched := filepath.Join(root, "touched")
	write(t, touched, "x")
	w := watch(t, root)
	h, err := os.OpenFile(f, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	h, err = os.OpenFile(touched, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.WriteString("y")
	h.Close()
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := w.Coverage().SilentCloses; !slices.Equal(got, []string{f}) {
		t.Fatalf("SilentCloses = %v", got)
	}
	if len(w.Wrote("")) != 1 {
		t.Fatalf("a silent close is not a write: %+v", w.Wrote(""))
	}
}

func TestSeveralRoots(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	w := watch(t, a, b)
	write(t, filepath.Join(b, "f"), "x")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if !w.Covers(a) || !w.Covers(b) {
		t.Fatal("both roots are watched")
	}
	got := w.Wrote("")
	if len(got) == 0 || got[0].Root != b {
		t.Fatalf("events %+v", got)
	}
}

// Symlinks are not followed: a link out of the root must not widen what the
// witness claims to watch.
func TestASymlinkOutOfTheRootIsNotFollowed(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	write(t, filepath.Join(outside, "f"), "x")
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := w.Wrote(""); len(got) != 0 {
		t.Fatalf("events %+v", got)
	}
	if c := w.Coverage(); c.Watches != 1 {
		t.Fatalf("watches %d", c.Watches)
	}
}
