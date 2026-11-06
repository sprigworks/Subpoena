//subpoena:impl_derived
//subpoena:pure_logic

// The witness's own guards, driven one at a time. Each failure here has others
// behind it in real life (a deleted root gives three signals), so these feed
// the reader single kernel events, with the reader itself held, to prove each
// guard stands alone. Written after reading the implementation.
package witness

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// wdOf returns the watch on dir.
func wdOf(t *testing.T, w *FileWatch, dir string) int32 {
	t.Helper()
	for wd, d := range w.state.wds {
		if d == dir {
			return wd
		}
	}
	t.Fatalf("no watch on %s", dir)
	return 0
}

func TestEachRootSignalIsAGapByItself(t *testing.T) {
	for name, mask := range map[string]uint32{
		"deleted": unix.IN_DELETE_SELF,
		"moved":   unix.IN_MOVE_SELF,
		"ignored": unix.IN_IGNORED,
		"unmount": unix.IN_UNMOUNT,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			w, release := held(t, fileHooks{}, root)
			defer release()
			w.handle(rawInotify{wd: wdOf(t, w, root), mask: mask})
			if !hasGap(w, GapRoot, root) {
				t.Fatalf("gaps %+v", w.Coverage().Gaps)
			}
		})
	}
}

// The same signals on a subdirectory are its ordinary end: its parent reports
// the unlink.
func TestASubdirectoryGoingIsNoGap(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	w, release := held(t, fileHooks{}, root)
	defer release()
	wd := wdOf(t, w, sub)
	for _, mask := range []uint32{unix.IN_MOVE_SELF, unix.IN_DELETE_SELF, unix.IN_IGNORED} {
		w.handle(rawInotify{wd: wd, mask: mask})
	}
	if g := w.Coverage().Gaps; len(g) != 0 {
		t.Fatalf("gaps %+v", g)
	}
}

func TestAnEventFromAnUnknownWatchIsAGap(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	defer release()
	w.handle(rawInotify{wd: 9999, mask: unix.IN_MODIFY, name: "x"})
	if !hasGap(w, GapRead, "") {
		t.Fatalf("gaps %+v", w.Coverage().Gaps)
	}
}

// A watch the witness took off itself may still have events queued.
func TestAnEventFromARemovedWatchIsNoGap(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	defer release()
	w.state.removed[77] = true
	w.handle(rawInotify{wd: 77, mask: unix.IN_MODIFY, name: "x"})
	w.handle(rawInotify{wd: 77, mask: unix.IN_IGNORED})
	if g := w.Coverage().Gaps; len(g) != 0 {
		t.Fatalf("gaps %+v", g)
	}
	if w.state.removed[77] {
		t.Fatal("IN_IGNORED ends a removed watch's story")
	}
	w.handle(rawInotify{wd: 77, mask: unix.IN_MODIFY, name: "x"})
	if !hasGap(w, GapRead, "") {
		t.Fatal("after IN_IGNORED the watch is unknown")
	}
}

func TestAReadThatEndsInsideAnEventIsAnError(t *testing.T) {
	event := make([]byte, unix.SizeofInotifyEvent)
	if got, err := parseInotify(event); err != nil || len(got) != 1 {
		t.Fatalf("%v, %v", got, err)
	}
	if _, err := parseInotify(event[:5]); err == nil {
		t.Fatal("a short header decoded")
	}
	event[12] = 16 // a 16-byte name that is not there
	if _, err := parseInotify(event); err == nil {
		t.Fatal("a name past the read decoded")
	}
}

func TestADirectoryThatCannotBeListedIsAGap(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	h := fileHooks{readDir: func(dir string) ([]os.DirEntry, error) {
		if dir == sub {
			return nil, syscall.EACCES
		}
		return os.ReadDir(dir)
	}}
	w, release := held(t, h, root)
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	release()
	w.Stop()
	if !hasGap(w, GapScan, sub) || w.Health() == nil {
		t.Fatalf("Health %v, gaps %+v", w.Health(), w.Coverage().Gaps)
	}
}

func TestAWatchThatFailsForAnotherReasonIsAGap(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	h := fileHooks{addWatch: func(fd int, path string, mask uint32) (int, error) {
		if path == sub {
			return -1, syscall.EACCES
		}
		return syscall.InotifyAddWatch(fd, path, mask)
	}}
	w, release := held(t, h, root)
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	release()
	w.Stop()
	if !hasGap(w, GapScan, sub) || w.Health() == nil {
		t.Fatalf("Health %v, gaps %+v", w.Health(), w.Coverage().Gaps)
	}
}

// With no watch left, a listing is the last thing the witness can do for the
// directory: what it finds still counts.
func TestTheWatchLimitStillListsTheDirectory(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	h := fileHooks{addWatch: func(fd int, path string, mask uint32) (int, error) {
		if path == sub {
			return -1, syscall.ENOSPC
		}
		return syscall.InotifyAddWatch(fd, path, mask)
	}}
	w, release := held(t, h, root)
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "f")
	write(t, f, "x")
	release()
	w.Stop()
	if !saw(w.Wrote(""), FileCreate, f) {
		t.Fatalf("events %+v", w.Wrote(""))
	}
}

func TestCheckRootsSeesAMissingRootByItself(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w, release := held(t, fileHooks{}, root)
	defer release()
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	w.checkRoots()
	if !hasGap(w, GapRoot, root) {
		t.Fatalf("gaps %+v", w.Coverage().Gaps)
	}
}

func TestCoverageIsACopy(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{}, root)
	defer release()
	w.gap(GapScan, "/x", "y")
	c := w.Coverage()
	c.Gaps[0].Path = "/changed"
	if !hasGap(w, GapScan, "/x") {
		t.Fatal("a caller rewrote the witness's gaps")
	}
}
