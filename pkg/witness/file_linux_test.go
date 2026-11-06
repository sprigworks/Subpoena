//subpoena:spec_derived
//subpoena:pure_logic

// The file witness's tests that need Linux's own calls, kept apart so the
// package's tests still build elsewhere.
package witness

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestTheWatchLimitFailsHealth(t *testing.T) {
	root := t.TempDir()
	calls := 0
	h := fileHooks{addWatch: func(fd int, path string, mask uint32) (int, error) {
		calls++
		if calls > 1 { // the root gets its watch; the next directory does not
			return -1, syscall.ENOSPC
		}
		return syscall.InotifyAddWatch(fd, path, mask)
	}}
	w, release := held(t, h, root)
	release()
	sub := filepath.Join(root, "d")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	found := filepath.Join(sub, "found")
	write(t, found, "x")
	waitFor(t, func() bool { return hasGap(w, GapWatchLimit, sub) })
	w.Stop()
	if err := w.Health(); err == nil || !strings.Contains(err.Error(), string(GapWatchLimit)) {
		t.Fatalf("Health = %v", err)
	}
}

func TestTheWatchLimitAtStartFailsHealth(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "d")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := fileHooks{addWatch: func(fd int, path string, mask uint32) (int, error) {
		calls++
		if calls > 1 {
			return -1, syscall.ENOSPC
		}
		return syscall.InotifyAddWatch(fd, path, mask)
	}}
	w, release := held(t, h, root)
	release()
	w.Stop()
	if !hasGap(w, GapWatchLimit, sub) || w.Health() == nil {
		t.Fatalf("Health %v, gaps %+v", w.Health(), w.Coverage().Gaps)
	}
}

// aioWrite overwrites the start of path by Linux native AIO, which queues no
// inotify event, and hands back the descriptor still open.
func aioWrite(t *testing.T, path string) int {
	t.Helper()
	var ctx uintptr
	if _, _, e := unix.Syscall(unix.SYS_IO_SETUP, 8, uintptr(unsafe.Pointer(&ctx)), 0); e != 0 {
		t.Skipf("io_setup: %v", e)
	}
	t.Cleanup(func() { unix.Syscall(unix.SYS_IO_DESTROY, ctx, 0, 0) })
	fd, err := unix.Open(path, unix.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := []byte("ZZZZ")
	// struct iocb: data, key+rw_flags, opcode+reqprio, fildes, buf, nbytes, offset, ...
	var cb struct {
		data         uint64
		key, rwFlags uint32
		opcode, prio int16
		fildes       uint32
		buf, n       uint64
		offset       int64
		reserved     uint64
		flags, resfd uint32
	}
	cb.opcode, cb.fildes = 1, uint32(fd) // IOCB_CMD_PWRITE
	cb.buf, cb.n = uint64(uintptr(unsafe.Pointer(&buf[0]))), uint64(len(buf))
	list := [1]uintptr{uintptr(unsafe.Pointer(&cb))}
	if n, _, e := unix.Syscall(unix.SYS_IO_SUBMIT, ctx, 1, uintptr(unsafe.Pointer(&list))); e != 0 || n != 1 {
		t.Skipf("io_submit: %d %v", n, e)
	}
	var ev [4]uint64
	if n, _, e := unix.Syscall6(unix.SYS_IO_GETEVENTS, ctx, 1, 1, uintptr(unsafe.Pointer(&ev)), 0, 0); e != 0 || n != 1 {
		t.Fatalf("io_getevents: %d %v", n, e)
	}
	runtime.KeepAlive(buf)
	return fd
}

func statEvent(w *FileWatch, op FileOp, path string) bool {
	return slices.ContainsFunc(w.Wrote(""), func(e FileEvent) bool {
		return e.Op == op && e.Path == path && e.Source == SourceStat
	})
}

// H4: native AIO queues nothing. The check at Stop is what is left: a write
// moved the file's timestamps, with the descriptor closed or still open.
func TestANativeAIOWriteIsFoundByTheCheckAtStop(t *testing.T) {
	for _, tc := range []struct {
		name         string
		close, reset bool
	}{{"closed", true, false}, {"held open past Stop", false, false}, {"mtime put back", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			f := filepath.Join(root, "f")
			write(t, f, "original content")
			was, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			w := watch(t, root)
			fd := aioWrite(t, f)
			defer unix.Close(fd)
			if tc.reset {
				if err := os.Chtimes(f, was.ModTime(), was.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			if tc.close {
				unix.Close(fd)
			}
			w.Stop()
			if !statEvent(w, FileWrite, f) {
				t.Fatalf("events %+v", w.Wrote(""))
			}
			if tc.close && !slices.Contains(w.SilentCloses(), f) {
				t.Fatalf("silent %v", w.SilentCloses())
			}
			if w.Coverage().Stat != 1 {
				t.Fatalf("%+v", w.Coverage())
			}
		})
	}
}

// A file left alone gives nothing, however it was opened.
func TestTheCheckAtStopIsQuietAboutWhatDidNotChange(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "f")
	write(t, f, "x")
	w := watch(t, root)
	file, err := os.OpenFile(f, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := os.ReadFile(f); err != nil {
		t.Fatal(err)
	}
	w.Stop()
	if got := w.Wrote(""); len(got) != 0 {
		t.Fatalf("events %+v", got)
	}
	if err := w.Health(); err != nil {
		t.Fatal(err)
	}
}

// The check is not fooled by what the events already explain, and finds what
// they do not: a file gone or arrived with no event at all.
func TestTheCheckAtStopFindsWhatNoEventNamed(t *testing.T) {
	root := t.TempDir()
	gone, kept, arrived := filepath.Join(root, "gone"), filepath.Join(root, "kept"), filepath.Join(root, "arrived")
	write(t, gone, "x")
	write(t, kept, "x")
	w, release := held(t, fileHooks{}, root)
	write(t, kept, "y") // named by an event, so the check adds nothing
	// With the reader held the queue is thrown away, as if it were never told.
	buf := make([]byte, 1<<16)
	for {
		if _, err := unix.Read(w.state.fd, buf); err != nil {
			break
		}
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	write(t, arrived, "x")
	for {
		if _, err := unix.Read(w.state.fd, buf); err != nil {
			break
		}
	}
	release()
	w.Stop()
	if !statEvent(w, FileUnlink, gone) || !statEvent(w, FileCreate, arrived) || !statEvent(w, FileWrite, kept) {
		t.Fatalf("events %+v", w.Wrote(""))
	}
}

// M1: a hard link is one file with two names, and the kernel names the one
// written through.
func TestAWriteThroughAHardLinkIsFoundUnderTheOtherName(t *testing.T) {
	for _, tc := range []struct {
		name string
		link func(root, out string) string
	}{
		{"inside the root", func(root, _ string) string { return filepath.Join(root, "b", "alias") }},
		{"outside the root", func(_, out string) string { return filepath.Join(out, "alias") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, out := t.TempDir(), t.TempDir()
			for _, d := range []string{"a", "b"} {
				if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			secret := filepath.Join(root, "a", "secret")
			write(t, secret, "orig")
			alias := tc.link(root, out)
			if err := os.Link(secret, alias); err != nil {
				t.Fatal(err)
			}
			w := watch(t, root)
			f, err := os.OpenFile(alias, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("hacked")
			f.Close()
			w.Stop()
			if !statEvent(w, FileWrite, secret) {
				t.Fatalf("events %+v", w.Wrote(""))
			}
		})
	}
}

// M1: a path through a symlink is spelled another way, or leaves the root.
func TestAPathCrossingASymlinkIsNotCovered(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(filepath.Join(root, "releases", "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "releases", "1", "conf"), "x")
	write(t, filepath.Join(dir, "out"), "x")
	if err := os.Symlink(filepath.Join("releases", "1"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "out"), filepath.Join(root, "conf")); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	made := filepath.Join(root, "made")
	if err := os.Symlink("releases", made); err != nil { // one made during the capture
		t.Fatal(err)
	}
	w.Stop()
	for path, want := range map[string]bool{
		filepath.Join(root, "current", "conf"):       false,
		filepath.Join(root, "conf"):                  false,
		filepath.Join(made, "1", "conf"):             false,
		filepath.Join(root, "releases", "1", "conf"): true,
		filepath.Join(root, "releases"):              true,
		root:                                         true,
		filepath.Join(root, "current-not-a-link"):    true,
	} {
		if got := w.Covers(path); got != want {
			t.Errorf("Covers(%s) = %v", path, got)
		}
	}
	var b strings.Builder
	if err := w.WriteLog(&b); err != nil {
		t.Fatal(err)
	}
	log, err := ReadLog(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if log.Covers(filepath.Join(root, "current", "conf")) || !log.Covers(filepath.Join(root, "releases")) {
		t.Fatalf("the log must keep the symlinks: %s", b.String())
	}
}

// M1: the kernel keeps one watch per directory, so the last spelling would be
// the only one any event could carry.
func TestOneDirectoryUnderTwoSpellingsIsRefused(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(filepath.Join(data, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	same, sub := filepath.Join(dir, "same"), filepath.Join(dir, "sub")
	if err := os.Symlink("data", same); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("data", "sub"), sub); err != nil {
		t.Fatal(err)
	}
	for _, roots := range [][]string{{data, same}, {same, data}, {data, sub}, {sub, data}} {
		if w, err := NewFileWatch(roots...); err == nil {
			w.Stop()
			t.Errorf("%v was not refused", roots)
		}
	}
	w, err := NewFileWatch(data, filepath.Join(data, "sub")) // nested, one spelling: fine
	if err != nil {
		t.Fatal(err)
	}
	w.Stop()
}

// M3: a new directory at a moved-out directory's name is in the tree. The
// pending move must take only the watches of what left.
func TestADirectoryMovedOutLeavesItsReplacementWatched(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	spool := filepath.Join(root, "spool")
	if err := os.Mkdir(spool, 0o755); err != nil {
		t.Fatal(err)
	}
	w := watch(t, root)
	if err := os.Rename(spool, filepath.Join(out, "spool")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(spool, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the move settles
	after := filepath.Join(spool, "after")
	write(t, after, "x")
	time.Sleep(20 * time.Millisecond)
	moved := filepath.Join(out, "spool", "unwatched")
	write(t, moved, "x") // what left is outside now
	w.Stop()
	if !saw(w.Wrote(""), FileCreate, after) {
		t.Fatalf("events %+v", w.Wrote(""))
	}
	if err := w.Health(); err != nil {
		t.Fatal(err)
	}
	if got := w.Coverage().Watches; got != 2 {
		t.Fatalf("watches = %d: the old directory's must come off", got)
	}
}

// The same with RENAME_EXCHANGE, whichever side the call names first: the
// kernel's two moves arrive in either order.
func TestAnExchangeAcrossTheEdgeLeavesTheNewDirectoryWatched(t *testing.T) {
	for _, inFirst := range []bool{true, false} {
		root, out := t.TempDir(), t.TempDir()
		in, there := filepath.Join(root, "spool"), filepath.Join(out, "spool")
		for _, d := range []string{in, there} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		w := watch(t, root)
		from, to := in, there
		if !inFirst {
			from, to = there, in
		}
		if err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_EXCHANGE); err != nil {
			t.Skipf("renameat2: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
		after := filepath.Join(in, "after")
		write(t, after, "x")
		time.Sleep(20 * time.Millisecond)
		w.Stop()
		if !saw(w.Wrote(""), FileCreate, after) {
			t.Fatalf("inFirst=%v: events %+v", inFirst, w.Wrote(""))
		}
	}
}

// L1: a writer that never stops must not hold Stop. The hook is a queue that
// never empties, which is what enough writers look like.
func TestStopReturnsWithAGapWhileWritersRun(t *testing.T) {
	root := t.TempDir()
	event := make([]byte, unix.SizeofInotifyEvent+16)
	h := fileHooks{maxQueue: 1000, maxEvents: 100}
	var wd int32
	h.read = func(_ int, b []byte) (int, error) {
		binary.NativeEndian.PutUint32(event[0:], uint32(wd))
		binary.NativeEndian.PutUint32(event[4:], unix.IN_MODIFY)
		binary.NativeEndian.PutUint32(event[12:], 16)
		copy(event[unix.SizeofInotifyEvent:], "f")
		return copy(b, event), nil
	}
	w, release := held(t, h, root)
	wd = wdOf(t, w, root)
	release()
	done := make(chan error, 1)
	go func() { done <- w.Stop() }()
	select {
	case err := <-done:
		if err == nil || !hasGap(w, GapBound, "") {
			t.Fatalf("Stop = %v, gaps %+v", err, w.Coverage().Gaps)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop is still reading")
	}
	if got := len(w.Wrote("")); got != 100 {
		t.Fatalf("kept %d events", got)
	}
	if c := w.Coverage(); c.Events <= 100 {
		t.Fatalf("%+v", c)
	}
}

// Every event made before Stop is read, up to what the queue can hold.
func TestStopStillReadsAFullQueue(t *testing.T) {
	root := t.TempDir()
	w, release := held(t, fileHooks{maxQueue: 5000}, root)
	a, err := os.Create(filepath.Join(root, "a"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	c, err := os.Create(filepath.Join(root, "c"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2000; i++ { // turn about, or the kernel merges them
		a.WriteString("x")
		c.WriteString("x")
	}
	w.stop() // the stop byte comes before the first read
	release()
	w.Stop()
	if err := w.Health(); err != nil {
		t.Fatal(err)
	}
	if got := len(w.Wrote("")); got != 4002 {
		t.Fatalf("read %d of 4002", got)
	}
}

// L3: JSON cannot carry this name, so the log must not read healthy.
func TestANameThatIsNotUTF8MakesTheLogUnhealthy(t *testing.T) {
	root := t.TempDir()
	w := watch(t, root)
	write(t, filepath.Join(root, "caf\xe9"), "x")
	w.Stop()
	var b strings.Builder
	if err := w.WriteLog(&b); err == nil {
		t.Fatal("WriteLog must say so")
	}
	log, err := ReadLog(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Health(); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("Health = %v", err)
	}
}

func TestAWitnessWithRootsSaysSo(t *testing.T) {
	root := t.TempDir()
	w := watch(t, root)
	w.Stop()
	if got := w.Roots(); !slices.Equal(got, []string{root}) {
		t.Fatalf("Roots = %v", got)
	}
}
