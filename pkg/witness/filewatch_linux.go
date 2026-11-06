//go:build linux

package witness

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	watchEvents = unix.IN_CREATE | unix.IN_MODIFY | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
		unix.IN_DELETE | unix.IN_CLOSE_WRITE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF
	rootMask = watchEvents | unix.IN_ONLYDIR
	// A subdirectory is never reached through a symlink: following one would
	// watch something outside the root under a path inside it.
	dirMask = rootMask | unix.IN_DONT_FOLLOW
)

// inotifyState is the reader's. Nothing else touches it once it runs.
type inotifyState struct {
	fd       int
	wake     [2]int              // a pipe; a byte on it means stop
	wds      map[int32]string    // watch descriptor to directory
	rootWds  map[int32]bool      // the watches of the roots
	removed  map[int32]bool      // removed by us; queued events are moot
	dirty    map[string]bool     // files written since their last close
	moves    map[uint32]*moveOut // directories renamed, other side unseen
	rootInfo map[string]os.FileInfo
}

// moveOut is a directory that left its place. drains counts the times the
// queue has run empty since, so a pair the reader caught halfway is not taken
// for a move out of the root.
type moveOut struct {
	path   string
	drains int
}

func (w *FileWatch) addWatch(path string, mask uint32) (int, error) {
	if w.hooks.addWatch != nil {
		return w.hooks.addWatch(w.state.fd, path, mask)
	}
	return unix.InotifyAddWatch(w.state.fd, path, mask)
}

func (w *FileWatch) start() error {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	s := &inotifyState{
		fd: fd, wds: map[int32]string{}, rootWds: map[int32]bool{}, removed: map[int32]bool{},
		dirty: map[string]bool{}, moves: map[uint32]*moveOut{}, rootInfo: map[string]os.FileInfo{},
	}
	w.state = s
	if err := unix.Pipe2(s.wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return fmt.Errorf("pipe: %w", err)
	}
	for _, root := range w.roots {
		info, statErr := os.Stat(root)
		wd, err := w.addWatch(root, rootMask)
		if err == nil {
			err = statErr
		}
		if err != nil {
			s.close()
			return fmt.Errorf("watch %s: %w", root, err)
		}
		s.wds[int32(wd)], s.rootWds[int32(wd)], s.rootInfo[root] = root, true, info
		w.setWatches()
		w.scan(root, false)
	}
	w.stop = func() {
		for {
			if _, err := unix.Write(s.wake[1], []byte{0}); err != unix.EINTR {
				return
			}
		}
	}
	go w.read()
	return nil
}

func (s *inotifyState) close() {
	unix.Close(s.fd)
	unix.Close(s.wake[0])
	unix.Close(s.wake[1])
}

func (w *FileWatch) setWatches() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coverage.Watches = len(w.state.wds)
}

// read is the reader goroutine: wait, drain, repeat; on stop, drain once more.
// A change made before Stop was called is in the queue by the time the system
// call that made it returned, so a read that finds the queue empty after the
// stop byte has seen them all.
func (w *FileWatch) read() {
	defer close(w.done)
	s := w.state
	defer s.close()
	if w.hooks.hold != nil {
		<-w.hooks.hold
	}
	buf := make([]byte, 64*1024)
	fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}, {Fd: int32(s.wake[0]), Events: unix.POLLIN}}
	for {
		// An unsettled rename needs one more drain even if the queue stays
		// quiet: see settleMoves.
		timeout := -1
		if len(s.moves) != 0 {
			timeout = 5
		}
		if _, err := unix.Poll(fds, timeout); err != nil && err != unix.EINTR {
			w.gap(GapRead, "", fmt.Sprintf("poll: %v", err))
			w.checkRoots()
			return
		}
		stopping := fds[1].Revents != 0
		if !w.drain(buf) || stopping {
			w.checkRoots()
			return
		}
	}
}

// drain reads until the queue is empty. It reports false when the queue cannot
// be read at all.
func (w *FileWatch) drain(buf []byte) bool {
	s := w.state
	for {
		at := time.Now()
		n, err := unix.Read(s.fd, buf)
		switch {
		case err == unix.EINTR:
			continue
		case err == unix.EAGAIN:
			w.mu.Lock()
			w.lastEmpty = at
			w.mu.Unlock()
			w.settleMoves()
			return true
		case err != nil:
			w.gap(GapRead, "", fmt.Sprintf("read: %v", err))
			return false
		case n == 0:
			w.gap(GapRead, "", "read: end of queue")
			return false
		}
		events, err := parseInotify(buf[:n])
		for _, e := range events {
			w.handle(e)
		}
		if err != nil {
			w.gap(GapRead, "", err.Error())
		}
	}
}

type rawInotify struct {
	wd     int32
	mask   uint32
	cookie uint32
	name   string
}

// parseInotify decodes a read's worth of events, and says so if it ended
// inside one.
func parseInotify(b []byte) ([]rawInotify, error) {
	var out []rawInotify
	for len(b) > 0 {
		if len(b) < unix.SizeofInotifyEvent {
			return out, fmt.Errorf("inotify: %d stray bytes after an event", len(b))
		}
		e := rawInotify{
			wd:     int32(binary.NativeEndian.Uint32(b[0:])),
			mask:   binary.NativeEndian.Uint32(b[4:]),
			cookie: binary.NativeEndian.Uint32(b[8:]),
		}
		l := int(binary.NativeEndian.Uint32(b[12:]))
		b = b[unix.SizeofInotifyEvent:]
		if l > len(b) {
			return out, fmt.Errorf("inotify: an event's name runs %d bytes past the read", l-len(b))
		}
		name := b[:l]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		e.name = string(name)
		b = b[l:]
		out = append(out, e)
	}
	return out, nil
}

// handle turns one kernel event into a record, and keeps the watches in step
// with the tree.
//
//subpoena:enforcement_point
func (w *FileWatch) handle(e rawInotify) {
	s := w.state
	if e.mask&unix.IN_Q_OVERFLOW != 0 {
		w.mu.Lock()
		w.coverage.Overflow++ //subpoena:enforcement
		w.mu.Unlock()
		w.gap(GapOverflow, "", "the kernel's event queue filled; events under every root were lost") //subpoena:enforcement
		return
	}
	dir, known := s.wds[e.wd]
	root := s.rootWds[e.wd]
	if !known {
		if e.mask&unix.IN_IGNORED != 0 {
			delete(s.removed, e.wd)
		} else if !s.removed[e.wd] {
			w.gap(GapRead, "", fmt.Sprintf("an event from unknown watch %d (mask %#x)", e.wd, e.mask)) //subpoena:enforcement
		}
		return
	}
	switch {
	case e.mask&unix.IN_UNMOUNT != 0:
		w.gap(GapRoot, dir, "the filesystem was unmounted") //subpoena:enforcement
		return
	case e.mask&unix.IN_IGNORED != 0:
		delete(s.wds, e.wd)
		w.setWatches()
		if root {
			w.gap(GapRoot, dir, "the kernel dropped the root's watch") //subpoena:enforcement
		}
		return
	case e.mask&unix.IN_DELETE_SELF != 0:
		if root {
			w.gap(GapRoot, dir, "the root was deleted") //subpoena:enforcement
		}
		return
	case e.mask&unix.IN_MOVE_SELF != 0:
		if root {
			w.gap(GapRoot, dir, "the root was moved") //subpoena:enforcement
		}
		return
	}
	path := filepath.Join(dir, e.name)
	isDir := e.mask&unix.IN_ISDIR != 0
	ev := FileEvent{Path: path, IsDir: isDir, Source: SourceInotify}
	switch {
	case e.mask&unix.IN_CREATE != 0:
		ev.Op = FileCreate
		w.record(ev)
		if isDir {
			w.scan(path, true)
		} else {
			s.dirty[path] = true
		}
	case e.mask&unix.IN_MODIFY != 0:
		ev.Op = FileWrite
		w.record(ev)
		s.dirty[path] = true
	case e.mask&unix.IN_CLOSE_WRITE != 0:
		if !s.dirty[path] {
			w.mu.Lock()
			w.silent[path] = true
			w.mu.Unlock()
		}
		delete(s.dirty, path)
	case e.mask&unix.IN_DELETE != 0:
		ev.Op = FileUnlink
		w.record(ev)
		delete(s.dirty, path)
	case e.mask&unix.IN_MOVED_FROM != 0:
		ev.Op, ev.Rename, ev.Cookie = FileRename, RenameFrom, e.cookie
		w.record(ev)
		delete(s.dirty, path)
		if isDir {
			s.moves[e.cookie] = &moveOut{path: path}
		}
	case e.mask&unix.IN_MOVED_TO != 0:
		ev.Op, ev.Rename, ev.Cookie = FileRename, RenameTo, e.cookie
		w.record(ev)
		delete(s.moves, e.cookie)
		if isDir {
			w.scan(path, true)
		}
	}
}

// settleMoves runs when the queue is empty. A directory renamed one drain ago
// whose other side never came has left the watched tree, so its watches come
// off: what happens to it now happens outside the root. A rename's two events
// are queued together, so one full drain is time enough for the second.
func (w *FileWatch) settleMoves() {
	s := w.state
	for cookie, m := range s.moves {
		m.drains++
		if m.drains < 2 {
			continue
		}
		delete(s.moves, cookie)
		for wd, dir := range s.wds {
			if pathWithin(dir, m.path) {
				s.removed[int32(wd)] = true
				delete(s.wds, wd)
				unix.InotifyRmWatch(s.fd, uint32(wd))
			}
		}
		w.setWatches()
	}
}

// scan watches dir and everything below it. The watch goes on first and the
// listing comes after, so a change is either in the listing or in the queue;
// both is fine, and neither cannot happen. report is true for a directory new
// to the capture: what it holds is new too, and is recorded as found by the
// scan. A file created and already removed by the time the listing runs is in
// neither; see FileCoverage.MaxWatchLag.
//
//subpoena:enforcement_point
func (w *FileWatch) scan(dir string, report bool) {
	s := w.state
	if !s.isRootPath(dir) {
		wd, err := w.addWatch(dir, dirMask)
		switch {
		case errors.Is(err, unix.ENOSPC):
			w.gap(GapWatchLimit, dir, "no watch: fs.inotify.max_user_watches is used up") //subpoena:enforcement
		case err != nil:
			w.gap(GapScan, dir, fmt.Sprintf("no watch, so nothing in it was seen: %v", err)) //subpoena:enforcement
			return
		default:
			if old, ok := s.wds[int32(wd)]; ok && old == dir {
				return // watched and listed already
			}
			s.wds[int32(wd)] = dir
			delete(s.removed, int32(wd))
			w.setWatches()
			if report {
				w.noteLag(dir)
			}
		}
	}
	entries, err := w.hooks.readDir(dir)
	if err != nil {
		w.gap(GapScan, dir, fmt.Sprintf("could not list it: %v", err)) //subpoena:enforcement
		return
	}
	for _, d := range entries {
		path := filepath.Join(dir, d.Name())
		if report {
			w.record(FileEvent{Op: FileCreate, Path: path, IsDir: d.IsDir(), Source: SourceScan})
		}
		if d.IsDir() {
			w.scan(path, report)
		}
	}
}

func (s *inotifyState) isRootPath(dir string) bool {
	_, ok := s.rootInfo[dir]
	return ok
}

// noteLag bounds how long dir went unwatched. Its watch has just landed. It
// cannot have appeared before its birth time, nor, since this event was not
// in a queue seen empty, before lastEmpty; the later of the two is the
// tighter bound. A directory moved in has an old birth time, and an idle
// reader an old lastEmpty, so for one of those the bound is loose, never low.
//
//subpoena:enforcement_point
func (w *FileWatch) noteLag(dir string) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coverage.NewDirs++
	from := w.lastEmpty
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, dir, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &st); err == nil && st.Mask&unix.STATX_BTIME != 0 {
		if born := time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)); born.After(from) {
			from = born
		}
	}
	if lag := now.Sub(from); lag > w.coverage.MaxWatchLag {
		w.coverage.MaxWatchLag = lag //subpoena:enforcement
	}
}

// checkRoots notices what inotify on a root cannot: a directory above it
// moved, and the path now means something else, or nothing.
//
//subpoena:enforcement_point
func (w *FileWatch) checkRoots() {
	for root, was := range w.state.rootInfo {
		now, err := os.Stat(root)
		switch {
		case err != nil:
			w.gap(GapRoot, root, strings.TrimPrefix(err.Error(), "stat ")) //subpoena:enforcement
		case !os.SameFile(was, now):
			w.gap(GapRoot, root, "the path is now another directory") //subpoena:enforcement
		}
	}
}
