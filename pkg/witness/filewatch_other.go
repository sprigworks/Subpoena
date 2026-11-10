//go:build !linux

package witness

import "errors"

type inotifyState struct{}

func (*inotifyState) close() {}

// start has nothing to attach to here: inotify is Linux's.
func (w *FileWatch) start() error { return errors.New("inotify needs Linux") }
