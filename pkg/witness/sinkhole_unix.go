//go:build unix

package witness

import (
	"errors"
	"net"
	"syscall"
)

// drainAccepts accepts and closes every connection already queued on ln,
// without waiting, and says how many there were. The listener's descriptor is
// non-blocking, so accept returns EAGAIN once the queue is empty.
func drainAccepts(ln *net.TCPListener) (int, error) {
	rc, err := ln.SyscallConn()
	if err != nil {
		return 0, err
	}
	n := 0
	var acceptErr error
	err = rc.Control(func(fd uintptr) {
		for {
			nfd, _, err := syscall.Accept(int(fd))
			switch {
			case err == nil:
				syscall.Close(nfd)
				n++
			case errors.Is(err, syscall.ECONNABORTED):
				n++ // completed a handshake, then reset: it still arrived
			case errors.Is(err, syscall.EINTR):
			case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EWOULDBLOCK):
				return
			default:
				acceptErr = err
				return
			}
		}
	})
	if err != nil {
		return n, err
	}
	return n, acceptErr
}
