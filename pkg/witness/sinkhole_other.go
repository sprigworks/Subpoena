//go:build !unix

package witness

import (
	"errors"
	"net"
)

// drainAccepts cannot read the accept queue without blocking here, so the
// capture cannot be shown complete.
func drainAccepts(*net.TCPListener) (int, error) {
	return 0, errors.New("draining the accept queue needs a unix system")
}
