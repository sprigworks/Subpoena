//subpoena:impl_derived
//subpoena:pure_logic

package live

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// recorded returns the address a witness should forward to. Normally that is
// addr. With SUBPOENA_DB_RECORD set to a directory and a name given, it is a tee
// that writes the session's bytes to <dir>/<name>.hex, for the replay tests in
// the parent package: one line per read, "C <hex>" from the client side and
// "S <hex>" from the server.
func recorded(t *testing.T, addr string, name ...string) string {
	dir := os.Getenv("SUBPOENA_DB_RECORD")
	if dir == "" || len(name) == 0 {
		return addr
	}
	f, err := os.Create(filepath.Join(dir, name[0]+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); f.Close() })
	var mu sync.Mutex
	copyLogged := func(dst io.WriteCloser, src io.Reader, tag string) {
		defer dst.Close()
		buf := make([]byte, 1<<20)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				mu.Lock()
				fmt.Fprintf(f, "%s %x\n", tag, buf[:n])
				mu.Unlock()
				dst.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", addr)
			if err != nil {
				c.Close()
				continue
			}
			go copyLogged(up, c, "C")
			go copyLogged(c, up, "S")
		}
	}()
	return ln.Addr().String()
}
