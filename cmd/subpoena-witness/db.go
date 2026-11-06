package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/sprigworks/subpoena/pkg/witness/dbproxy"
)

// runDB runs the database witness until stop delivers. Its error is the capture's
// health, as the file's stop record also says.
func runDB(args []string, stop <-chan os.Signal) error {
	fs := flag.NewFlagSet("subpoena-witness db", flag.ContinueOnError)
	engine := fs.String("engine", "", "wire protocol: postgres or mysql")
	upstream := fs.String("upstream", "", "host:port of the real server")
	listen := fs.String("listen", "127.0.0.1:0", "address to listen on")
	out := fs.String("out", "-", "file to write JSON lines to (- for stdout)")
	ready := fs.String("ready", "", "file to write the listening address to, once listening")
	if err := fs.Parse(args); err != nil {
		return err
	}
	addr, err := netip.ParseAddrPort(*listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	var dst io.Writer = os.Stdout
	if *out != "-" {
		// Truncated, not appended: a file holds one capture window.
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		dst = f
	}
	w, err := dbproxy.New(dbproxy.Config{Engine: dbproxy.Engine(*engine), Upstream: *upstream, Listen: addr, Output: dst})
	if err != nil {
		return err
	}
	if *ready != "" {
		if err := os.WriteFile(*ready, []byte(w.Addr().String()+"\n"), 0o644); err != nil {
			w.Stop()
			return err
		}
		defer os.Remove(*ready)
	}
	fmt.Fprintln(os.Stderr, "subpoena-witness: listening on", w.Addr())
	<-stop
	return w.Stop()
}
