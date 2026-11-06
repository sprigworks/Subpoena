// Command subpoena-witness runs the kernel-side process witness
// (pkg/witness/execbpf) and writes one JSON line per exec, for shipping to a
// log store (tier 2 sends them to Loki). Needs root, cgroup v2 and BTF.
//
//	subpoena-witness [-cgroup-root dir] [-all] [-deliveries] [-out file] [-ready file]
//	subpoena-witness -check-ready file   # exit 0 once the witness is attached
//	subpoena-witness -file-root dir [-file-root dir ...] [-out file] [-ready file]
//	subpoena-witness db -engine postgres|mysql -upstream host:port [-listen addr:port] [-out file] [-ready file]
//
// With -file-root it runs the tier-1 file witness (witness.FileWatch) in place
// of the eBPF one, and needs no privilege. It writes the start record once
// attached, before -ready, and the rest when told to stop (SIGTERM or SIGINT),
// so a witness killed outright leaves a window that never closed, which proves
// nothing, as it should, even in a file an earlier run left healthy. An -out or
// -ready inside a watched root is refused: the witness would see its own file.
//
// The db form runs the database witness (pkg/witness/dbproxy) instead, for a suite
// in another language: point the application at the address it prints and writes
// to -ready, stop it with SIGTERM, then read -out. It needs no privileges.
//
// By default only execs inside a session cgroup are written; -all writes every
// exec on the machine, which an argument-based witness query needs. The line
// format is witness.Line (schema: docs/witness-event.schema.json). A "start"
// record (witness.Record) opens the file's capture window once the program is
// attached, and a "stop" record closes it with the capture's health: whether
// kernel events were lost, or a read or write failed.
//
// -deliveries also runs pkg/witness/netbpf and writes one witness.DeliveryLine
// per send from a session cgroup, -all or not: a broker's write to a subscriber
// on a socket it accepted, or a send that names its destination. The start record
// lists the captures that ran, and a reader refuses a delivery claim on a file
// that does not name this one.
//
// Stopping the eBPF or file witness does not wait on a stalled output: if a line can make no progress for
// stallLimit once told to stop, the capture is unhealthy and the process exits
// non-zero, most likely with no stop record, which proves nothing, as it should.
// Told to stop while -out is a FIFO with no reader, it exits non-zero with no start
// record.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness"
	"github.com/sprigworks/subpoena/pkg/witness/execbpf"
	"github.com/sprigworks/subpoena/pkg/witness/netbpf"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "db" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		if err := runDB(os.Args[2:], sig); err != nil {
			fmt.Fprintln(os.Stderr, "subpoena-witness:", err)
			os.Exit(1)
		}
		return
	}
	root := flag.String("cgroup-root", "", "parent of the session cgroups (default $SUBPOENA_CGROUP_ROOT or /sys/fs/cgroup/subpoena)")
	all := flag.Bool("all", false, "write every exec, not only those in a session cgroup")
	deliveries := flag.Bool("deliveries", false, "also write every send from a session cgroup (needs the network witness's programs)")
	out := flag.String("out", "-", "file to append JSON lines to (- for stdout)")
	ready := flag.String("ready", "", "file to create once the program is attached")
	var fileRoots []string
	flag.Func("file-root", "directory to watch with the file witness, in place of the eBPF witness (repeatable)", func(dir string) error {
		fileRoots = append(fileRoots, dir)
		return nil
	})
	checkReady := flag.String("check-ready", "", "exit 0 if this ready file exists, 1 otherwise (for container health checks)")
	flag.Parse()

	if *checkReady != "" {
		if _, err := os.Stat(*checkReady); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(fileRoots) != 0 {
		if *deliveries {
			fmt.Fprintln(os.Stderr, "subpoena-witness: -deliveries needs the eBPF witness and cannot be combined with -file-root")
			os.Exit(2)
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		if err := runFiles(fileRoots, *out, *ready, sig); err != nil {
			fmt.Fprintln(os.Stderr, "subpoena-witness:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*root, *all, *deliveries, *out, *ready); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-witness:", err)
		os.Exit(1)
	}
}

// runFiles runs the file witness until stop delivers, then writes the capture.
// Its output can stall as the eBPF path's can, and the same guard ends the wait.
// An unhealthy capture is written and returned: the file says so, and so does
// the exit status. The start record is written before anything is told the
// witness is ready: a file that cannot be written is refused then, and a
// witness killed later leaves an open window, not whatever was there before.
//
//subpoena:enforcement_point
func runFiles(roots []string, out, ready string, stop <-chan os.Signal) error {
	if err := ownFileWatched(roots, out, ready); err != nil {
		return err //subpoena:enforcement
	}
	w, err := witness.NewFileWatch(roots...)
	if err != nil {
		return err
	}
	var dst io.Writer = os.Stdout
	if out != "-" {
		f, err := openOut(out, stop)
		if err != nil {
			w.Stop()
			return err
		}
		defer f.Close()
		dst = f
	}
	guard := newStallGuard(dst, stallLimit)
	if err := w.WriteStart(guard); err != nil {
		w.Stop()
		return err
	}
	if ready != "" {
		if err := os.WriteFile(ready, []byte("attached\n"), 0o644); err != nil {
			w.Stop()
			return err
		}
		defer os.Remove(ready)
	}
	fmt.Fprintln(os.Stderr, "subpoena-witness: attached")
	<-stop
	guard.stopping() //subpoena:enforcement
	stopErr := w.Stop()
	return errors.Join(stopErr, w.WriteEnd(guard))
}

// openOut opens the output file. Opening a FIFO waits for its reader, before the
// stall guard exists, so stop must end that wait: nothing is written and nothing
// is told the witness is ready. The open left behind ends with the process.
//
//subpoena:enforcement_point
func openOut(out string, stop <-chan os.Signal) (*os.File, error) {
	open := func() (*os.File, error) {
		return os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
	if st, err := os.Stat(out); err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		return open()
	}
	type opened struct {
		f   *os.File
		err error
	}
	done := make(chan opened, 1)
	go func() {
		f, err := open()
		done <- opened{f, err}
	}()
	select {
	case r := <-done:
		return r.f, r.err
	case <-stop:
	}
	return nil, fmt.Errorf("told to stop while waiting to open %s: a FIFO with no reader", out) //subpoena:enforcement
}

// ownFileWatched refuses an output or ready file under a watched root, whatever
// the spelling, a link to a file not made yet among them: its own lines would read
// as changes there, and fail a claim about the root.
//
//subpoena:enforcement_point
func ownFileWatched(roots []string, files ...string) error {
	for _, file := range files {
		if file == "" || file == "-" {
			continue
		}
		abs, err := filepath.Abs(file)
		if err != nil {
			return err
		}
		abs = followLinks(abs)
		for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
			for _, root := range roots {
				if sameDir(dir, root) {
					return fmt.Errorf("%s is under the watched root %s, so the witness would see its own file: put it elsewhere", file, root) //subpoena:enforcement
				}
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
	}
	return nil
}

// followLinks is where the open of abs lands. EvalSymlinks refuses a link to a file
// not made yet, and the open follows one and makes the file, so links are read one
// at a time. Past the kernel's own limit the open fails anyway.
func followLinks(abs string) string {
	for range maxLinks {
		if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
			abs = filepath.Join(dir, filepath.Base(abs))
		}
		link, err := os.Readlink(abs)
		if err != nil {
			break
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(abs), link)
		}
		abs = link
	}
	return abs
}

// maxLinks is above the 40 links Linux follows in one path.
const maxLinks = 64

func sameDir(a, b string) bool {
	x, err := os.Stat(a)
	if err != nil {
		return false
	}
	y, err := os.Stat(b)
	return err == nil && os.SameFile(x, y)
}

// startRecord opens the capture window and says which hooks are behind it.
func startRecord(deliveries bool) witness.Record {
	captures := []string{witness.CaptureExec}
	if deliveries {
		captures = append(captures, witness.CaptureDelivery)
	}
	return witness.Record{Time: time.Now().UTC(), Record: witness.RecordStart, Captures: captures}
}

func run(root string, all, deliveries bool, out, ready string) error {
	var dst io.Writer = os.Stdout
	if out != "-" {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		f, err := openOut(out, stop)
		signal.Stop(stop)
		if err != nil {
			return err
		}
		defer f.Close()
		dst = f
	}
	guard := newStallGuard(dst, stallLimit)
	var mu sync.Mutex
	enc := json.NewEncoder(guard)
	var writeErr error
	w := execbpf.New(execbpf.Config{
		CgroupRoot: root,
		NoRetain:   true,
		OnEvent: func(e execbpf.Event) {
			if e.Kind != execbpf.KindExec || (!all && e.Attribution != witness.ByCgroup) {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			args := e.Args
			if args == nil {
				args = []string{} // the schema requires an array, never null
			}
			if err := enc.Encode(witness.Line{
				Time: e.Time.UTC(), PID: e.PID, PPID: e.PPID, HostPID: e.HostPID,
				Comm: e.Comm, Exe: e.Exe, Command: strings.Join(args, " "), Args: args,
				CgroupID: e.CgroupID, Cgroup: e.Cgroup, TraceID: e.TraceID, Attribution: string(e.Attribution),
			}); err != nil && writeErr == nil {
				writeErr = err
			}
		},
	})
	var net *netbpf.Witness
	if deliveries {
		net = netbpf.New(netbpf.Config{
			CgroupRoot: root,
			NoRetain:   true,
			OnEvent: func(e netbpf.Event) {
				if e.Attribution != witness.ByCgroup || (e.Op != witness.OpDeliver && e.Op != witness.OpSendmsg) {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if err := enc.Encode(e.DeliveryLine()); err != nil && writeErr == nil {
					writeErr = err
				}
			},
		})
	}
	// stopAll ends every capture. NoRetain leaves Health failing by design, so
	// each Stop's own error is the verdict.
	stopAll := func() error {
		err := w.Stop()
		if net != nil {
			err = errors.Join(err, net.Stop())
		}
		return err
	}
	// The start and stop records bound the capture. A reader trusts an
	// absence only inside a window closed by a healthy stop, so a witness
	// killed before it could write one leaves a file that proves nothing.
	// mu is held from Start until the start record is written: Start hands
	// events to a reader goroutine, and an exec line written before the
	// start record would read as outside the window and fail a healthy run.
	mu.Lock()
	if err := w.Start(); err != nil {
		mu.Unlock()
		return err
	}
	if net != nil {
		if err := net.Start(); err != nil {
			mu.Unlock()
			w.Stop()
			return err
		}
	}
	err := enc.Encode(startRecord(net != nil))
	mu.Unlock()
	if err != nil {
		stopAll()
		return err
	}
	if ready != "" {
		if err := os.WriteFile(ready, []byte("attached\n"), 0o644); err != nil {
			stopAll()
			return err
		}
		defer os.Remove(ready)
	}
	fmt.Fprintln(os.Stderr, "subpoena-witness: attached")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	guard.stopping()
	err = stopAll()
	mu.Lock()
	defer mu.Unlock()
	err = errors.Join(err, writeErr)
	stop := witness.Record{Time: time.Now().UTC(), Record: witness.RecordStop, Healthy: err == nil}
	if err != nil {
		stop.Error = err.Error()
	}
	if net != nil {
		stop.Coverage = net.DeliveryCoverage().String()
	}
	return errors.Join(err, enc.Encode(stop))
}
