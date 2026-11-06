// Command subpoena-witness runs the kernel-side process witness
// (pkg/witness/execbpf) and writes one JSON line per exec, for shipping to a
// log store (tier 2 sends them to Loki). Needs root, cgroup v2 and BTF.
//
//	subpoena-witness [-cgroup-root dir] [-all] [-deliveries] [-out file] [-ready file]
//	subpoena-witness -check-ready file   # exit 0 once the witness is attached
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
// on a socket it accepted, or a send that names its destination.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness"
	"github.com/sprigworks/subpoena/pkg/witness/execbpf"
	"github.com/sprigworks/subpoena/pkg/witness/netbpf"
)

func main() {
	root := flag.String("cgroup-root", "", "parent of the session cgroups (default $SUBPOENA_CGROUP_ROOT or /sys/fs/cgroup/subpoena)")
	all := flag.Bool("all", false, "write every exec, not only those in a session cgroup")
	deliveries := flag.Bool("deliveries", false, "also write every send from a session cgroup (needs the network witness's programs)")
	out := flag.String("out", "-", "file to append JSON lines to (- for stdout)")
	ready := flag.String("ready", "", "file to create once the program is attached")
	checkReady := flag.String("check-ready", "", "exit 0 if this ready file exists, 1 otherwise (for container health checks)")
	flag.Parse()

	if *checkReady != "" {
		if _, err := os.Stat(*checkReady); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := run(*root, *all, *deliveries, *out, *ready); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-witness:", err)
		os.Exit(1)
	}
}

func run(root string, all, deliveries bool, out, ready string) error {
	var dst io.Writer = os.Stdout
	if out != "-" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		dst = f
	}
	var mu sync.Mutex
	enc := json.NewEncoder(dst)
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
	err := enc.Encode(witness.Record{Time: time.Now().UTC(), Record: witness.RecordStart})
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
