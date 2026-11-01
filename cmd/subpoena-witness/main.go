// Command subpoena-witness runs the kernel-side process witness
// (pkg/witness/execbpf) and writes one JSON line per exec, for shipping to a
// log store (tier 2 sends them to Loki). With -net-out it also runs the
// network witness (pkg/witness/netbpf) and writes one JSON line per outbound
// connection attempt to that file. Needs root, cgroup v2 and BTF.
//
//	subpoena-witness [-cgroup-root dir] [-all] [-out file] [-net-out file] [-ready file]
//	subpoena-witness -check-ready file   # exit 0 once the witness is attached
//
// By default only events inside a session cgroup are written; -all writes
// every exec and attempt on the machine, which an argument-based witness
// query needs. The exec line format is witness.Line (schema:
// docs/witness-event.schema.json), the network line format witness.NetLine
// (docs/witness-network-event.schema.json). In each file a "start" record
// (witness.Record) opens the capture window once its program is attached,
// and a "stop" record closes it with the capture's health: whether kernel
// events were lost, or a read or write failed. The two kinds of line go to
// separate files because a reader of the exec file takes every line that is
// not a record for an exec.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
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
	var o options
	flag.StringVar(&o.root, "cgroup-root", "", "parent of the session cgroups (default $SUBPOENA_CGROUP_ROOT or /sys/fs/cgroup/subpoena)")
	flag.BoolVar(&o.all, "all", false, "write every exec and attempt, not only those in a session cgroup")
	flag.StringVar(&o.out, "out", "-", "file to append exec JSON lines to (- for stdout)")
	flag.StringVar(&o.netOut, "net-out", "", "also run the network witness and append its JSON lines to this file (- for stdout)")
	flag.StringVar(&o.ready, "ready", "", "file to create once every witness is attached")
	checkReady := flag.String("check-ready", "", "exit 0 if this ready file exists, 1 otherwise (for container health checks)")
	flag.Parse()

	if *checkReady != "" {
		if _, err := os.Stat(*checkReady); err != nil {
			os.Exit(1)
		}
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	if err := run(o, kernel, sig); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-witness:", err)
		os.Exit(1)
	}
}

type options struct {
	root, out, netOut, ready string
	all                      bool
}

// capturer is a kernel witness: execbpf's or netbpf's.
type capturer interface {
	Start() error
	Stop() error
}

// witnesses builds the two witnesses, so a test can run the command without
// loading eBPF.
type witnesses struct {
	exec func(root string, on func(execbpf.Event)) capturer
	net  func(root string, on func(netbpf.Event)) capturer
}

var kernel = witnesses{
	exec: func(root string, on func(execbpf.Event)) capturer {
		return execbpf.New(execbpf.Config{CgroupRoot: root, NoRetain: true, OnEvent: on})
	},
	net: func(root string, on func(netbpf.Event)) capturer {
		return netbpf.New(netbpf.Config{CgroupRoot: root, NoRetain: true, OnEvent: on})
	},
}

// sink is one output file. mu orders its lines: an event line is written
// only while mu is held, and mu is held from the witness's Start until the
// start record is written.
type sink struct {
	mu  sync.Mutex
	enc *json.Encoder
	err error // the first failed event write
}

func (s *sink) event(v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(v); err != nil && s.err == nil {
		s.err = err
	}
}

func openSink(path string) (*sink, func(), error) {
	if path == "-" {
		return &sink{enc: json.NewEncoder(os.Stdout)}, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return &sink{enc: json.NewEncoder(io.Writer(f))}, func() { f.Close() }, nil
}

func run(o options, ws witnesses, stopSig <-chan os.Signal) error {
	if o.netOut != "" && filepath.Clean(o.netOut) == filepath.Clean(o.out) {
		return errors.New("-net-out and -out must be different files: a reader of the exec file takes every line that is not a record for an exec")
	}
	execOut, closeExec, err := openSink(o.out)
	if err != nil {
		return err
	}
	defer closeExec()
	ew := ws.exec(o.root, func(e execbpf.Event) {
		if e.Kind != execbpf.KindExec || (!o.all && e.Attribution != witness.ByCgroup) {
			return
		}
		args := e.Args
		if args == nil {
			args = []string{} // the schema requires an array, never null
		}
		execOut.event(witness.Line{
			Time: e.Time.UTC(), PID: e.PID, PPID: e.PPID, HostPID: e.HostPID,
			Comm: e.Comm, Exe: e.Exe, Command: strings.Join(args, " "), Args: args,
			CgroupID: e.CgroupID, Cgroup: e.Cgroup, TraceID: e.TraceID, Attribution: string(e.Attribution),
		})
	})
	var netOut *sink
	var nw capturer
	if o.netOut != "" {
		var closeNet func()
		if netOut, closeNet, err = openSink(o.netOut); err != nil {
			return err
		}
		defer closeNet()
		nw = ws.net(o.root, func(e netbpf.Event) {
			if !o.all && e.Attribution != witness.ByCgroup {
				return
			}
			netOut.event(witness.NetLine{
				Time: e.Time.UTC(), Op: string(e.Op), Protocol: e.Protocol,
				Dest: netip.AddrPortFrom(e.Dest.Addr().Unmap(), e.Dest.Port()).String(),
				PID:  e.PID, HostPID: e.HostPID, Comm: e.Comm, SockType: e.SockType,
				CgroupID: e.CgroupID, Cgroup: e.Cgroup, TraceID: e.TraceID, Attribution: string(e.Attribution),
			})
		})
	}

	// The start and stop records bound each file's capture. A reader trusts
	// an absence only inside a window closed by a healthy stop, so a witness
	// killed before it could write one leaves a file that proves nothing.
	if err := start(ew, execOut); err != nil {
		return err
	}
	if nw != nil {
		// -net-out asked for network evidence: running exec-only instead
		// would leave the network file without a window, so fail.
		if err := start(nw, netOut); err != nil {
			ew.Stop()
			return fmt.Errorf("network witness: %w", err)
		}
	}
	stopAll := func() error { return errors.Join(stop(ew, execOut), stop(nw, netOut)) }
	if o.ready != "" {
		if err := os.WriteFile(o.ready, []byte("attached\n"), 0o644); err != nil {
			return errors.Join(err, stopAll())
		}
		defer os.Remove(o.ready)
	}
	fmt.Fprintln(os.Stderr, "subpoena-witness: attached")
	<-stopSig
	return stopAll()
}

// start starts w and writes s's start record. s.mu is held from Start until
// the record is written: Start hands events to a reader goroutine, and an
// event line written before the start record would read as outside the
// window and fail a healthy run.
func start(w capturer, s *sink) error {
	s.mu.Lock()
	if err := w.Start(); err != nil {
		s.mu.Unlock()
		return err
	}
	err := s.enc.Encode(witness.Record{Time: time.Now().UTC(), Record: witness.RecordStart})
	s.mu.Unlock()
	if err != nil {
		w.Stop()
		return err
	}
	return nil
}

// stop stops w and writes s's stop record, healthy only if Stop reported no
// loss or failure and no event write failed. A nil w does nothing.
func stop(w capturer, s *sink) error {
	if w == nil {
		return nil
	}
	err := w.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	err = errors.Join(err, s.err)
	rec := witness.Record{Time: time.Now().UTC(), Record: witness.RecordStop, Healthy: err == nil}
	if err != nil {
		rec.Error = err.Error()
	}
	return errors.Join(err, s.enc.Encode(rec))
}
