// Command subpoena-witness runs the kernel-side process witness
// (pkg/witness/execbpf) and writes one JSON line per exec, for shipping to a
// log store (tier 2 sends them to Loki). Needs root, cgroup v2 and BTF.
//
//	subpoena-witness [-cgroup-root dir] [-all] [-out file] [-ready file]
//	subpoena-witness -check-ready file   # exit 0 once the witness is attached
//
// By default only execs inside a session cgroup are written; -all writes every
// exec on the machine, which an argument-based witness query needs.
package main

import (
	"encoding/json"
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
)

// line is the JSON written per exec. Field names are what LogQL queries use
// (`| json | attribution="cgroup"`), so they are part of the interface.
type line struct {
	Time        time.Time `json:"time"`
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	HostPID     int       `json:"host_pid"`
	Comm        string    `json:"comm"`
	Exe         string    `json:"exe"`
	Command     string    `json:"command"`
	Args        []string  `json:"args"`
	CgroupID    uint64    `json:"cgroup_id"`
	Cgroup      string    `json:"cgroup"`
	TraceID     string    `json:"trace_id,omitempty"`
	Attribution string    `json:"attribution,omitempty"`
}

func main() {
	root := flag.String("cgroup-root", "", "parent of the session cgroups (default $SUBPOENA_CGROUP_ROOT or /sys/fs/cgroup/subpoena)")
	all := flag.Bool("all", false, "write every exec, not only those in a session cgroup")
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
	if err := run(*root, *all, *out, *ready); err != nil {
		fmt.Fprintln(os.Stderr, "subpoena-witness:", err)
		os.Exit(1)
	}
}

func run(root string, all bool, out, ready string) error {
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
			if err := enc.Encode(line{
				Time: e.Time.UTC(), PID: e.PID, PPID: e.PPID, HostPID: e.HostPID,
				Comm: e.Comm, Exe: e.Exe, Command: strings.Join(e.Args, " "), Args: e.Args,
				CgroupID: e.CgroupID, Cgroup: e.Cgroup, TraceID: e.TraceID, Attribution: string(e.Attribution),
			}); err != nil && writeErr == nil {
				writeErr = err
			}
		},
	})
	if err := w.Start(); err != nil {
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	err := w.Stop()
	mu.Lock()
	defer mu.Unlock()
	if writeErr != nil {
		return writeErr
	}
	return err
}
