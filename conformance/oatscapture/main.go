// Command capture is the tier-2 fixture driver, outside the application under
// test. It owns the kernel witness and proxies requests to the gateway. OATS
// closes the capture with POST /capture/stop before judging any absence.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness"
)

const events = "/var/run/subpoena-witness/events.json"
const ready = "/var/run/subpoena-witness/ready"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Each fixture gets one fresh capture, never a previous ready file or a
	// second window appended to the same log.
	for _, path := range []string{events, ready} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	cmd := exec.Command("/subpoena-witness", "-all", "-cgroup-root=/sys/fs/cgroup/subpoena", "-out="+events, "-ready="+ready)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var once sync.Once
	var stopErr error
	stop := func() error {
		once.Do(func() {
			// Stop drains pending events and reads the kernel loss counter
			// before the child writes its final health record and exits.
			stopErr = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				stopErr = errors.Join(stopErr, err)
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				stopErr = errors.Join(stopErr, errors.New("witness did not stop within 15s"), <-done)
			}
			stopErr = errors.Join(stopErr, captureHealth(events))
		})
		return stopErr
	}
	defer stop()

	// Docker marks this service healthy only when the child creates ready.
	// The gateway depends on that health check; this server can listen now,
	// but never forwards a request while the witness is not attached.
	upstream, _ := url.Parse("http://gateway:8080")
	h := &captureHandler{
		proxy: httputil.NewSingleHostReverseProxy(upstream), stop: stop,
		attached: func() bool { _, err := os.Stat(ready); return err == nil },
	}
	srv := &http.Server{Addr: ":8081", Handler: h, ReadHeaderTimeout: 5 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return stop()
}

// captureHealth uses the same fail-closed reader as tier 1: a missing start,
// missing stop, multiple windows, malformed log or unhealthy stop is an error.
func captureHealth(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	l, err := witness.ReadLog(f)
	if err != nil {
		return err
	}
	return l.Health()
}

type captureHandler struct {
	mu       sync.Mutex
	proxy    http.Handler
	stop     func() error
	attached func() bool
	closed   bool
	stopErr  error
}

//subpoena:enforcement_point
func (h *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Finalization waits for all forwarded requests to complete. No request
	// can run after the capture closes, even when a caller races the stop.
	// This fixture serializes every proxy request; it is unsuitable for
	// testing concurrent gateway requests.
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.URL.Path == "/capture/stop" {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !h.closed {
			h.closed = true
			h.stopErr = h.stop()
		}
		if h.stopErr != nil { //subpoena:enforcement_guard false
			http.Error(w, "witness capture incomplete: "+h.stopErr.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "capture stopped and healthy")
		return
	}
	if h.closed || !h.attached() { //subpoena:enforcement_guard false
		http.Error(w, "witness capture is not active", http.StatusServiceUnavailable)
		return
	}
	h.proxy.ServeHTTP(w, r)
}
