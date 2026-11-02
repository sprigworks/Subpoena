//subpoena:impl_derived
//subpoena:pure_logic
package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFinalCaptureHealth(t *testing.T) {
	start := `{"time":"2026-11-01T00:00:00Z","record":"start"}` + "\n"
	stop := `{"time":"2026-11-01T00:00:01Z","record":"stop","healthy":true}` + "\n"
	exec := `{"time":"2026-11-01T00:00:00Z","command":"sleep 0.138"}` + "\n"
	for _, tc := range []struct {
		name, data string
		ok         bool
	}{
		{"healthy", start + exec + stop, true},
		{"empty", "", false},
		{"no start", exec + stop, false},
		{"no stop", start + exec, false},
		{"restart", start + stop + start + stop, false},
		{"malformed", start + "{\n" + stop, false},
		{"missing healthy", start + `{"time":"2026-11-01T00:00:01Z","record":"stop"}`, false},
		{"lost kernel events", start + `{"time":"2026-11-01T00:00:01Z","record":"stop","healthy":false,"error":"lost 2 kernel events"}`, false},
		{"reader error", start + `{"time":"2026-11-01T00:00:01Z","record":"stop","healthy":false,"error":"reader failed"}`, false},
		{"write error despite healthy", start + `{"time":"2026-11-01T00:00:01Z","record":"stop","healthy":true,"error":"write failed"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := captureHealth(path); (err == nil) != tc.ok {
				t.Fatalf("capture health = %v, want healthy=%t", err, tc.ok)
			}
		})
	}
	if err := captureHealth(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing capture passed")
	}
}

func TestRequestsMustBeInsideHealthyCapture(t *testing.T) {
	for _, stopErr := range []error{nil, errors.New("lost kernel events")} {
		t.Run(strings.ReplaceAll(fmtError(stopErr), " ", "_"), func(t *testing.T) {
			attached := false
			forwarded, stopped := 0, 0
			h := &captureHandler{
				proxy:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded++ }),
				attached: func() bool { return attached },
				stop:     func() error { stopped++; return stopErr },
			}
			request := func(method, path string, want int) {
				t.Helper()
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
				if w.Code != want {
					t.Fatalf("%s %s: status=%d body=%s, want %d", method, path, w.Code, w.Body, want)
				}
			}
			request("POST", "/sessions", 503)
			attached = true
			request("GET", "/capture/stop", 405)
			request("POST", "/sessions", 200)
			want := 200
			if stopErr != nil {
				want = 500
			}
			request("POST", "/capture/stop", want)
			request("POST", "/capture/stop", want) // stable outcome, no second capture
			request("POST", "/sessions", 503)
			if stopped != 1 || forwarded != 1 {
				t.Fatalf("stop calls=%d, forwarded=%d; want 1 each", stopped, forwarded)
			}
		})
	}
}

func fmtError(err error) string {
	if err == nil {
		return "healthy"
	}
	return err.Error()
}

func TestStopWaitsForRequestCompletion(t *testing.T) {
	entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := &captureHandler{
		proxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release
		}),
		attached: func() bool { return true },
		stop:     func() error { close(stopped); return nil },
	}
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/sessions", nil))
	}()
	<-entered
	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/capture/stop", nil))
	}()
	select {
	case <-stopped:
		t.Error("capture stopped during an active request")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-requestDone
	<-stopDone
	select {
	case <-stopped:
	default:
		t.Fatal("capture never stopped after the request finished")
	}
}
