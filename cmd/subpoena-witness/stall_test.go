//subpoena:impl_derived
//subpoena:pure_logic

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// The start record is the only thing that says the delivery hook ran.
func TestStartRecordNamesTheCaptures(t *testing.T) {
	for _, tc := range []struct {
		deliveries bool
		want       []string
	}{
		{false, []string{witness.CaptureExec}},
		{true, []string{witness.CaptureExec, witness.CaptureDelivery}},
	} {
		r := startRecord(tc.deliveries)
		if r.Record != witness.RecordStart || !slices.Equal(r.Captures, tc.want) {
			t.Errorf("startRecord(%v) = %+v", tc.deliveries, r)
		}
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(r); err != nil {
			t.Fatal(err)
		}
		buf.WriteString(`{"time":"2026-11-06T12:00:09Z","record":"stop","healthy":true}` + "\n")
		l, err := witness.ReadLog(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if l.CapturedDeliveries() != tc.deliveries {
			t.Errorf("deliveries=%v read back as %v", tc.deliveries, l.CapturedDeliveries())
		}
	}
}

type stuckWriter struct{ release chan struct{} }

func (w stuckWriter) Write(b []byte) (int, error) { <-w.release; return len(b), nil }

// A consumer that stops reading must not hold a stopping witness for ever.
func TestStalledOutputDoesNotHoldStop(t *testing.T) {
	w := stuckWriter{make(chan struct{})}
	defer close(w.release)
	g := newStallGuard(w, 20*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := g.Write([]byte("line"))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a slow consumer lost a line before the stop: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	g.stopping()
	select {
	case err := <-done:
		if !errors.Is(err, errStalled) {
			t.Fatalf("Write = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write still blocked after the stall limit")
	}
	if _, err := g.Write([]byte("next")); !errors.Is(err, errStalled) {
		t.Fatalf("a later Write = %v", err)
	}
}

// A quiet capture has nothing to write while Stop runs, and detaching a program
// can take seconds. The stop record after that must still be written.
func TestAnIdleOutputIsNotAStall(t *testing.T) {
	var buf bytes.Buffer
	g := newStallGuard(&buf, 20*time.Millisecond)
	g.stopping()
	time.Sleep(200 * time.Millisecond)
	if _, err := g.Write([]byte("stop")); err != nil {
		t.Fatalf("Write after an idle stop = %v", err)
	}
}

// A consumer that is keeping up is not a stall, however long the drain takes.
func TestStopKeepsWritingWhileOutputMoves(t *testing.T) {
	var buf bytes.Buffer
	g := newStallGuard(&buf, 50*time.Millisecond)
	g.stopping()
	for i := 0; i < 10; i++ {
		time.Sleep(10 * time.Millisecond)
		if _, err := g.Write([]byte("x")); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}
	if buf.Len() != 10 {
		t.Fatalf("wrote %d", buf.Len())
	}
}
