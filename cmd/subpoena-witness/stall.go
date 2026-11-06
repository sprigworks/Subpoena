package main

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// stallLimit is how long a line may sit unwritten once the witness is told to
// stop. Reading the last events takes the reader goroutines, which block on the
// output, so without it a consumer that stopped reading holds Stop forever.
const stallLimit = 3 * time.Second

// stallGuard writes to dst from one goroutine, so that a caller can give up on a
// write that never returns. Until stopping is called it waits as long as dst
// does, and no line is dropped here. That holds up the reader behind it, though,
// so a slow consumer can fill the kernel's ring buffer: those events are lost, and
// Health says so. After stopping, once a Write has waited limit with no line
// getting through, every Write fails. An output with nothing to
// write is not stalled, however long Stop takes. The goroutine stuck in dst is left
// behind, for the process's exit to end.
type stallGuard struct {
	limit   time.Duration
	lines   chan []byte
	results chan error
	stalled chan struct{}
	written atomic.Uint64
	waiting atomic.Int64 // Writes in progress
}

func newStallGuard(dst io.Writer, limit time.Duration) *stallGuard {
	g := &stallGuard{limit: limit, lines: make(chan []byte), results: make(chan error), stalled: make(chan struct{})}
	go func() {
		for b := range g.lines {
			_, err := dst.Write(b)
			g.written.Add(1)
			select {
			case g.results <- err:
			case <-g.stalled:
			}
		}
	}()
	return g
}

var errStalled = errors.New("output stalled while stopping, so lines were dropped")

// Write hands b to the writing goroutine and waits for its result.
func (g *stallGuard) Write(b []byte) (int, error) {
	g.waiting.Add(1)
	defer g.waiting.Add(-1)
	line := append([]byte(nil), b...) // an encoder reuses its buffer
	select {
	case g.lines <- line:
	case <-g.stalled:
		return 0, fmt.Errorf("subpoena-witness: %w", errStalled)
	}
	select {
	case err := <-g.results:
		if err != nil {
			return 0, err
		}
		return len(b), nil
	case <-g.stalled:
		return 0, fmt.Errorf("subpoena-witness: %w", errStalled)
	}
}

// stopping starts the clock on writes that make no progress.
func (g *stallGuard) stopping() {
	go func() {
		tick := g.limit / 4
		last, stuck := g.written.Load(), time.Duration(0)
		for {
			time.Sleep(tick)
			now := g.written.Load()
			if now != last || g.waiting.Load() == 0 {
				last, stuck = now, 0
				continue
			}
			if stuck += tick; stuck >= g.limit {
				close(g.stalled)
				return
			}
		}
	}()
}
