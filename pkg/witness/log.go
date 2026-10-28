package witness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Line is one line of subpoena-witness output: one exec. The JSON field names
// are an interface (LogQL queries and other languages' readers use them); the
// schema is docs/witness-event.schema.json, and docs/ports.md says what each
// field means.
type Line struct {
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

// Record is a line that marks a capture window: "start" once the witness is
// attached, "stop" when it has stopped, with the capture's health. A record
// line is told from an exec line by its record field.
type Record struct {
	Time    time.Time `json:"time"`
	Record  string    `json:"record"`
	Healthy bool      `json:"healthy"`
	Error   string    `json:"error,omitempty"`
}

// Record kinds.
const (
	RecordStart = "start"
	RecordStop  = "stop"
)

// Log is a witness file read back: a Witness over what subpoena-witness
// wrote, for tests that run the witness as a separate process.
type Log struct {
	lines  []Line
	health error // the first capture fault in the file, or nil
}

var (
	_ Witness        = (*Log)(nil)
	_ HealthReporter = (*Log)(nil)
)

// ReadLog reads subpoena-witness JSON lines. Blank lines and unknown fields
// are ignored. A line that does not decode, or has no time, is an error
// naming its line number: skipping it could turn an exec into an absence.
// Capture faults in the file (see Health) do not stop the read: the execs
// are still evidence that something ran.
func ReadLog(r io.Reader) (*Log, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	l := &Log{}
	open, records := 0, 0 // open: line of the start record of the open window
	fault := func(err error) {
		if l.health == nil {
			l.health = err
		}
	}
	for n := 1; sc.Scan(); n++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var kind struct {
			Record *string `json:"record"`
		}
		if err := json.Unmarshal(b, &kind); err != nil {
			return nil, fmt.Errorf("witness: line %d: %w", n, err)
		}
		if kind.Record != nil {
			var rec Record
			if err := json.Unmarshal(b, &rec); err != nil {
				return nil, fmt.Errorf("witness: line %d: %w", n, err)
			}
			if rec.Time.IsZero() {
				return nil, fmt.Errorf("witness: line %d: no time", n)
			}
			records++
			switch rec.Record {
			case RecordStart:
				if open != 0 {
					fault(fmt.Errorf("witness: line %d: a capture started while the one from line %d was still open", n, open))
				}
				open = n
			case RecordStop:
				switch {
				case open == 0:
					fault(fmt.Errorf("witness: line %d: a stop with no capture open", n))
				case !rec.Healthy || rec.Error != "":
					fault(fmt.Errorf("witness: line %d: capture unhealthy: %s", n, rec.Error))
				}
				open = 0
			default:
				return nil, fmt.Errorf("witness: line %d: unknown record %q", n, rec.Record)
			}
			continue
		}
		var ln Line
		if err := json.Unmarshal(b, &ln); err != nil {
			return nil, fmt.Errorf("witness: line %d: %w", n, err)
		}
		if ln.Time.IsZero() {
			return nil, fmt.Errorf("witness: line %d: no time", n)
		}
		if open == 0 {
			fault(fmt.Errorf("witness: line %d: an exec outside any capture window", n))
		}
		l.lines = append(l.lines, ln)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	switch {
	case records == 0:
		// Every exec was outside a window too; say why, once.
		l.health = errNoRecords
	case open != 0:
		fault(fmt.Errorf("witness: the capture from line %d never stopped: the witness was killed, or the file was read before it stopped", open))
	}
	return l, nil
}

var errNoRecords = errors.New("witness: the file has no start or stop records, so its capture health is unknown (an older subpoena-witness wrote it, or it was cut short)")

// Health reports the first capture fault in the file: no start and stop
// records at all, an exec outside a start..stop window, a window that never
// stopped, or a stop record that says the capture was unhealthy (lost kernel
// events, a reader or write failure). Absence can rest on the file only when
// Health is nil.
//
//subpoena:enforcement_point
func (l *Log) Health() error {
	if l.health != nil {
		return l.health //subpoena:enforcement
	}
	return nil
}

// Len returns the number of lines read.
func (l *Log) Len() int { return len(l.lines) }

// Lines returns the lines read, in file order.
func (l *Log) Lines() []Line { return append([]Line(nil), l.lines...) }

// Spawned returns every exec whose trace ID, read by the kernel side from its
// cgroup, is traceID. Nothing the application controls is consulted. The
// empty trace ID matches nothing.
func (l *Log) Spawned(traceID string) []ProcessEvent {
	if traceID == "" {
		return nil
	}
	var out []ProcessEvent
	for _, ln := range l.lines {
		if ln.TraceID != traceID {
			continue
		}
		// subpoena-witness writes argv as the command. Without it, the task
		// name stands in, marked as name-only.
		cmd, src := ln.Command, CommandLine
		if cmd == "" {
			cmd, src = ln.Comm, CommandName
			if cmd == "" {
				src = ""
			}
		}
		out = append(out, ProcessEvent{
			CommandSource: src,
			PID:           ln.PID, PPID: ln.PPID, Exe: ln.Exe, Command: cmd,
			Cgroup: ln.Cgroup, CgroupID: ln.CgroupID, TraceID: ln.TraceID,
			Attribution: Attribution(ln.Attribution), SeenAt: ln.Time,
		})
	}
	return out
}
