package witness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
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
// are ignored. A line that does not decode, has no time, or has a key that
// differs from a known one only by case is an error naming its line number:
// skipping it could turn an exec into an absence, and Go's case-insensitive
// decoding would read such a key where another language's reader would not.
// Capture faults in the file (see Health) do not stop the read: the execs
// are still evidence that something ran.
func ReadLog(r io.Reader) (*Log, error) {
	l := &Log{}
	c := &capture{known: execKeys, noun: "an exec"}
	err := c.scan(r, func(n int, b []byte) (time.Time, error) {
		var ln Line
		if err := json.Unmarshal(b, &ln); err != nil {
			return time.Time{}, fmt.Errorf("witness: line %d: %w", n, err)
		}
		l.lines = append(l.lines, ln)
		return ln.Time, nil
	})
	if err != nil {
		return nil, err
	}
	l.health = c.health
	return l, nil
}

// capture reads a witness file's lines and keeps its capture windows: the
// start and stop records, and whether each event lies inside a window.
// ReadLog and ReadNetworkLog share it, so the exec file and the network file
// are held to the same rules.
type capture struct {
	known []string // the field names of the file's event line and Record
	noun  string   // an event line, in a fault: "an exec"
	// open: line of the start record of the open window.
	open, records, windows int
	health                 error // the first capture fault, or nil
}

func (c *capture) fault(err error) {
	if c.health == nil {
		c.health = err
	}
}

// scan reads JSON lines from r. Record lines it keeps itself; every other
// line goes to event, which decodes it and returns its time. A line that does
// not decode, has no time, has a key in another case or an unknown record
// kind is an error naming its line number.
//
//subpoena:enforcement_point
func (c *capture) scan(r io.Reader, event func(n int, b []byte) (time.Time, error)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for n := 1; sc.Scan(); n++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(b, &keys); err != nil {
			return fmt.Errorf("witness: line %d: %w", n, err)
		}
		if err := caseVariant(keys, c.known); err != nil {
			return fmt.Errorf("witness: line %d: %w", n, err) //subpoena:enforcement
		}
		if rec, ok := keys["record"]; ok && string(rec) != "null" {
			var rec Record
			if err := json.Unmarshal(b, &rec); err != nil {
				return fmt.Errorf("witness: line %d: %w", n, err)
			}
			if rec.Time.IsZero() {
				return fmt.Errorf("witness: line %d: no time", n) //subpoena:enforcement
			}
			c.records++
			switch rec.Record {
			case RecordStart:
				if c.open != 0 {
					c.fault(fmt.Errorf("witness: line %d: a capture started while the one from line %d was still open", n, c.open)) //subpoena:enforcement
				}
				c.open = n
				c.windows++
			case RecordStop:
				switch {
				case c.open == 0:
					c.fault(fmt.Errorf("witness: line %d: a stop with no capture open", n)) //subpoena:enforcement
				case !rec.Healthy || rec.Error != "":
					c.fault(fmt.Errorf("witness: line %d: capture unhealthy: %s", n, rec.Error)) //subpoena:enforcement
				}
				c.open = 0
			default:
				return fmt.Errorf("witness: line %d: unknown record %q", n, rec.Record) //subpoena:enforcement
			}
			continue
		}
		t, err := event(n, b)
		if err != nil {
			return err
		}
		if t.IsZero() {
			return fmt.Errorf("witness: line %d: no time", n) //subpoena:enforcement
		}
		if c.open == 0 {
			c.fault(fmt.Errorf("witness: line %d: %s outside any capture window", n, c.noun)) //subpoena:enforcement
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	switch {
	case c.records == 0:
		// Every event was outside a window too; say why, once.
		c.health = errNoRecords //subpoena:enforcement
	case c.open != 0:
		c.fault(fmt.Errorf("witness: the capture from line %d never stopped: the witness was killed, or the file was read before it stopped", c.open)) //subpoena:enforcement
	case c.windows > 1:
		// Events are tied to a window by file order, not time, and Spawned
		// and Dialed filter by trace: something that ran between two windows
		// (the witness restarted mid-test) is in neither, so nothing vouches
		// for its absence.
		c.fault(fmt.Errorf("witness: the file holds %d capture windows, and nothing watched between them; use one witness run per file", c.windows)) //subpoena:enforcement
	}
	return nil
}

// execKeys are the field names of Line and Record.
var execKeys = jsonNames(Line{}, Record{})

// jsonNames returns the JSON field names of the given structs.
func jsonNames(vs ...any) []string {
	var out []string
	for _, v := range vs {
		t := reflect.TypeOf(v)
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			out = append(out, name)
		}
	}
	return out
}

// caseVariant refuses a key that differs from a known field name only by
// case ("Healthy", "TRACE_ID"): encoding/json would read it as that field,
// and a reader in another language would not.
func caseVariant(keys map[string]json.RawMessage, knownKeys []string) error {
	for k := range keys {
		for _, known := range knownKeys {
			if k != known && strings.EqualFold(k, known) {
				return fmt.Errorf("key %q is %q in another case", k, known)
			}
		}
	}
	return nil
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
