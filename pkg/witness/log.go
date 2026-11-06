package witness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
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

// DeliveryLine is one line of a delivery capture: one send seen by the kernel
// (netbpf). A line with a delivery_op field is a DeliveryLine; docs/ports.md
// (W8) has the rest. Peer and Local are "address:port", "[address]:port" for
// IPv6. An empty Peer means the send's peer could not be read.
type DeliveryLine struct {
	Time        time.Time `json:"time"`
	DeliveryOp  string    `json:"delivery_op"`
	PID         int       `json:"pid"`
	HostPID     int       `json:"host_pid"`
	Comm        string    `json:"comm"`
	Protocol    string    `json:"protocol"`
	Peer        string    `json:"peer"`
	Local       string    `json:"local"`
	Bytes       uint64    `json:"bytes"`
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
	// Coverage, on a stop record, says in one line what the capture might have
	// missed even when healthy.
	Coverage string `json:"coverage,omitempty"`
}

// Record kinds.
const (
	RecordStart = "start"
	RecordStop  = "stop"
)

// Log is a witness file read back: a Witness over what subpoena-witness
// wrote, for tests that run the witness as a separate process.
type Log struct {
	lines      []Line
	deliveries []DeliveryEvent
	coverage   string
	health     error // the first capture fault in the file, or nil
}

var (
	_ Witness         = (*Log)(nil)
	_ DeliveryWitness = (*Log)(nil)
	_ HealthReporter  = (*Log)(nil)
)

// ReadLog reads subpoena-witness JSON lines. Blank lines and unknown fields
// are ignored. A line that does not decode, has no time, or has a key that
// differs from a known one only by case is an error naming its line number:
// skipping it could turn an exec into an absence, and Go's case-insensitive
// decoding would read such a key where another language's reader would not.
// Capture faults in the file (see Health) do not stop the read: the execs
// are still evidence that something ran.
//
//subpoena:enforcement_point
func ReadLog(r io.Reader) (*Log, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	l := &Log{}
	open, records, windows := 0, 0, 0 // open: line of the start record of the open window
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
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(b, &keys); err != nil {
			return nil, fmt.Errorf("witness: line %d: %w", n, err)
		}
		if err := caseVariant(keys); err != nil {
			return nil, fmt.Errorf("witness: line %d: %w", n, err) //subpoena:enforcement
		}
		if rec, ok := keys["record"]; ok && string(rec) != "null" {
			var rec Record
			if err := json.Unmarshal(b, &rec); err != nil {
				return nil, fmt.Errorf("witness: line %d: %w", n, err)
			}
			if rec.Time.IsZero() {
				return nil, fmt.Errorf("witness: line %d: no time", n) //subpoena:enforcement
			}
			records++
			if rec.Coverage != "" {
				l.coverage = rec.Coverage
			}
			switch rec.Record {
			case RecordStart:
				if open != 0 {
					fault(fmt.Errorf("witness: line %d: a capture started while the one from line %d was still open", n, open)) //subpoena:enforcement
				}
				open = n
				windows++
			case RecordStop:
				switch {
				case open == 0:
					fault(fmt.Errorf("witness: line %d: a stop with no capture open", n)) //subpoena:enforcement
				case !rec.Healthy || rec.Error != "":
					fault(fmt.Errorf("witness: line %d: capture unhealthy: %s", n, rec.Error)) //subpoena:enforcement
				}
				open = 0
			default:
				return nil, fmt.Errorf("witness: line %d: unknown record %q", n, rec.Record) //subpoena:enforcement
			}
			continue
		}
		if op, ok := keys["delivery_op"]; ok && string(op) != "null" {
			e, err := readDelivery(b)
			if err != nil {
				return nil, fmt.Errorf("witness: line %d: %w", n, err) //subpoena:enforcement
			}
			if open == 0 {
				fault(fmt.Errorf("witness: line %d: a delivery outside any capture window", n)) //subpoena:enforcement
			}
			l.deliveries = append(l.deliveries, e)
			continue
		}
		var ln Line
		if err := json.Unmarshal(b, &ln); err != nil {
			return nil, fmt.Errorf("witness: line %d: %w", n, err)
		}
		if ln.Time.IsZero() {
			return nil, fmt.Errorf("witness: line %d: no time", n) //subpoena:enforcement
		}
		if open == 0 {
			fault(fmt.Errorf("witness: line %d: an exec outside any capture window", n)) //subpoena:enforcement
		}
		l.lines = append(l.lines, ln)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	switch {
	case records == 0:
		// Every exec was outside a window too; say why, once.
		l.health = errNoRecords //subpoena:enforcement
	case open != 0:
		fault(fmt.Errorf("witness: the capture from line %d never stopped: the witness was killed, or the file was read before it stopped", open)) //subpoena:enforcement
	case windows > 1:
		// Execs are tied to a window by file order, not time, and Spawned
		// filters by trace: a process that ran between two windows (the
		// witness restarted mid-test) is in neither, so nothing vouches for
		// its absence.
		fault(fmt.Errorf("witness: the file holds %d capture windows, and nothing watched between them; use one witness run per file", windows)) //subpoena:enforcement
	}
	return l, nil
}

// readDelivery reads a delivery line. A peer that does not parse is an error,
// never an unknown peer: an empty one is how the witness says it could not tell.
func readDelivery(b []byte) (DeliveryEvent, error) {
	var d DeliveryLine
	if err := json.Unmarshal(b, &d); err != nil {
		return DeliveryEvent{}, err
	}
	if d.Time.IsZero() {
		return DeliveryEvent{}, errors.New("no time")
	}
	switch Op(d.DeliveryOp) {
	case OpDeliver, OpSendmsg:
	default:
		return DeliveryEvent{}, fmt.Errorf("unknown delivery_op %q", d.DeliveryOp)
	}
	e := DeliveryEvent{
		PID: d.PID, Comm: d.Comm, Op: Op(d.DeliveryOp), Protocol: d.Protocol, Bytes: d.Bytes,
		Cgroup: d.Cgroup, CgroupID: d.CgroupID, TraceID: d.TraceID, Attribution: Attribution(d.Attribution), SeenAt: d.Time,
	}
	var err error
	if d.Peer != "" {
		if e.Peer, err = netip.ParseAddrPort(d.Peer); err != nil {
			return DeliveryEvent{}, fmt.Errorf("peer: %w", err)
		}
		e.Peer = netip.AddrPortFrom(e.Peer.Addr().Unmap(), e.Peer.Port())
	}
	if d.Local != "" {
		if e.Local, err = netip.ParseAddrPort(d.Local); err != nil {
			return DeliveryEvent{}, fmt.Errorf("local: %w", err)
		}
	}
	return e, nil
}

// knownKeys are the field names of Line, Record and DeliveryLine.
var knownKeys = func() []string {
	var out []string
	for _, v := range []any{Line{}, Record{}, DeliveryLine{}} {
		t := reflect.TypeOf(v)
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			out = append(out, name)
		}
	}
	return out
}()

// caseVariant refuses a key that differs from a known field name only by
// case ("Healthy", "TRACE_ID"): encoding/json would read it as that field,
// and a reader in another language would not.
func caseVariant(keys map[string]json.RawMessage) error {
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

// Len returns the number of exec lines read.
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

// Delivered returns every send whose trace ID, read by the kernel side from its
// cgroup, is traceID. Nothing the application controls is consulted. The empty
// trace ID matches nothing.
func (l *Log) Delivered(traceID string) []DeliveryEvent {
	if traceID == "" {
		return nil
	}
	var out []DeliveryEvent
	for _, e := range l.deliveries {
		if e.TraceID == traceID {
			out = append(out, e)
		}
	}
	return out
}

// Coverage is the stop record's account of what the capture might have missed
// even when healthy, or "" if it gives none.
func (l *Log) Coverage() string { return l.coverage }
