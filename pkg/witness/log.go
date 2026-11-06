package witness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
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

// FileLine is one line of file witness output: one change under a watched
// root. A line with a file_op field is a FileLine; docs/ports.md (W7) has the
// rest. TraceID is empty for a witness that cannot attribute to a trace, and
// such a line belongs to every trace.
type FileLine struct {
	Time        time.Time `json:"time"`
	FileOp      string    `json:"file_op"`
	Path        string    `json:"path"`
	Root        string    `json:"root"`
	IsDir       bool      `json:"is_dir"`
	Source      string    `json:"source"`
	Rename      string    `json:"rename,omitempty"`
	Cookie      uint32    `json:"cookie,omitempty"`
	TraceID     string    `json:"trace_id,omitempty"`
	Attribution string    `json:"attribution"`
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
	// Roots, on a file witness's start record, are the directories it watched.
	Roots []string `json:"roots,omitempty"`
	// Captures, on a start record, are the hooks that ran (CaptureExec,
	// CaptureDelivery). A file that does not name a capture cannot prove an
	// absence of what it would have seen.
	Captures []string `json:"captures,omitempty"`
	// Coverage, on a stop record, says in one line what the capture might have
	// missed even when healthy.
	Coverage string `json:"coverage,omitempty"`
	// SilentCloses, on a file witness's stop record, are the files opened for
	// writing and closed with no write seen: no absence rests on them.
	SilentCloses []string `json:"silent_closes,omitempty"`
	// Symlinks, on a file witness's stop record, are the symlinks seen under
	// the roots: a path crossing one is not covered.
	Symlinks []string `json:"symlinks,omitempty"`
}

// Capture names, as a start record lists them.
const (
	CaptureExec     = "exec"
	CaptureDelivery = "delivery"
)

// Record kinds.
const (
	RecordStart = "start"
	RecordStop  = "stop"
)

// EventRow is RowLine.Event. A line with an event field that is not a record is
// a database witness's row line.
const EventRow = "row"

// RowLine is one line a database witness writes: one statement and what became
// of it. Rows is -1 when the server gave no usable count. Unlike an exec line it
// has no trace ID: it holds for every trace (Attribution "destination").
type RowLine struct {
	Time        time.Time `json:"time"`
	Event       string    `json:"event"`
	Engine      string    `json:"engine"`
	Conn        int       `json:"conn"`
	Dest        string    `json:"dest"`
	Statement   string    `json:"statement"`
	Verb        string    `json:"verb"`
	Tables      []string  `json:"tables"`
	Opaque      bool      `json:"opaque"`
	Reason      string    `json:"reason,omitempty"`
	Rows        int64     `json:"rows"`
	Outcome     Outcome   `json:"outcome"`
	Attribution string    `json:"attribution"`
}

// RowLineOf is e as a line of the witness file.
func RowLineOf(e RowEvent) RowLine {
	tables := e.Tables
	if tables == nil {
		tables = []string{} // the schema requires an array, never null
	}
	return RowLine{
		Time: e.SeenAt, Event: EventRow, Engine: e.Engine, Conn: e.Conn, Dest: e.Dest.String(),
		Statement: e.Statement, Verb: e.Verb, Tables: tables, Opaque: e.Opaque, Reason: e.Reason,
		Rows: e.Rows, Outcome: e.Outcome, Attribution: string(e.Attribution),
	}
}

// Log is a witness file read back: a Witness over what subpoena-witness
// wrote, for tests that run the witness as a separate process.
type Log struct {
	lines      []Line
	files      []FileLine
	roots      []string
	silent     []string
	symlinks   []string
	captures   []string
	deliveries []DeliveryEvent
	rows       []RowLine
	coverage   string
	health     error // the first capture fault in the file, or nil
}

var (
	_ Witness         = (*Log)(nil)
	_ FileWitness     = (*Log)(nil)
	_ DeliveryWitness = (*Log)(nil)
	_ DBWitness       = (*Log)(nil)
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
			l.roots = append(l.roots, rec.Roots...)
			l.silent = append(l.silent, rec.SilentCloses...)
			l.symlinks = append(l.symlinks, rec.Symlinks...)
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
				l.captures = append(l.captures, rec.Captures...)
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
		if op, ok := keys["file_op"]; ok && string(op) != "null" {
			var fl FileLine
			if err := json.Unmarshal(b, &fl); err != nil {
				return nil, fmt.Errorf("witness: line %d: %w", n, err)
			}
			if fl.Time.IsZero() {
				return nil, fmt.Errorf("witness: line %d: no time", n) //subpoena:enforcement
			}
			if fl.Path == "" {
				return nil, fmt.Errorf("witness: line %d: no path", n) //subpoena:enforcement
			}
			switch FileOp(fl.FileOp) {
			case FileCreate, FileWrite, FileRename, FileUnlink:
			default:
				return nil, fmt.Errorf("witness: line %d: unknown file_op %q", n, fl.FileOp) //subpoena:enforcement
			}
			if open == 0 {
				fault(fmt.Errorf("witness: line %d: a file event outside any capture window", n)) //subpoena:enforcement
			}
			l.files = append(l.files, fl)
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
		if ev, ok := keys["event"]; ok && string(ev) != "null" {
			row, err := readRow(b, keys)
			if err != nil {
				return nil, fmt.Errorf("witness: line %d: %w", n, err) //subpoena:enforcement
			}
			if open == 0 {
				fault(fmt.Errorf("witness: line %d: a row outside any capture window", n)) //subpoena:enforcement
			}
			if row.Outcome == OutcomeUnknown {
				fault(fmt.Errorf("witness: line %d: a write whose outcome was not seen", n)) //subpoena:enforcement
			}
			l.rows = append(l.rows, row)
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
		if e.Peer.Addr().Zone() != "" {
			return DeliveryEvent{}, fmt.Errorf("peer: %q has a zone, which the kernel never reports", d.Peer)
		}
		e.Peer = netip.AddrPortFrom(e.Peer.Addr().Unmap(), e.Peer.Port())
	}
	if d.Local != "" {
		if e.Local, err = netip.ParseAddrPort(d.Local); err != nil {
			return DeliveryEvent{}, fmt.Errorf("local: %w", err)
		}
		if e.Local.Addr().Zone() != "" {
			return DeliveryEvent{}, fmt.Errorf("local: %q has a zone, which the kernel never reports", d.Local)
		}
	}
	return e, nil
}

// readRow decodes a row line. A row it cannot read could be a write, so anything
// out of shape is an error, as for an exec, and never a skip.
//
//subpoena:enforcement_point
func readRow(b []byte, keys map[string]json.RawMessage) (RowLine, error) {
	var row RowLine
	if err := json.Unmarshal(b, &row); err != nil {
		return row, err
	}
	// A missing count would decode as zero rows, which is no effect at all.
	if rows, ok := keys["rows"]; !ok || string(rows) == "null" || row.Rows < RowsUnknown {
		return row, errors.New("no usable rows field") //subpoena:enforcement
	}
	if row.Event != EventRow {
		return row, fmt.Errorf("unknown event %q", row.Event) //subpoena:enforcement
	}
	if row.Time.IsZero() {
		return row, errors.New("no time") //subpoena:enforcement
	}
	switch row.Outcome {
	case OutcomeRead, OutcomeCommitted, OutcomeRolledBack, OutcomeFailed, OutcomeUnknown:
	default:
		return row, fmt.Errorf("unknown outcome %q", row.Outcome) //subpoena:enforcement
	}
	return row, nil
}

// knownKeys are the field names of Line, Record, FileLine, DeliveryLine and RowLine.
var knownKeys = func() []string {
	var out []string
	for _, v := range []any{Line{}, Record{}, FileLine{}, DeliveryLine{}, RowLine{}} {
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

// Wrote returns the file changes for traceID: lines naming it, and every line
// that names no trace, which a tier-1 witness's never do.
func (l *Log) Wrote(traceID string) []FileEvent {
	var out []FileEvent
	for _, f := range l.files {
		if f.TraceID != "" && f.TraceID != traceID {
			continue
		}
		out = append(out, FileEvent{
			Op: FileOp(f.FileOp), Path: f.Path, Root: f.Root, IsDir: f.IsDir, Source: FileSource(f.Source),
			Rename: f.Rename, Cookie: f.Cookie, TraceID: f.TraceID, Attribution: Attribution(f.Attribution), SeenAt: f.Time,
		})
	}
	return out
}

// Committed returns every committed row line, for every trace: a database witness
// attributes by destination, and a row line has no trace ID.
func (l *Log) Committed(traceID string) []RowEvent {
	var out []RowEvent
	for _, r := range l.rows {
		if r.Outcome != OutcomeCommitted {
			continue
		}
		dest, _ := netip.ParseAddrPort(r.Dest)
		out = append(out, RowEvent{
			Engine: r.Engine, Conn: r.Conn, Dest: dest, Statement: r.Statement, Verb: r.Verb,
			Tables: r.Tables, Opaque: r.Opaque, Reason: r.Reason, Rows: r.Rows, Outcome: r.Outcome,
			Attribution: Attribution(r.Attribution), SeenAt: r.Time,
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

// CapturedDeliveries reports whether the file's start record says the delivery
// hook ran. Without it the file has no delivery lines because nothing looked,
// which says nothing about sends: harness.NoDelivery is then Inconclusive.
func (l *Log) CapturedDeliveries() bool {
	return slices.Contains(l.captures, CaptureDelivery)
}

// Covers reports whether path lies under a root the file's start record names,
// and crosses no symlink its stop record names.
func (l *Log) Covers(path string) bool {
	return filepath.IsAbs(path) && slices.ContainsFunc(l.roots, func(r string) bool { return pathWithin(path, r) }) &&
		!crossesSymlink(path, l.symlinks)
}

// Roots are the directories the file's start record names. An exec witness's
// file names none.
func (l *Log) Roots() []string { return slices.Clone(l.roots) }

// SilentCloses are the files the stop record names as closed with no write seen.
func (l *Log) SilentCloses() []string { return slices.Clone(l.silent) }

// Coverage is the stop record's account of what the capture might have
// missed, or "" if it gives none.
func (l *Log) Coverage() string { return l.coverage }

// Rows returns the row lines read, in file order, whatever their outcome.
func (l *Log) Rows() []RowLine { return append([]RowLine(nil), l.rows...) }
