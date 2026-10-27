//subpoena:spec_derived
//subpoena:pure_logic

// The witness-file reader, from docs/ports.md (W3) and
// docs/witness-event.schema.json. These are the cases a port's reader must
// also pass. They read a file the witness wrote; there is no telemetry.
package witness

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	traceA = "c0de00000000000000000000000000a1"
	traceB = "c0de00000000000000000000000000b2"
)

func TestSpawnedReturnsEveryLineOfThatTrace(t *testing.T) {
	in := `{"time":"2026-10-26T12:00:00Z","pid":7,"ppid":1,"host_pid":4007,"comm":"rm","exe":"/usr/bin/rm","command":"rm -rf /tmp/x","args":["rm","-rf","/tmp/x"],"cgroup_id":91,"cgroup":"subpoena/` + traceA + `","trace_id":"` + traceA + `","attribution":"cgroup"}
{"time":"2026-10-26T12:00:01Z","pid":8,"ppid":7,"host_pid":4008,"comm":"sh","exe":"/bin/sh","command":"sh","args":["sh"],"cgroup_id":92,"cgroup":"subpoena/` + traceB + `","trace_id":"` + traceB + `","attribution":"cgroup"}
{"time":"2026-10-26T12:00:02Z","pid":9,"ppid":7,"host_pid":4009,"comm":"curl","exe":"/usr/bin/curl","command":"curl x","args":["curl","x"],"cgroup_id":91,"cgroup":"subpoena/` + traceA + `","trace_id":"` + traceA + `","attribution":"cgroup"}
`
	log, err := ReadLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := log.Spawned(traceA)
	if len(got) != 2 {
		t.Fatalf("want both execs of trace A, got %+v", got)
	}
	want := ProcessEvent{
		PID: 7, PPID: 1, Exe: "/usr/bin/rm", Command: "rm -rf /tmp/x", CommandSource: CommandLine,
		Cgroup: "subpoena/" + traceA, CgroupID: 91, TraceID: traceA,
		Attribution: ByCgroup, SeenAt: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("first event:\n got  %+v\n want %+v", got[0], want)
	}
	if got[1].Command != "curl x" {
		t.Fatalf("second event: %+v", got[1])
	}
	if n := len(log.Spawned(traceB)); n != 1 {
		t.Fatalf("trace B: want 1 exec, got %d", n)
	}
	if n := len(log.Spawned("c0de00000000000000000000000000ff")); n != 0 {
		t.Fatalf("unknown trace: want none, got %d", n)
	}
}

// Over-report, never filter on what the application controls: the command
// name and arguments play no part, only the trace ID from the cgroup.
func TestSpawnedDoesNotFilterOnTheCommand(t *testing.T) {
	in := `{"time":"2026-10-26T12:00:00Z","pid":7,"ppid":1,"host_pid":7,"comm":"","exe":"","command":"","args":[],"cgroup_id":1,"cgroup":"","trace_id":"` + traceA + `","attribution":"cgroup"}
`
	log, err := ReadLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(log.Spawned(traceA)); n != 1 {
		t.Fatalf("an exec with no readable command is still an exec: got %d", n)
	}
}

// Lines without a trace ID (written with -all) belong to no session.
func TestLinesWithoutATraceBelongToNoSession(t *testing.T) {
	in := `{"time":"2026-10-26T12:00:00Z","pid":7,"ppid":1,"host_pid":7,"comm":"cron","exe":"/usr/sbin/cron","command":"cron","args":["cron"],"cgroup_id":1,"cgroup":"/system.slice/cron.service"}
`
	log, err := ReadLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(log.Spawned("")); n != 0 {
		t.Fatalf("the empty trace ID must match nothing, got %d", n)
	}
	if n := log.Len(); n != 1 {
		t.Fatalf("the line is still read: Len %d", n)
	}
}

func TestUnknownFieldsAndBlankLinesAreIgnored(t *testing.T) {
	in := "\n" + `{"time":"2026-10-26T12:00:00Z","pid":7,"ppid":1,"host_pid":7,"comm":"x","exe":"/x","command":"x","args":["x"],"cgroup_id":1,"cgroup":"/c","trace_id":"` + traceA + `","attribution":"cgroup","added_later":{"a":1}}` + "\n\n"
	log, err := ReadLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(log.Spawned(traceA)); n != 1 {
		t.Fatalf("want 1, got %d", n)
	}
}

// A line that does not decode is an error, never skipped: skipping it could
// turn an exec into an absence.
func TestAMalformedLineIsAnErrorWithItsLineNumber(t *testing.T) {
	for name, in := range map[string]string{
		"truncated":     `{"time":"2026-10-26T12:00:00Z","pid":7` + "\n",
		"wrong type":    `{"time":"2026-10-26T12:00:00Z","pid":"seven","trace_id":"` + traceA + `"}` + "\n",
		"not an object": "[1,2]\n",
		"no time":       `{"pid":7,"trace_id":"` + traceA + `","attribution":"cgroup"}` + "\n",
	} {
		_, err := ReadLog(strings.NewReader(`{"time":"2026-10-26T12:00:00Z","pid":1}` + "\n" + in))
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		if !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%s: error %q does not name line 2", name, err)
		}
	}
}

// The schema is the contract other languages read; Line is what the witness
// writes. They must name the same fields, with the same ones required.
func TestLineMatchesTheSchema(t *testing.T) {
	b, err := os.ReadFile("../../docs/witness-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required             []string                  `json:"required"`
		Properties           map[string]map[string]any `json:"properties"`
		AdditionalProperties *bool                     `json:"additionalProperties"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties == nil || !*schema.AdditionalProperties {
		t.Error("the schema must allow additional properties: readers ignore fields they do not know")
	}
	var fields, required []string
	lt := reflect.TypeOf(Line{})
	for i := 0; i < lt.NumField(); i++ {
		tag := lt.Field(i).Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		fields = append(fields, name)
		if opts != "omitempty" {
			required = append(required, name)
		}
	}
	var props []string
	for p := range schema.Properties {
		props = append(props, p)
	}
	sort.Strings(fields)
	sort.Strings(props)
	sort.Strings(required)
	sort.Strings(schema.Required)
	if !reflect.DeepEqual(fields, props) {
		t.Errorf("fields:\n Line   %v\n schema %v", fields, props)
	}
	if !reflect.DeepEqual(required, schema.Required) {
		t.Errorf("required:\n Line   %v\n schema %v", required, schema.Required)
	}
}

// What the witness writes, ReadLog reads back unchanged.
func TestLineRoundTrips(t *testing.T) {
	l := Line{
		Time: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC), PID: 3, PPID: 2, HostPID: 30,
		Comm: "rm", Exe: "/usr/bin/rm", Command: "rm a", Args: []string{"rm", "a"},
		CgroupID: 5, Cgroup: "subpoena/" + traceA, TraceID: traceA, Attribution: string(ByCgroup),
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	log, err := ReadLog(strings.NewReader(string(b) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := log.Lines(); len(got) != 1 || !reflect.DeepEqual(got[0], l) {
		t.Fatalf("round trip: %+v", got)
	}
}
