//subpoena:spec_derived
//subpoena:pure_logic

// The network witness file reader, from docs/ports.md (W4, W6) and
// docs/witness-network-event.schema.json. conformance/witness-network.yaml
// holds the window and read-error table (cases_test.go runs it here); these
// are the field mapping, the schema and the rules the two readers share.
// They read a file the witness wrote; there is no telemetry.
package witness

import (
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	netStart = `{"time":"2026-10-28T12:00:00Z","record":"start","healthy":false}`
	netStop  = `{"time":"2026-10-28T12:00:09Z","record":"stop","healthy":true}`
)

func TestDialedReturnsEveryAttemptOfThatTrace(t *testing.T) {
	in := netStart + `
{"time":"2026-10-28T12:00:01Z","op":"connect","protocol":"tcp","dest":"192.0.2.1:443","pid":7,"host_pid":4007,"comm":"curl","sock_type":1,"cgroup_id":91,"cgroup":"subpoena/` + traceA + `","trace_id":"` + traceA + `","attribution":"cgroup"}
{"time":"2026-10-28T12:00:02Z","op":"sendmsg","protocol":"udp","dest":"[2001:db8::1]:53","pid":8,"host_pid":4008,"comm":"dig","sock_type":2,"cgroup_id":92,"cgroup":"subpoena/` + traceB + `","trace_id":"` + traceB + `","attribution":"cgroup"}
{"time":"2026-10-28T12:00:03Z","op":"sendmsg","protocol":"udp","dest":"[::ffff:198.51.100.7]:9","pid":9,"host_pid":4009,"comm":"x","sock_type":2,"cgroup_id":91,"cgroup":"subpoena/` + traceA + `","trace_id":"` + traceA + `","attribution":"cgroup"}
{"time":"2026-10-28T12:00:04Z","op":"connect","protocol":"tcp","dest":"10.0.0.1:80","pid":1,"host_pid":1,"comm":"cron","sock_type":1,"cgroup_id":1,"cgroup":"system.slice/cron.service"}
` + netStop + "\n"
	log, err := ReadNetworkLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Health(); err != nil {
		t.Fatal(err)
	}
	got := log.Dialed(traceA)
	if len(got) != 2 {
		t.Fatalf("want both attempts of trace A, got %+v", got)
	}
	want := NetworkEvent{
		PID: 7, Comm: "curl", Op: OpConnect, Protocol: "tcp", Dest: netip.MustParseAddrPort("192.0.2.1:443"),
		Cgroup: "subpoena/" + traceA, CgroupID: 91, TraceID: traceA, Attribution: ByCgroup,
		SeenAt: time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC),
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("first event:\n got  %+v\n want %+v", got[0], want)
	}
	if d := got[1].Dest; d != netip.MustParseAddrPort("198.51.100.7:9") || !d.Addr().Is4() {
		t.Fatalf("an IPv4-mapped dest must read as IPv4: %v", d)
	}
	if b := log.Dialed(traceB); len(b) != 1 || b[0].Dest != netip.MustParseAddrPort("[2001:db8::1]:53") || b[0].Op != OpSendmsg {
		t.Fatalf("trace B: %+v", b)
	}
	if n := len(log.Dialed(strings.ToUpper(traceA))); n != 2 {
		t.Fatalf("a trace ID matches whatever its case, as netbpf.Witness.Dialed: got %d", n)
	}
	if n := len(log.Dialed("")); n != 0 {
		t.Fatalf("the empty trace ID must match nothing, got %d", n)
	}
	if n := log.Len(); n != 4 {
		t.Fatalf("an attempt with no trace is still read: Len %d", n)
	}
}

// What the witness writes, ReadNetworkLog reads back unchanged.
func TestNetLineRoundTrips(t *testing.T) {
	l := NetLine{
		Time: time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), Op: string(OpConnect), Protocol: "tcp",
		Dest: "[2001:db8::7]:8080", PID: 3, HostPID: 30, Comm: "curl", SockType: 1,
		CgroupID: 5, Cgroup: "subpoena/" + traceA, TraceID: traceA, Attribution: string(ByCgroup),
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	log, err := ReadNetworkLog(strings.NewReader(netStart + "\n" + string(b) + "\n" + netStop + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := log.Lines(); len(got) != 1 || !reflect.DeepEqual(got[0], l) {
		t.Fatalf("round trip: %+v", got)
	}
	if err := log.Health(); err != nil {
		t.Fatal(err)
	}
}

// The two files follow one set of window rules, so a fault reads the same
// in both, apart from what the event is called.
func TestNetworkLogFaultsMatchTheExecLog(t *testing.T) {
	execLine := `{"time":"2026-10-28T12:00:01Z","pid":7,"trace_id":"` + traceA + `"}`
	netLine := `{"time":"2026-10-28T12:00:01Z","dest":"192.0.2.1:9","pid":7,"trace_id":"` + traceA + `"}`
	for _, tc := range []struct{ name, in string }{
		{"healthy", "<S>\n<E>\n<T>\n"},
		{"no records", "<E>\n"},
		{"never stopped", "<S>\n<E>\n"},
		{"outside", "<E>\n<S>\n<T>\n"},
		{"two windows", "<S>\n<T>\n<S>\n<T>\n"},
		{"start inside", "<S>\n<S>\n<T>\n"},
		{"stop without start", "<T>\n"},
		{"unhealthy", "<S>\n" + `{"time":"2026-10-28T12:00:09Z","record":"stop","healthy":false,"error":"lost"}` + "\n"},
		{"unknown record", "<S>\n" + `{"time":"2026-10-28T12:00:09Z","record":"pause"}` + "\n"},
		{"record without time", `{"record":"start"}` + "\n"},
		{"case variant", "<S>\n" + `{"time":"2026-10-28T12:00:09Z","Record":"stop","healthy":true}` + "\n"},
	} {
		file := func(ev string) string {
			return strings.NewReplacer("<S>", netStart, "<T>", netStop, "<E>", ev).Replace(tc.in)
		}
		el, eErr := ReadLog(strings.NewReader(file(execLine)))
		nl, nErr := ReadNetworkLog(strings.NewReader(file(netLine)))
		if (eErr == nil) != (nErr == nil) || (eErr != nil && eErr.Error() != nErr.Error()) {
			t.Errorf("%s: read errors differ:\n exec %v\n net  %v", tc.name, eErr, nErr)
			continue
		}
		if eErr != nil {
			continue
		}
		eh, nh := el.Health(), nl.Health()
		norm := func(err error) string {
			if err == nil {
				return ""
			}
			return strings.Replace(err.Error(), "a connection attempt", "an exec", 1)
		}
		if norm(eh) != norm(nh) {
			t.Errorf("%s: health differs:\n exec %v\n net  %v", tc.name, eh, nh)
		}
	}
}

// Each file refuses case variants of its own fields: a network key in an
// exec file, or an exec key in a network file, is an unknown field.
func TestEachFileKnowsItsOwnKeys(t *testing.T) {
	net := netStart + "\n" + `{"time":"2026-10-28T12:00:01Z","dest":"192.0.2.1:9","PPID":3,"trace_id":"` + traceA + `"}` + "\n" + netStop + "\n"
	if _, err := ReadNetworkLog(strings.NewReader(net)); err != nil {
		t.Fatalf("PPID is not a network field: %v", err)
	}
	if _, err := ReadNetworkLog(strings.NewReader(strings.Replace(net, "PPID", "Sock_Type", 1))); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("Sock_Type is sock_type in another case: %v", err)
	}
}

// Lines without a trace ID (written with -all) belong to no session, and an
// attempt with no readable fields is still an attempt.
func TestDialedDoesNotFilterOnWhatTheApplicationControls(t *testing.T) {
	in := netStart + "\n" + `{"time":"2026-10-28T12:00:01Z","op":"","protocol":"","dest":"0.0.0.0:0","pid":0,"host_pid":0,"comm":"","sock_type":0,"cgroup_id":0,"cgroup":"","trace_id":"` + traceA + `","attribution":"cgroup"}` + "\n" + netStop + "\n"
	log, err := ReadNetworkLog(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(log.Dialed(traceA)); n != 1 {
		t.Fatalf("want the attempt, got %d", n)
	}
}

// The schema is the contract other languages read; NetLine and Record are
// what the witness writes. They must name the same fields, with the same
// ones required: NetLine's in the schema's else branch, Record's in its then
// branch. Record's properties match the exec schema's word for word.
func TestNetLineMatchesTheSchema(t *testing.T) {
	type branch struct {
		Required []string `json:"required"`
	}
	type schemaDoc struct {
		Properties           map[string]map[string]any `json:"properties"`
		AdditionalProperties *bool                     `json:"additionalProperties"`
		If                   branch                    `json:"if"`
		Then                 branch                    `json:"then"`
		Else                 branch                    `json:"else"`
	}
	load := func(path string) schemaDoc {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var s schemaDoc
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	schema := load("../../docs/witness-network-event.schema.json")
	execSchema := load("../../docs/witness-event.schema.json")
	if schema.AdditionalProperties == nil || !*schema.AdditionalProperties {
		t.Error("the schema must allow additional properties: readers ignore fields they do not know")
	}
	if !reflect.DeepEqual(schema.If.Required, []string{"record"}) {
		t.Errorf("a line is a record exactly when it has a record field; if = %v", schema.If.Required)
	}
	fieldsOf := func(v any) (fields, required []string) {
		lt := reflect.TypeOf(v)
		for i := 0; i < lt.NumField(); i++ {
			name, opts, _ := strings.Cut(lt.Field(i).Tag.Get("json"), ",")
			fields = append(fields, name)
			if opts != "omitempty" {
				required = append(required, name)
			}
		}
		sort.Strings(required)
		return fields, required
	}
	lineFields, lineReq := fieldsOf(NetLine{})
	recFields, recReq := fieldsOf(Record{})
	all := map[string]bool{}
	for _, f := range append(lineFields, recFields...) {
		all[f] = true
	}
	var fields, props []string
	for f := range all {
		fields = append(fields, f)
	}
	for p := range schema.Properties {
		props = append(props, p)
	}
	sort.Strings(fields)
	sort.Strings(props)
	sort.Strings(schema.Then.Required)
	sort.Strings(schema.Else.Required)
	if !reflect.DeepEqual(fields, props) {
		t.Errorf("fields:\n NetLine+Record %v\n schema         %v", fields, props)
	}
	if !reflect.DeepEqual(lineReq, schema.Else.Required) {
		t.Errorf("attempt line required:\n NetLine %v\n schema  %v", lineReq, schema.Else.Required)
	}
	if !reflect.DeepEqual(recReq, schema.Then.Required) {
		t.Errorf("record required:\n Record %v\n schema %v", recReq, schema.Then.Required)
	}
	for _, f := range recFields {
		if !reflect.DeepEqual(schema.Properties[f], execSchema.Properties[f]) && f != "time" {
			t.Errorf("record field %s differs from the exec schema's", f)
		}
	}
}
