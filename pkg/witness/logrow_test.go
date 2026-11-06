//subpoena:impl_derived
//subpoena:pure_logic

package witness

import (
	"strings"
	"testing"
)

const rowOK = `{"time":"2026-11-06T12:00:01Z","event":"row","engine":"postgres","conn":1,"dest":"127.0.0.1:5432","statement":"INSERT INTO users VALUES (1)","verb":"INSERT","tables":["users"],"opaque":false,"rows":1,"outcome":"committed","attribution":"destination"}`

func rowFile(lines ...string) string {
	return `{"time":"2026-11-06T12:00:00Z","record":"start","healthy":false}` + "\n" +
		strings.Join(lines, "\n") + "\n" + `{"time":"2026-11-06T12:00:09Z","record":"stop","healthy":true}` + "\n"
}

func TestReadLogRows(t *testing.T) {
	l, err := ReadLog(strings.NewReader(rowFile(rowOK,
		strings.Replace(rowOK, `"committed"`, `"rolled_back"`, 1),
		strings.Replace(rowOK, `"committed"`, `"read"`, 1))))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Health(); err != nil {
		t.Fatal(err)
	}
	if len(l.Rows()) != 3 || l.Len() != 0 {
		t.Fatalf("rows %d, execs %d", len(l.Rows()), l.Len())
	}
	for _, trace := range []string{"a", "b", ""} {
		got := l.Committed(trace)
		if len(got) != 1 || got[0].Rows != 1 || got[0].Tables[0] != "users" || got[0].Attribution != ByDestination || got[0].Dest.Port() != 5432 {
			t.Fatalf("trace %q: %+v", trace, got)
		}
	}
}

func TestReadLogRefusesRowsItCannotRead(t *testing.T) {
	for name, line := range map[string]string{
		"unknown event":          strings.Replace(rowOK, `"event":"row"`, `"event":"file"`, 1),
		"unknown outcome":        strings.Replace(rowOK, `"committed"`, `"maybe"`, 1),
		"no outcome":             strings.Replace(rowOK, `"outcome":"committed",`, ``, 1),
		"no time":                strings.Replace(rowOK, `"time":"2026-11-06T12:00:01Z",`, ``, 1),
		"no rows":                strings.Replace(rowOK, `"rows":1,`, ``, 1),
		"null rows":              strings.Replace(rowOK, `"rows":1`, `"rows":null`, 1),
		"impossible rows":        strings.Replace(rowOK, `"rows":1`, `"rows":-2`, 1),
		"rows of the wrong type": strings.Replace(rowOK, `"rows":1`, `"rows":"1"`, 1),
		"case variant":           strings.Replace(rowOK, `"outcome"`, `"Outcome"`, 1),
	} {
		if _, err := ReadLog(strings.NewReader(rowFile(line))); err == nil {
			t.Errorf("%s: read without error", name)
		}
	}
}

func TestReadLogRowFaults(t *testing.T) {
	outside := `{"time":"2026-11-06T12:00:00Z","record":"start","healthy":false}` + "\n" +
		`{"time":"2026-11-06T12:00:09Z","record":"stop","healthy":true}` + "\n" + rowOK + "\n"
	for name, file := range map[string]string{
		"outside a window": outside,
		"unknown outcome":  rowFile(strings.Replace(rowOK, `"committed"`, `"unknown"`, 1)),
	} {
		l, err := ReadLog(strings.NewReader(file))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if l.Health() == nil {
			t.Errorf("%s: healthy", name)
		}
	}
}
