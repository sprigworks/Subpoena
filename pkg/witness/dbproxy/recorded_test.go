//subpoena:impl_derived
//subpoena:pure_logic

// Bytes recorded from real servers, replayed through the frame parsers:
// postgres:17 and mysql:8.4, with pgx, psql, go-sql-driver and the mysql client.
// The live package writes them: SUBPOENA_DB_RECORD=pkg/witness/dbproxy/testdata
// go test -run 'Recorded|PsqlClient|CommandLineClient$' ./pkg/witness/dbproxy/live
// mysql-cli negotiates CLIENT_DEPRECATE_EOF and query attributes; the driver
// session does neither. The password in them is the live tests' throwaway.
package dbproxy

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// replay feeds a transcript through w, merging consecutive reads in one direction
// so that no message is split.
func replay(t *testing.T, w *wire, name string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	var dir string
	var run []byte
	flush := func() {
		switch dir {
		case "C":
			w.client(run)
		case "S":
			w.server(run)
		}
		run = nil
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		d, data, ok := strings.Cut(line, " ")
		chunk, err := hex.DecodeString(data)
		if !ok || err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		if d != dir {
			flush()
			dir = d
		}
		run = append(run, chunk...)
	}
	flush()
}

func TestRecordedSessions(t *testing.T) {
	session := []string{"committed INSERT", "committed INSERT", "committed INSERT",
		"rolled_back UPDATE", "committed DELETE", "failed INSERT"}
	for _, tc := range []struct {
		name string
		wire func(*testing.T) *wire
		want []string
	}{
		{"postgres-pgx", newPG, session},
		{"mysql-driver", newMy, session},
		{"postgres-psql", newPG, []string{"rolled_back INSERT", "committed INSERT"}},
		{"mysql-cli", newMy, []string{"rolled_back INSERT", "committed INSERT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.wire(t)
			replay(t, w, tc.name)
			if w.err != nil {
				t.Fatalf("stopped reading: %v", w.err)
			}
			w.s.finish()
			w.want(tc.want...)
			w.healthy()
		})
	}
}

// What was recorded came through a witness, so the client's bytes say no TLS; the
// server's greeting still offers it, and the witness takes it out again here.
func TestRecordedGreetingLosesTLS(t *testing.T) {
	for _, name := range []string{"mysql-driver", "mysql-cli"} {
		w := newMy(t)
		b, err := os.ReadFile(filepath.Join("testdata", name+".hex"))
		if err != nil {
			t.Fatal(err)
		}
		first, _, _ := strings.Cut(string(b), "\n")
		greeting, err := hex.DecodeString(strings.TrimPrefix(first, "S "))
		if err != nil {
			t.Fatal(err)
		}
		if greetingCaps(t, greeting)&capSSL == 0 {
			t.Fatalf("%s: the recorded server did not offer TLS", name)
		}
		w.server(greeting)
		if got := greetingCaps(t, w.back.Bytes()); got&capSSL != 0 {
			t.Fatalf("%s: caps %#x", name, got)
		}
		if bytes.Equal(w.back.Bytes(), greeting) {
			t.Fatal("the greeting was not changed")
		}
	}
}
