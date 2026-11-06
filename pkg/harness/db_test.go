//subpoena:spec_derived
//subpoena:pure_logic

// From the round 2 brief ("New witnesses": same API shape, Inconclusive is first
// class) and docs/ports.md W5/W6: a sighting is Fail even from an unhealthy
// capture; with none, missing or bad health is Inconclusive. There is no
// telemetry here.
package harness

import (
	"errors"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

type unknownDB struct{ events []witness.RowEvent }

func (w unknownDB) Committed(string) []witness.RowEvent { return w.events }

type healthDB struct {
	unknownDB
	err error
}

func (w healthDB) Health() error { return w.err }

// reported runs body as a test function and returns what it reported.
func reported(body func(tb testing.TB)) []string {
	f := &cleanupTB{}
	f.run(body)
	return f.errs
}

func row(table string, rows int64) witness.RowEvent {
	return witness.RowEvent{Tables: []string{table}, Rows: rows, Outcome: witness.OutcomeCommitted, Attribution: witness.ByDestination}
}

func opaque() witness.RowEvent {
	return witness.RowEvent{Opaque: true, Reason: "unparsed", Rows: witness.RowsUnknown, Outcome: witness.OutcomeCommitted}
}

func TestNoRowNeedsHealthyCapture(t *testing.T) {
	gap := errors.New("frame unreadable")
	seen := func(e ...witness.RowEvent) unknownDB { return unknownDB{e} }
	for _, tc := range []struct {
		name  string
		w     witness.DBWitness
		table string
		want  Verdict
	}{
		{"healthy empty", healthDB{}, "users", Pass},
		{"unhealthy empty", healthDB{err: gap}, "users", Inconclusive},
		{"no health reported", unknownDB{}, "users", Inconclusive},
		{"committed", healthDB{unknownDB: seen(row("users", 1))}, "users", Fail},
		{"committed, unhealthy", healthDB{seen(row("users", 1)), gap}, "users", Fail},
		{"other table", healthDB{unknownDB: seen(row("orders", 1))}, "users", Pass},
		{"other table, unhealthy", healthDB{seen(row("orders", 1)), gap}, "users", Inconclusive},
		{"opaque counts against every table", healthDB{unknownDB: seen(opaque())}, "users", Fail},
		{"zero rows is no row", healthDB{unknownDB: seen(row("users", 0))}, "users", Pass},
		{"unknown count is a row", healthDB{unknownDB: seen(row("users", witness.RowsUnknown))}, "users", Fail},
		{"empty table means any", healthDB{unknownDB: seen(row("orders", 1))}, "", Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NoRow(tc.w, "trace", tc.table)
			if got != tc.want || (err == nil) != (got == Pass) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			errs := reported(func(tb testing.TB) { RequireNoRow(tb, tc.w, "trace", tc.table) })
			if (len(errs) == 0) != (got == Pass) {
				t.Fatalf("RequireNoRow reported %q for %v", errs, got)
			}
			if got == Fail && !strings.HasPrefix(errs[0], TagWitness+":") {
				t.Fatalf("a sighting must read as witness evidence: %q", errs)
			}
			if got == Inconclusive && !strings.HasPrefix(errs[0], TagInconclusive+":") {
				t.Fatalf("a blind witness must not read as a sighting: %q", errs)
			}
		})
	}
}

// A failed Committed row that was rolled back never reaches here: Committed
// leaves it out. This holds the harness to Effect, for a witness that returns
// more than it should.
func TestNoRowIgnoresWhatDidNotCommit(t *testing.T) {
	e := row("users", 1)
	e.Outcome = witness.OutcomeRolledBack
	if v, err := NoRow(healthDB{unknownDB: unknownDB{[]witness.RowEvent{e}}}, "trace", "users"); v != Pass {
		t.Fatalf("got %v, %v", v, err)
	}
}

func TestCheckNoRowDoesNotStopTheTest(t *testing.T) {
	w := healthDB{unknownDB: unknownDB{[]witness.RowEvent{row("users", 1)}}}
	var ok, wentOn bool
	errs := reported(func(tb testing.TB) { ok = CheckNoRow(tb, w, "trace", "users"); wentOn = true })
	if ok || !wentOn || len(errs) != 1 {
		t.Fatalf("ok %v, went on %v, errors %q", ok, wentOn, errs)
	}
	errs = reported(func(tb testing.TB) { ok = CheckNoRow(tb, healthDB{}, "trace", "users") })
	if !ok || len(errs) != 0 {
		t.Fatalf("clean: ok %v, errors %q", ok, errs)
	}
}

type stoppableDB struct {
	healthDB
	stopped *bool
}

func (w stoppableDB) Stop() error { *w.stopped = true; return nil }

func TestWatchRowsRule(t *testing.T) {
	gap := errors.New("frame unreadable")
	for _, tc := range []struct {
		name   string
		events []witness.RowEvent
		health error
		rule   RowRule
		errTag string // "" if the check must pass
	}{
		{"nothing committed", nil, nil, RowRule{Never: []string{"users"}}, ""},
		{"refused table", []witness.RowEvent{row("users", 1)}, nil, RowRule{Never: []string{"users"}}, TagWitness},
		{"unrefused table", []witness.RowEvent{row("orders", 1)}, nil, RowRule{Never: []string{"users"}}, ""},
		{"never beats allowed", []witness.RowEvent{row("users", 1)}, nil, RowRule{Allowed: []string{"users"}, Never: []string{"users"}}, TagWitness},
		{"allowed table", []witness.RowEvent{row("audit", 1)}, nil, RowRule{Allowed: []string{"audit"}}, ""},
		{"not allowed", []witness.RowEvent{row("users", 1)}, nil, RowRule{Allowed: []string{"audit"}}, TagWitness},
		{"empty allow list allows none", []witness.RowEvent{row("users", 1)}, nil, RowRule{Allowed: []string{}}, TagWitness},
		{"opaque against never", []witness.RowEvent{opaque()}, nil, RowRule{Never: []string{"users"}}, TagWitness},
		{"opaque is not allowed", []witness.RowEvent{opaque()}, nil, RowRule{Allowed: []string{"audit"}}, TagWitness},
		{"zero rows pass an allow list", []witness.RowEvent{row("users", 0)}, nil, RowRule{Allowed: []string{}}, ""},
		{"one of several not allowed", []witness.RowEvent{{Tables: []string{"audit", "users"}, Rows: 1, Outcome: witness.OutcomeCommitted}}, nil, RowRule{Allowed: []string{"audit"}}, TagWitness},
		{"unhealthy", nil, gap, RowRule{Never: []string{"users"}}, TagInconclusive},
		{"no rule still needs health", nil, gap, RowRule{}, TagInconclusive},
		{"no rule, a write is logged", []witness.RowEvent{row("users", 1)}, nil, RowRule{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopped := false
			w := stoppableDB{healthDB{unknownDB{tc.events}, tc.health}, &stopped}
			var ok bool
			errs := reported(func(tb testing.TB) { ok = checkRows(tb, w, "trace", tc.rule) })
			if !stopped {
				t.Fatal("the check must stop the witness before reading it")
			}
			if tc.errTag == "" {
				if !ok || len(errs) != 0 {
					t.Fatalf("ok %v, errors %q", ok, errs)
				}
				return
			}
			if ok || len(errs) == 0 || !strings.HasPrefix(errs[0], tc.errTag+":") {
				t.Fatalf("ok %v, errors %q, want tag %s", ok, errs, tc.errTag)
			}
		})
	}
	t.Run("no health reported", func(t *testing.T) {
		var ok bool
		errs := reported(func(tb testing.TB) { ok = checkRows(tb, unknownDB{}, "trace", RowRule{}) })
		if ok || len(errs) != 1 || !strings.HasPrefix(errs[0], TagInconclusive+":") {
			t.Fatalf("ok %v, errors %q", ok, errs)
		}
	})
}

func TestWatchRowsRunsAtCleanup(t *testing.T) {
	stopped := false
	errs := reported(func(tb testing.TB) {
		WatchRows(tb, stoppableDB{healthDB{unknownDB: unknownDB{[]witness.RowEvent{row("users", 1)}}}, &stopped}, "trace", RowRule{Never: []string{"users"}})
		if stopped {
			t.Fatal("ran before cleanup")
		}
		tb.Fatalf("an earlier failure must not stop the check")
	})
	if !stopped || len(errs) != 2 || !strings.HasPrefix(errs[1], TagWitness+":") {
		t.Fatalf("stopped %v, errors %q", stopped, errs)
	}
}
