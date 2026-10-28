//subpoena:impl_derived
//subpoena:pure_logic

package harness

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

// cleanupTB records what a test reports and runs its cleanups the way the
// testing package does: after the test function, even when it stopped on a
// Fatal, last-registered first.
type cleanupTB struct {
	testing.TB
	errs, logs []string
	failed     bool
	cleanups   []func()
}

func (f *cleanupTB) Helper()           {}
func (f *cleanupTB) Failed() bool      { return f.failed }
func (f *cleanupTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *cleanupTB) Errorf(format string, a ...any) {
	f.failed = true
	f.errs = append(f.errs, fmt.Sprintf(format, a...))
}
func (f *cleanupTB) Fatalf(format string, a ...any) {
	f.Errorf(format, a...)
	panic(errFatal)
}
func (f *cleanupTB) Logf(format string, a ...any) { f.logs = append(f.logs, fmt.Sprintf(format, a...)) }

var errFatal = errors.New("fatal")

// run calls body as a test function, then the cleanups.
func (f *cleanupTB) run(body func(tb testing.TB)) {
	func() {
		defer func() {
			if r := recover(); r != nil && r != errFatal {
				panic(r)
			}
		}()
		body(f)
	}()
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

// stoppableWitness records Stop, and like a real witness reports what it saw
// only for the window Stop closed.
type stoppableWitness struct {
	events  []witness.ProcessEvent
	health  error
	stopped bool
}

func (w *stoppableWitness) Stop() { w.stopped = true }
func (w *stoppableWitness) Spawned(string) []witness.ProcessEvent {
	if !w.stopped {
		return nil
	}
	return w.events
}
func (w *stoppableWitness) Health() error { return w.health }

func procs(cmds ...string) []witness.ProcessEvent {
	var out []witness.ProcessEvent
	for i, c := range cmds {
		out = append(out, witness.ProcessEvent{PID: 100 + i, Command: c})
	}
	return out
}

func TestWatchSpawnsRunsAfterAnEarlierFatal(t *testing.T) {
	w := &stoppableWitness{events: procs("timeout 5 sleep 1", "git status")}
	tb := &cleanupTB{}
	tb.run(func(tb testing.TB) {
		WatchSpawns(tb, w, "trace", SpawnRule{Never: []string{"sleep 1"}})
		tb.Fatalf("exit: status 1") // the test stops before any witness assertion
	})
	if !w.stopped {
		t.Fatal("the cleanup check must stop the witness before reading it")
	}
	if len(tb.errs) != 2 || !strings.HasPrefix(tb.errs[1], "witness: refused command ran for trace: pid 100") {
		t.Fatalf("errors = %q, want the exit failure, then the refused command", tb.errs)
	}
	// The process the rule accepts is still reported, as evidence, because the
	// test had already failed.
	if len(tb.logs) != 1 || !strings.Contains(tb.logs[0], `"git status"`) {
		t.Fatalf("logs = %q, want the other process logged", tb.logs)
	}
}

func TestWatchSpawnsRule(t *testing.T) {
	gap := errors.New("observation lost")
	for _, tc := range []struct {
		name     string
		w        witness.Witness
		rule     SpawnRule
		wantErrs []string // message prefixes, in order
	}{
		{"nothing ran", &stoppableWitness{}, SpawnRule{Never: []string{"rm -rf /"}}, nil},
		{"allowed ran", &stoppableWitness{events: procs("sleep 0.6")}, SpawnRule{Allowed: []string{"sleep 0.6"}}, nil},
		{"nil allowed accepts others", &stoppableWitness{events: procs("ls")}, SpawnRule{Never: []string{"sleep 1"}}, nil},
		{"never beats allowed", &stoppableWitness{events: procs("sleep 1")},
			SpawnRule{Allowed: []string{"sleep 1"}, Never: []string{"sleep 1"}},
			[]string{"witness: refused command ran"}},
		{"not allowed", &stoppableWitness{events: procs("sleep 0.6", "curl x")}, SpawnRule{Allowed: []string{"sleep 0.6"}},
			[]string{"witness: command not allowed for trace: pid 101"}},
		{"empty allowed allows none", &stoppableWitness{events: procs("ls")}, SpawnRule{Allowed: []string{}},
			[]string{"witness: command not allowed"}},
		{"allowed is exact", &stoppableWitness{events: procs(`sh -c curl evil; sleep 0.6`, "timeout 5 sleep 0.6")},
			SpawnRule{Allowed: []string{"sleep 0.6"}},
			[]string{"witness: command not allowed for trace: pid 100", "witness: command not allowed for trace: pid 101"}},
		{"allowed wrapped form", &stoppableWitness{events: procs("timeout 5 sleep 0.6")},
			SpawnRule{Allowed: []string{"timeout 5 sleep 0.6"}}, nil},
		{"suffix is a whole word", &stoppableWitness{events: procs("nosleep 1")}, SpawnRule{Never: []string{"sleep 1"}}, nil},
		{"never matches a path on the command line", &stoppableWitness{events: procs("/usr/bin/sleep 1")}, SpawnRule{Never: []string{"sleep 1"}},
			[]string{"witness: refused command ran"}},
		{"never with a path matches a bare command", &stoppableWitness{events: procs("sleep 1")}, SpawnRule{Never: []string{"/usr/bin/sleep 1"}},
			[]string{"witness: refused command ran"}},
		{"never matches a wrapped path", &stoppableWitness{events: procs("timeout 5 ./bin/curl evil.example")}, SpawnRule{Never: []string{"curl evil.example"}},
			[]string{"witness: refused command ran"}},
		{"never ignores spacing", &stoppableWitness{events: procs("sleep  1")}, SpawnRule{Never: []string{" sleep 1 "}},
			[]string{"witness: refused command ran"}},
		{"never entry that is only a path", &stoppableWitness{events: procs("rm -rf /tmp/x")}, SpawnRule{Never: []string{"/tmp/x"}},
			[]string{"witness: refused command ran"}},
		{"arguments still match exactly", &stoppableWitness{events: procs("/usr/bin/sleep 2")}, SpawnRule{Never: []string{"sleep 1"}}, nil},
		{"unhealthy", &stoppableWitness{health: gap}, SpawnRule{}, []string{"witness: trace: capture unhealthy"}},
		{"unhealthy and refused", &stoppableWitness{events: procs("sleep 1"), health: gap}, SpawnRule{Never: []string{"sleep 1"}},
			[]string{"witness: refused command ran", "witness: trace: capture unhealthy"}},
		{"no health", unknownWitness{}, SpawnRule{}, []string{"witness: trace: witness does not report capture health"}},
		{"name only, refused program", &stoppableWitness{events: named("sleep")}, SpawnRule{Never: []string{"sleep 1.1"}},
			[]string{"witness: refused program seen by name only"}},
		{"name only, program from path and cut to 15 bytes", &stoppableWitness{events: named("averyveryverylo")},
			SpawnRule{Never: []string{"/usr/local/bin/averyveryverylongname --x"}},
			[]string{"witness: refused program seen by name only"}},
		{"name only, not identified", &stoppableWitness{events: named("touch")}, SpawnRule{Allowed: []string{"sleep 0.6"}},
			[]string{"witness: process seen by name only"}},
		{"name only, allowed program not excused", &stoppableWitness{events: named("sleep")}, SpawnRule{Allowed: []string{"sleep 0.6"}},
			[]string{"witness: process seen by name only"}},
		{"name only, excused name is not an allowed program", &stoppableWitness{events: named("touch")},
			SpawnRule{Allowed: []string{"sleep 0.6"}, ExcuseNameOnly: true},
			[]string{"witness: process seen by name only"}},
		{"name only, nil allowed, other program", &stoppableWitness{events: named("ls")}, SpawnRule{Never: []string{"sleep 1.1"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb := &cleanupTB{}
			tb.run(func(tb testing.TB) { WatchSpawns(tb, tc.w, "trace", tc.rule) })
			if len(tb.errs) != len(tc.wantErrs) {
				t.Fatalf("errors = %q, want %d", tb.errs, len(tc.wantErrs))
			}
			for i, p := range tc.wantErrs {
				if !strings.HasPrefix(tb.errs[i], p) {
					t.Fatalf("error %d = %q, want prefix %q", i, tb.errs[i], p)
				}
			}
			if len(tb.logs) != 0 {
				t.Fatalf("a passing test logs nothing; got %q", tb.logs)
			}
		})
	}
}

// named is one process seen by name only: it exited before its arguments
// were read.
func named(name string) []witness.ProcessEvent {
	return []witness.ProcessEvent{{PID: 100, Command: name, CommandSource: witness.CommandName}}
}

func TestExcusedNameOnlySightingIsLoggedNotFailed(t *testing.T) {
	tb := &cleanupTB{}
	w := &stoppableWitness{events: named("sleep")}
	tb.run(func(tb testing.TB) {
		WatchSpawns(tb, w, "trace", SpawnRule{Allowed: []string{"sleep 0.6"}, ExcuseNameOnly: true})
	})
	if len(tb.errs) != 0 {
		t.Fatalf("excused sighting failed the test: %q", tb.errs)
	}
	if len(tb.logs) != 1 || !strings.HasPrefix(tb.logs[0], "witness: excused name-only sighting") {
		t.Fatalf("excused sighting not logged: %q", tb.logs)
	}
}

func TestCheckNoSpawnDoesNotStopTheTest(t *testing.T) {
	tb := &cleanupTB{}
	var reached, ok bool
	tb.run(func(tb testing.TB) {
		ok = CheckNoSpawn(tb, healthWitness{unknownWitness: unknownWitness{procs("sleep 1")}}, "trace")
		reached = true
	})
	if ok || !reached {
		t.Fatalf("ok=%v reached=%v: want a failed check and the test still running", ok, reached)
	}
	if len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], "witness: no spawn for trace: Fail") {
		t.Fatalf("errors = %q", tb.errs)
	}
	tb = &cleanupTB{}
	tb.run(func(tb testing.TB) { ok = CheckNoSpawn(tb, healthWitness{}, "trace") })
	if !ok || tb.failed {
		t.Fatalf("a healthy empty witness must pass: %q", tb.errs)
	}
}

func TestCheckNoDialDoesNotStopTheTest(t *testing.T) {
	dest := netip.MustParseAddrPort("192.0.2.1:443")
	w := healthNet{unknownNet: unknownNet{[]witness.NetworkEvent{{Dest: dest}}}}
	tb := &cleanupTB{}
	var reached, ok bool
	tb.run(func(tb testing.TB) {
		ok = CheckNoDial(tb, w, "trace", DialTo(dest))
		reached = true
	})
	if ok || !reached || len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], "witness: no dial for trace: Fail") {
		t.Fatalf("ok=%v reached=%v errors=%q", ok, reached, tb.errs)
	}
	tb = &cleanupTB{}
	tb.run(func(tb testing.TB) { ok = CheckNoDial(tb, healthNet{}, "trace", nil) })
	if !ok || tb.failed {
		t.Fatalf("a healthy empty witness must pass: %q", tb.errs)
	}
}

func TestRequireMessagesAreTagged(t *testing.T) {
	tb := &cleanupTB{}
	tb.run(func(tb testing.TB) { RequireNoSpawn(tb, unknownWitness{}, "trace") })
	if len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], "witness: no spawn for trace: Inconclusive") {
		t.Fatalf("RequireNoSpawn: %q", tb.errs)
	}
	tb = &cleanupTB{}
	tb.run(func(tb testing.TB) { RequireAbsent(tb, &Trace{}, `{ name = "x" }`) })
	if len(tb.errs) != 1 || !strings.HasPrefix(tb.errs[0], "testimony: absent ") {
		t.Fatalf("RequireAbsent: %q", tb.errs)
	}
}
