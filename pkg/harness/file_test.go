//subpoena:spec_derived
//subpoena:pure_logic

// The file absence checks, from the brief's "same API shape" note and the W5
// and W6 rules in docs/ports.md: a sighting is Fail even from a bad capture,
// and silence is Pass only from a healthy, stopped one. Written before the
// implementation.
package harness

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

type unknownFile struct {
	events []witness.FileEvent
	roots  []string
	silent []string
}

func (w unknownFile) Wrote(string) []witness.FileEvent { return w.events }
func (w unknownFile) Roots() []string                  { return w.roots }
func (w unknownFile) SilentCloses() []string           { return w.silent }
func (w unknownFile) Covers(path string) bool {
	for _, r := range w.roots {
		if (witness.FileEvent{Path: path}).Within(r) {
			return true
		}
	}
	return false
}

type healthFile struct {
	unknownFile
	err     error
	stopped *int
}

func (w healthFile) Health() error { return w.err }
func (w healthFile) Stop() {
	if w.stopped != nil {
		*w.stopped++
	}
}

func wroteTo(paths ...string) unknownFile {
	w := unknownFile{roots: []string{"/r"}}
	for _, p := range paths {
		w.events = append(w.events, witness.FileEvent{Op: witness.FileWrite, Path: p, Attribution: witness.ByRoot})
	}
	return w
}

func TestNoWriteNeedsHealthyCapture(t *testing.T) {
	gap := errors.New("queue overflowed")
	for _, tc := range []struct {
		name  string
		w     witness.FileWitness
		paths []string
		want  Verdict
	}{
		{"healthy, nothing seen", healthFile{unknownFile: wroteTo()}, nil, Pass},
		{"unhealthy, nothing seen", healthFile{unknownFile: wroteTo(), err: gap}, nil, Inconclusive},
		{"no health, nothing seen", wroteTo(), nil, Inconclusive},
		{"healthy, write seen", healthFile{unknownFile: wroteTo("/r/x")}, nil, Fail},
		{"unhealthy, write seen", healthFile{unknownFile: wroteTo("/r/x"), err: gap}, nil, Fail},
		{"seen elsewhere", healthFile{unknownFile: wroteTo("/r/allowed")}, []string{"/r/secret"}, Pass},
		{"seen elsewhere, unhealthy", healthFile{unknownFile: wroteTo("/r/allowed"), err: gap}, []string{"/r/secret"}, Inconclusive},
		{"seen there", healthFile{unknownFile: wroteTo("/r/secret")}, []string{"/r/secret"}, Fail},
		{"seen below", healthFile{unknownFile: wroteTo("/r/secret/deep")}, []string{"/r/secret"}, Fail},
		{"one of several", healthFile{unknownFile: wroteTo("/r/b")}, []string{"/r/a", "/r/b"}, Fail},
		// A path the witness never watched can never be seen: a typo, or a
		// spelling through a symlink, must not read as a pass.
		{"not watched", healthFile{unknownFile: wroteTo()}, []string{"/elsewhere/x"}, Inconclusive},
		{"one not watched", healthFile{unknownFile: wroteTo()}, []string{"/r/a", "/elsewhere/x"}, Inconclusive},
		{"relative", healthFile{unknownFile: wroteTo()}, []string{"x"}, Inconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NoWrite(tc.w, "trace", tc.paths...)
			if got != tc.want || (err == nil) != (got == Pass) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
			fatal, _ := runRequire(func(tb testing.TB) { RequireNoWrite(tb, tc.w, "trace", tc.paths...) })
			if (fatal != "") != (tc.want != Pass) {
				t.Fatalf("RequireNoWrite fatal = %q", fatal)
			}
			f := &cleanupTB{}
			if CheckNoWrite(f, tc.w, "trace", tc.paths...) != (tc.want == Pass) || f.failed != (tc.want != Pass) {
				t.Fatalf("CheckNoWrite: failed=%v errs=%v", f.failed, f.errs)
			}
			if tc.want == Fail && !strings.HasPrefix(f.errs[0], TagWitness+":") {
				t.Fatalf("a sighting is witness evidence: %v", f.errs)
			}
			if tc.want == Inconclusive && !strings.HasPrefix(f.errs[0], TagInconclusive+":") {
				t.Fatalf("a blind witness is not evidence: %v", f.errs)
			}
		})
	}
}

// A rename of a directory above the path moved it with no event naming it.
// Round 2 review 6, M2: a witness with no roots watched nothing.
func TestNoRootsIsNeverPass(t *testing.T) {
	none := healthFile{}
	if v, err := NoWrite(none, "trace"); v != Inconclusive {
		t.Fatalf("no paths: %v, %v", v, err)
	}
	for _, rule := range []WriteRule{{}, {Allowed: []string{}}} {
		f := &cleanupTB{}
		if checkWrites(f, none, "trace", rule) {
			t.Fatalf("%+v passed", rule)
		}
		if len(f.errs) != 1 || !strings.HasPrefix(f.errs[0], TagInconclusive+":") {
			t.Fatalf("%+v: %v", rule, f.errs)
		}
	}
	saw := healthFile{unknownFile: unknownFile{events: wroteTo("/r/x").events}}
	if v, _ := NoWrite(saw, "trace"); v != Fail {
		t.Fatalf("an event stands with no roots: %v", v)
	}
}

// Round 2 review 6, H4: closed with no write seen is all a change by mmap or
// native AIO may leave, so no absence rests on that file.
func TestASilentCloseIsNeverPass(t *testing.T) {
	silent := wroteTo()
	silent.silent = []string{"/r/dir/secret"}
	w := healthFile{unknownFile: silent}
	for _, tc := range []struct {
		name  string
		paths []string
		want  Verdict
	}{
		{"the file", []string{"/r/dir/secret"}, Inconclusive},
		{"its directory", []string{"/r/dir"}, Inconclusive},
		{"anything", nil, Inconclusive},
		{"another file", []string{"/r/dir/other"}, Pass},
	} {
		if v, err := NoWrite(w, "trace", tc.paths...); v != tc.want {
			t.Errorf("%s: %v, %v", tc.name, v, err)
		}
	}
	seen := healthFile{unknownFile: unknownFile{roots: []string{"/r"}, silent: silent.silent, events: wroteTo("/r/dir/secret").events}}
	if v, _ := NoWrite(seen, "trace", "/r/dir/secret"); v != Fail {
		t.Fatalf("a write seen stands: %v", v)
	}
	for _, tc := range []struct {
		name string
		rule WriteRule
		want bool
	}{
		{"never", WriteRule{Never: []string{"/r/dir"}}, false},
		{"not allowed", WriteRule{Allowed: []string{"/r/log"}}, false},
		{"allowed", WriteRule{Allowed: []string{"/r/dir"}}, true},
		{"no rule on it", WriteRule{Never: []string{"/r/log"}}, true},
	} {
		if got := checkWrites(&cleanupTB{}, w, "trace", tc.rule); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

func TestNoWriteCountsARenameAboveThePath(t *testing.T) {
	w := healthFile{unknownFile: unknownFile{roots: []string{"/r"}, events: []witness.FileEvent{
		{Op: witness.FileRename, Path: "/r/dir", IsDir: true, Rename: witness.RenameFrom},
	}}}
	if v, _ := NoWrite(w, "t", "/r/dir/secret"); v != Fail {
		t.Fatalf("got %v", v)
	}
}

func TestWatchWritesRunsAfterAnEarlierFatal(t *testing.T) {
	stops := 0
	w := healthFile{unknownFile: wroteTo("/r/secret"), stopped: &stops}
	f := &cleanupTB{}
	f.run(func(tb testing.TB) {
		WatchWrites(tb, w, "trace", WriteRule{Never: []string{"/r/secret"}})
		tb.Fatalf("the test failed on something else first")
	})
	if stops != 1 {
		t.Fatalf("stops = %d", stops)
	}
	if !strings.Contains(strings.Join(f.errs, "\n"), TagWitness+":") {
		t.Fatalf("errs %v", f.errs)
	}
}

func TestWriteRule(t *testing.T) {
	gap := errors.New("gap")
	for _, tc := range []struct {
		name         string
		w            witness.FileWitness
		rule         WriteRule
		ok           bool
		tag          string
		wantLogMatch string
	}{
		{name: "nothing seen", w: healthFile{unknownFile: wroteTo()}, rule: WriteRule{Never: []string{"/r/x"}}, ok: true},
		{name: "never, seen", w: healthFile{unknownFile: wroteTo("/r/x")}, rule: WriteRule{Never: []string{"/r/x"}}, tag: TagWitness},
		{name: "never beats allowed", w: healthFile{unknownFile: wroteTo("/r/x")}, rule: WriteRule{Allowed: []string{"/r"}, Never: []string{"/r/x"}}, tag: TagWitness},
		{name: "allowed", w: healthFile{unknownFile: wroteTo("/r/log/a")}, rule: WriteRule{Allowed: []string{"/r/log"}}, ok: true},
		{name: "not allowed", w: healthFile{unknownFile: wroteTo("/r/data")}, rule: WriteRule{Allowed: []string{"/r/log"}}, tag: TagWitness},
		{name: "empty allow list allows none", w: healthFile{unknownFile: wroteTo("/r/data")}, rule: WriteRule{Allowed: []string{}}, tag: TagWitness},
		{name: "nil allow list", w: healthFile{unknownFile: wroteTo("/r/data")}, rule: WriteRule{}, ok: true},
		{name: "unhealthy", w: healthFile{unknownFile: wroteTo(), err: gap}, rule: WriteRule{}, tag: TagInconclusive},
		{name: "no health", w: wroteTo(), rule: WriteRule{}, tag: TagInconclusive},
		{name: "never not watched", w: healthFile{unknownFile: wroteTo()}, rule: WriteRule{Never: []string{"/else/x"}}, tag: TagInconclusive},
		{name: "allowed not watched", w: healthFile{unknownFile: wroteTo()}, rule: WriteRule{Allowed: []string{"/else/x"}}, tag: TagInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &cleanupTB{}
			ok := checkWrites(f, tc.w, "trace", tc.rule)
			if ok != tc.ok || f.failed == tc.ok {
				t.Fatalf("ok=%v failed=%v errs=%v", ok, f.failed, f.errs)
			}
			if tc.tag != "" && !strings.HasPrefix(f.errs[0], tc.tag+":") {
				t.Fatalf("errs %v, want tag %s", f.errs, tc.tag)
			}
		})
	}
}

// A file opened for writing and closed with no write seen may have changed by mmap
// or native AIO, so a rule on that path can't pass, and a rule elsewhere isn't touched.
func TestWatchWritesSilentCloseOnAClaimedPath(t *testing.T) {
	silent := wroteTo()
	silent.silent = []string{"/r/x"}
	for _, tc := range []struct {
		name string
		rule WriteRule
		ok   bool
	}{
		{name: "never", rule: WriteRule{Never: []string{"/r/x"}}},
		{name: "not allowed", rule: WriteRule{Allowed: []string{"/r/log"}}},
		{name: "allowed", rule: WriteRule{Allowed: []string{"/r/x"}}, ok: true},
		{name: "no claim on it", rule: WriteRule{Never: []string{"/r/y"}}, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &cleanupTB{}
			ok := checkWrites(f, healthFile{unknownFile: silent}, "trace", tc.rule)
			if ok != tc.ok || f.failed == tc.ok {
				t.Fatalf("ok=%v failed=%v errs=%v", ok, f.failed, f.errs)
			}
			if !tc.ok && !strings.HasPrefix(f.errs[0], TagInconclusive+":") {
				t.Fatalf("errs %v, want tag %s", f.errs, TagInconclusive)
			}
		})
	}
}

// After another failure every write is logged, so the evidence is on the page.
func TestWatchWritesLogsWhatItSawAfterAFailure(t *testing.T) {
	f := &cleanupTB{failed: true}
	checkWrites(f, healthFile{unknownFile: wroteTo("/r/x")}, "trace", WriteRule{})
	if !strings.Contains(strings.Join(f.logs, "\n"), "/r/x") {
		t.Fatalf("logs %v", f.logs)
	}
}

// End to end: a real witness, and another process doing the writing.
func TestRequireNoWriteAgainstARealWitness(t *testing.T) {
	root := t.TempDir()
	w, err := witness.NewFileWatch(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, audit := filepath.Join(root, "secret"), filepath.Join(root, "audit")
	if out, err := exec.Command("sh", "-c", "echo denied >> "+audit).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	RequireNoWrite(t, w, "trace", secret)
	if v, _ := NoWrite(w, "trace", audit); v != Fail {
		t.Fatalf("the audit write went unseen: %v", v)
	}
	// Removing the root leaves silence that proves nothing.
	w2, err := witness.NewFileWatch(filepath.Dir(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	w2.Stop()
	if v, err := NoWrite(w2, "trace", filepath.Join(root, "other")); v != Inconclusive {
		t.Fatalf("got %v, %v", v, err)
	}
}
