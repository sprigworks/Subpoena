//subpoena:impl_derived

// Attribution and bookkeeping, fed synthetic kernel events: no eBPF, no
// privileges. kernel_linux_test.go loads the real program.
package execbpf

import (
	"reflect"
	"testing"

	"github.com/sprigworks/subpoena/pkg/witness"
)

const (
	tidA = "0af7651916cd43dd8448eb211c80319c"
	tidB = "4bf92f3577b34da6a3ce929d0e0e4736"
)

func execEv(pid, ppid int, cg string, args ...string) Event {
	return Event{Kind: KindExec, PID: pid, PPID: ppid, Cgroup: cg, Exe: "/usr/bin/" + args[0], Args: args, CgroupID: 42}
}

func forkEv(pid, ppid int, cg string) Event {
	return Event{Kind: KindFork, PID: pid, PPID: ppid, Cgroup: cg}
}

func TestSessionCgroupAttributesByTrace(t *testing.T) {
	w := New(Config{CgroupRoot: "/sys/fs/cgroup/subpoena"})
	w.handle(execEv(10, 1, "system.slice/docker-x.scope/subpoena/"+tidA, "sleep", "0.1"))
	w.handle(execEv(11, 1, "subpoena/"+tidB, "true"))
	w.handle(execEv(12, 1, "user.slice/session-1.scope", "ls")) // not a session: not kept
	w.handle(execEv(13, 1, "other/"+tidA, "true"))              // trace-shaped name under another root: not a session

	got := w.Spawned(tidA)
	if len(got) != 1 || got[0].PID != 10 || got[0].Attribution != witness.ByCgroup || got[0].TraceID != tidA {
		t.Fatalf("Spawned(A) = %+v", got)
	}
	if got[0].Command != "sleep 0.1" || got[0].CgroupID != 42 || got[0].Exe != "/usr/bin/sleep" {
		t.Fatalf("event fields not carried over: %+v", got[0])
	}
	if got := w.Spawned(tidB); len(got) != 1 || got[0].PID != 11 {
		t.Fatalf("Spawned(B) = %+v", got)
	}
	if n := len(w.Events()); n != 2 {
		t.Fatalf("kept %d events, want only the 2 attributed ones", n)
	}
}

func TestSessionFoundBelowNestedChildCgroup(t *testing.T) {
	// A process that moved itself into a child of its session cgroup is still
	// in the session.
	w := New(Config{CgroupRoot: "/x/subpoena"})
	w.handle(execEv(10, 1, "subpoena/"+tidA+"/escape", "sh"))
	if got := w.Spawned(tidA); len(got) != 1 {
		t.Fatalf("nested child cgroup lost the session: %+v", w.Events())
	}
}

func TestLineageFollowsForksAndIsReturnedForEveryTrace(t *testing.T) {
	w := New(Config{CgroupRoot: "/x/subpoena", RootPID: 100})
	w.handle(forkEv(101, 100, "user.slice"))             // gateway forks
	w.handle(execEv(101, 100, "user.slice", "sh"))       // and execs sh
	w.handle(forkEv(102, 101, "user.slice"))             // sh forks a subshell, no exec
	w.handle(execEv(103, 102, "user.slice", "sleep"))    // whose child execs: still a descendant
	w.handle(execEv(200, 1, "user.slice", "unrelated"))  // not a descendant
	w.handle(execEv(104, 101, "subpoena/"+tidB, "true")) // a descendant in B's session: cgroup wins

	if got := pids(w.Spawned(tidA)); !reflect.DeepEqual(got, []int{101, 103}) {
		t.Fatalf("Spawned(A) = %v, want the lineage-only execs [101 103]", got)
	}
	if got := pids(w.Spawned(tidB)); !reflect.DeepEqual(got, []int{101, 103, 104}) {
		t.Fatalf("Spawned(B) = %v", got)
	}
	for _, e := range w.Spawned(tidB) {
		if e.PID == 104 && e.Attribution != witness.ByCgroup {
			t.Fatalf("session cgroup must take precedence over lineage: %+v", e)
		}
	}
}

func TestNoLineageWithoutRootPID(t *testing.T) {
	w := New(Config{CgroupRoot: "/x/subpoena"})
	w.handle(execEv(101, 100, "user.slice", "sh"))
	if n := len(w.Events()); n != 0 {
		t.Fatalf("no RootPID, no session cgroup: nothing is attributable, got %d", n)
	}
}

func TestOnEventSeesEverythingAndNoRetainKeepsNothing(t *testing.T) {
	var seen []Event
	w := New(Config{CgroupRoot: "/x/subpoena", NoRetain: true, OnEvent: func(e Event) { seen = append(seen, e) }})
	w.handle(execEv(10, 1, "subpoena/"+tidA, "true"))
	w.handle(execEv(11, 1, "user.slice", "ls"))
	if len(seen) != 2 || seen[0].Attribution != witness.ByCgroup || seen[0].TraceID != tidA || seen[1].Attribution != "" {
		t.Fatalf("OnEvent got %+v", seen)
	}
	if n := len(w.Events()); n != 0 {
		t.Fatalf("NoRetain kept %d events", n)
	}
}

func TestSplitArgsAndCgroupPath(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"sleep\x000.1\x00", []string{"sleep", "0.1"}},
		{"sh\x00-c\x00\x00", []string{"sh", "-c", ""}},       // an empty argument survives
		{"trunc\x00ated-arg", []string{"trunc", "ated-arg"}}, // truncated copy: no final NUL
	}
	for _, c := range cases {
		if got := splitArgs([]byte(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Leaf first, as the kernel walks; the hierarchy root has an empty name.
	if got := cgroupPath([]string{tidA, "subpoena", "docker-x.scope", "system.slice", ""}); got != "system.slice/docker-x.scope/subpoena/"+tidA {
		t.Errorf("cgroupPath = %q", got)
	}
}

func pids(es []witness.ProcessEvent) []int {
	var out []int
	for _, e := range es {
		out = append(out, e.PID)
	}
	return out
}
