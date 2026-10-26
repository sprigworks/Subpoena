//subpoena:impl_derived

package cgroup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const tid = "0123456789abcdef0123456789abcdef"

// standIn builds a directory that mimics a cgroup v2 hierarchy closely enough
// for the write path: a root with cgroup.controllers. Create adds the
// cgroup.procs file that cgroupfs would have made.
func standIn(t *testing.T) *Manager {
	t.Helper()
	root := filepath.Join(t.TempDir(), "subpoena")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, controllersFile), "cpu memory pids\n")
	return &Manager{Root: root}
}

func mustWrite(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvRoot, "")
	if m := FromEnv(); m.Root != DefaultRoot {
		t.Fatalf("default root = %q", m.Root)
	}
	t.Setenv(EnvRoot, "/x/y/z")
	if m := FromEnv(); m.Root != "/x/y/z" || RootBase(m.Root) != "z" {
		t.Fatalf("env root = %+v", m)
	}
	if RootBase("/a/b/") != "b" {
		t.Fatal("RootBase must ignore a trailing slash")
	}
}

func TestCreateStartsProcessesInTheGroup(t *testing.T) {
	m := standIn(t)
	t.Setenv(EnvRoot, m.Root)
	g, err := m.Create(strings.ToUpper(tid))
	if err != nil {
		t.Fatal(err)
	}
	if g.TraceID() != tid || g.Dir() != filepath.Join(m.Root, tid) || g.Path() != "subpoena/"+tid || g.Real() {
		t.Fatalf("group = %+v path=%s", g, g.Path())
	}

	cmd, placeErr, err := g.Start(func() *exec.Cmd { return exec.Command("sleep", "0.1") })
	if err != nil || placeErr != nil {
		t.Fatalf("start err=%v placeErr=%v", err, placeErr)
	}
	defer cmd.Wait()
	procs, err := g.Procs()
	if err != nil || len(procs) != 1 || procs[0] != cmd.Process.Pid {
		t.Fatalf("cgroup.procs = %v (%v), want [%d]", procs, err, cmd.Process.Pid)
	}
	// The file holds one PID per line, as cgroupfs expects.
	raw, _ := os.ReadFile(filepath.Join(g.Dir(), procsFile))
	if string(raw) != fmt.Sprintf("%d\n", cmd.Process.Pid) {
		t.Fatalf("raw cgroup.procs = %q", raw)
	}
	if err := g.Remove(); err != nil {
		t.Fatalf("stand-in group must be removable: %v", err)
	}
	if _, err := os.Stat(g.Dir()); !os.IsNotExist(err) {
		t.Fatal("group directory still exists")
	}
}

func TestCreateIsIdempotentForTheSameTrace(t *testing.T) {
	m := standIn(t)
	if _, err := m.Create(tid); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(tid); err != nil {
		t.Fatalf("second Create for the same trace: %v", err)
	}
}

func TestCreateRefusesBadTraceIDs(t *testing.T) {
	m := standIn(t)
	for _, id := range []string{"", "abc", "../../../tmp/pwn", tid[:31], tid + "0", strings.Repeat("g", 32)} {
		if _, err := m.Create(id); err == nil {
			t.Errorf("Create(%q) must fail", id)
		}
	}
	if ents, _ := os.ReadDir(m.Root); len(ents) != 1 { // only cgroup.controllers
		t.Errorf("rejected IDs left entries behind: %v", ents)
	}
}

func TestCreateRefusesAPlainDirectoryRoot(t *testing.T) {
	// A root that exists but is not a cgroup (no cgroup.controllers): the
	// failure mode on cgroup v1 or hybrid hosts, where /sys/fs/cgroup is tmpfs.
	root := filepath.Join(t.TempDir(), "subpoena")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Root: root}
	if _, err := m.Create(tid); err == nil || !strings.Contains(err.Error(), "not a cgroup v2 directory") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, tid)); !os.IsNotExist(err) {
		t.Fatal("must not create the session directory in a non-cgroup root")
	}
}

func TestCreateDoesNotLeaveARootItCreatedButCannotUse(t *testing.T) {
	parent := t.TempDir()
	m := &Manager{Root: filepath.Join(parent, "subpoena")}
	if _, err := m.Create(tid); err == nil {
		t.Fatal("a fresh plain directory is not a cgroup; Create must fail")
	}
	if _, err := os.Stat(m.Root); !os.IsNotExist(err) {
		t.Fatal("Create left behind the root it made")
	}
}

func TestCreateFailsWhenTheParentIsMissingOrUnwritable(t *testing.T) {
	m := &Manager{Root: filepath.Join(t.TempDir(), "no", "such", "parent")}
	if _, err := m.Create(tid); err == nil {
		t.Fatal("want an error")
	}
	if _, err := (&Manager{}).Create(tid); err == nil {
		t.Fatal("empty root must fail")
	}
}

func TestStandInGetsAProcsFileAndRealCgroupfsIsNeverFaked(t *testing.T) {
	m := standIn(t)
	g, err := m.Create(tid)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(g.Dir(), procsFile)); err != nil || st.IsDir() {
		t.Fatalf("stand-in must get a cgroup.procs file: %v", err)
	}
	if g.Real() {
		t.Fatal("a temp directory is not a real cgroup")
	}
	if id, err := g.ID(); err == nil {
		t.Fatalf("a stand-in has no cgroup ID, got %d", id)
	}
}

func TestStartReportsPlacementFailureWithoutLosingTheProcess(t *testing.T) {
	m := standIn(t)
	g, err := m.Create(tid)
	if err != nil {
		t.Fatal(err)
	}
	// Make cgroup.procs unopenable for writing: replace the file with a directory.
	p := filepath.Join(g.Dir(), procsFile)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd, placeErr, err := g.Start(func() *exec.Cmd { return exec.Command("true") })
	if err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	if placeErr == nil {
		t.Fatal("placement failure must be reported so the caller can fall back to lineage")
	}
}

func TestStartReportsStartFailure(t *testing.T) {
	g, err := standIn(t).Create(tid)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _, err := g.Start(func() *exec.Cmd { return exec.Command("/definitely/not/a/binary") })
	if err == nil || cmd != nil {
		t.Fatalf("want a start error, got cmd=%v err=%v", cmd, err)
	}
}

func TestSessionTrace(t *testing.T) {
	hybrid := "12:pids:/\n4:memory:/user\n1:name=systemd:/\n0::/subpoena/" + strings.ToUpper(tid) + "\n"
	cases := []struct {
		name, in, base string
		want           string
		ok             bool
	}{
		{"v2 line", "0::/subpoena/" + tid + "\n", "subpoena", tid, true},
		{"hybrid, any line", hybrid, "subpoena", tid, true},
		{"nested under the session", "0::/subpoena/" + tid + "/inner/leaf\n", "subpoena", tid, true},
		{"under a slice", "0::/system.slice/subpoena/" + tid + "\n", "subpoena", tid, true},
		{"other base", "0::/other/" + tid + "\n", "subpoena", "", false},
		{"base but not a trace ID", "0::/subpoena/web\n", "subpoena", "", false},
		{"trace ID without the base", "0::/" + tid + "\n", "subpoena", "", false},
		{"base is last element", "0::/subpoena\n", "subpoena", "", false},
		{"custom base", "0::/lab/" + tid + "\n", "lab", tid, true},
		{"garbage", "not a cgroup file", "subpoena", "", false},
		{"empty", "", "subpoena", "", false},
	}
	for _, c := range cases {
		got, ok := SessionTrace(c.in, c.base)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

// realGroup returns a group on a real cgroup v2 hierarchy when this machine
// lets us write one (root, or a delegated subtree), and skips otherwise
// (fails instead when SUBPOENA_CGROUP_REQUIRE=1, as make test-cgroup and CI
// set). Set SUBPOENA_CGROUP_ROOT to use a specific parent directory; otherwise
// the usual mount points are tried. It cleans up everything it creates.
func realGroup(t *testing.T) (g *Group, root string) {
	t.Helper()
	uniq := fmt.Sprintf("subpoena-test-%d", os.Getpid())
	var candidates []string
	if r := os.Getenv(EnvRoot); r != "" {
		candidates = append(candidates, r)
	}
	candidates = append(candidates,
		"/sys/fs/cgroup/unified/"+uniq, // hybrid hosts mount cgroup2 here
		"/sys/fs/cgroup/"+uniq,         // pure cgroup v2 hosts
	)
	var errs []string
	for _, c := range candidates {
		grp, err := (&Manager{Root: c}).Create(tid)
		if err == nil {
			g, root = grp, c
			break
		}
		errs = append(errs, err.Error())
	}
	if g == nil {
		msg := "no writable cgroup v2 hierarchy: " + strings.Join(errs, "; ")
		if os.Getenv("SUBPOENA_CGROUP_REQUIRE") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	t.Cleanup(func() {
		_ = g.Remove()
		if os.Getenv(EnvRoot) == "" {
			_ = os.Remove(root)
		}
	})
	if !g.Real() {
		t.Fatalf("%s is not on a cgroup2 filesystem", g.Dir())
	}
	return g, root
}

// TestStartIntoIsAtomic: CLONE_INTO_CGROUP puts the child in the group from its
// first instruction. Kernels before 5.7 do not support it; then the PID-write
// fallback (TestRealCgroup) is what runs.
func TestStartIntoIsAtomic(t *testing.T) {
	g, root := realGroup(t)
	cmd, ok := startInto(g.Dir(), func() *exec.Cmd { return exec.Command("sleep", "0.3") })
	if !ok {
		t.Skip("kernel or filesystem refused CLONE_INTO_CGROUP")
	}
	defer cmd.Wait()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := SessionTrace(string(b), RootBase(root)); !ok || got != tid {
		t.Fatalf("child not in the session cgroup: %q", b)
	}
	// No PID was written by us: cgroup.procs shows it because the kernel put it there.
	if procs, _ := g.Procs(); len(procs) != 1 || procs[0] != cmd.Process.Pid {
		t.Fatalf("cgroup.procs = %v", procs)
	}
}

// TestRealCgroup places processes in a real cgroup both ways and removes it.
func TestRealCgroup(t *testing.T) {
	g, root := realGroup(t)

	cmd, placeErr, err := g.Start(func() *exec.Cmd { return exec.Command("sleep", "0.5") })
	if err != nil || placeErr != nil {
		t.Fatalf("start err=%v placeErr=%v", err, placeErr)
	}
	pid := cmd.Process.Pid
	// Placement is immediate: read the process's own view of its cgroup.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := SessionTrace(string(b), RootBase(root)); !ok || got != tid {
		t.Fatalf("/proc/%d/cgroup = %q; want session cgroup %s", pid, b, tid)
	}
	procs, err := g.Procs()
	if err != nil || len(procs) != 1 || procs[0] != pid {
		t.Fatalf("cgroup.procs = %v (%v), want [%d]", procs, err, pid)
	}

	// The cgroup ID from the file handle is the kernfs inode number, a second,
	// independent derivation. (execbpf's tests check it against the kernel's
	// bpf_get_current_cgroup_id.)
	id, err := g.ID()
	if err != nil || id == 0 {
		t.Fatalf("ID() = %d, %v", id, err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(g.Dir(), &st); err != nil {
		t.Fatal(err)
	}
	if id != st.Ino {
		t.Fatalf("ID() = %d, inode = %d", id, st.Ino)
	}

	// A process added after the fact (the fallback path) moves too.
	late := exec.Command("sleep", "0.5")
	if err := late.Start(); err != nil {
		t.Fatal(err)
	}
	if err := g.Add(late.Process.Pid); err != nil {
		t.Fatalf("Add on a real cgroup: %v", err)
	}
	if procs, _ := g.Procs(); len(procs) != 2 {
		t.Fatalf("after Add, cgroup.procs = %v", procs)
	}

	// A non-empty cgroup cannot be removed; an empty one can.
	if err := g.Remove(); err == nil {
		t.Fatal("removing a populated cgroup must fail")
	} else if !isBusy(err) {
		t.Logf("remove error (expected EBUSY): %v", err)
	}
	_ = cmd.Process.Kill()
	_ = late.Process.Kill()
	cmd.Wait()
	late.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := g.Remove(); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("empty cgroup could not be removed")
}

func isBusy(err error) bool {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			return e == syscall.EBUSY
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
