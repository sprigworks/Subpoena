//subpoena:impl_derived

package witness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These benchmarks measure the live ProcWitness on the machine they run on.
// They assert nothing: polling cost and short-process capture depend on how
// busy the host is, so the numbers are evidence for a report, not a pass bar.
// Run them with the host's process count in the output:
//
//	go test -run '^$' -bench 'Proc' -benchtime 200x ./pkg/witness

// hostProcs counts the PIDs listed in /proc.
func hostProcs(b *testing.B) int {
	b.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		b.Skip("no procfs")
	}
	n := 0
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

// BenchmarkProcFullScan times one full scan of /proc: the cost every process
// outside the root's children lists waits on.
func BenchmarkProcFullScan(b *testing.B) {
	procs := hostProcs(b)
	w := NewProcWitness(os.Getpid())
	w.baseline, w.tracked = map[procKey]bool{}, map[procKey]*ProcessEvent{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Poll()
	}
	b.ReportMetric(float64(procs), "host-procs")
}

// BenchmarkProcChildrenWalk times one walk of the root's children lists, the
// path that sees the root's own descendants.
func BenchmarkProcChildrenWalk(b *testing.B) {
	procs := hostProcs(b)
	if _, err := os.Stat("/proc/self/task"); err != nil {
		b.Skip("no task directory")
	}
	w := NewProcWitness(os.Getpid())
	w.baseline, w.tracked = map[procKey]bool{}, map[procKey]*ProcessEvent{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.pollChildren()
	}
	b.ReportMetric(float64(procs), "host-procs")
}

// BenchmarkProcShortProcessCapture runs short-lived children of the root and
// reports the fraction the witness saw at all (seen/op) and the fraction it
// saw after exec (exec-seen/op): a child seen only as the fork still shows the
// test binary's command line. grandchildren-seen/op counts exec'd processes
// whose parent is one of those children.
func BenchmarkProcShortProcessCapture(b *testing.B) {
	procs := hostProcs(b)
	dir := b.TempDir()
	git, gitErr := exec.LookPath("git")
	if gitErr == nil {
		if out, err := exec.Command(git, "init", "-q", dir).CombinedOutput(); err != nil {
			b.Fatalf("git init: %v: %s", err, out)
		}
	}
	self, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		b.Skip("no /proc/self/cmdline")
	}
	selfCmd := strings.Join(strings.Split(strings.TrimRight(string(self), "\x00"), "\x00"), " ")
	cases := []struct {
		name string
		argv []string
	}{
		{"true", []string{"true"}},
		{"touch", []string{"touch", filepath.Join(dir, "f")}},
		{"git-status", []string{"git", "-C", dir, "status", "--short"}},
		{"sleep-5ms", []string{"sleep", "0.005"}},
		{"sleep-20ms", []string{"sleep", "0.02"}},
		{"sleep-100ms", []string{"sleep", "0.1"}},
		// Two short grandchildren per run, counted in grandchildren-seen/op.
		{"sh-two-true", []string{"sh", "-c", "/bin/true; /bin/true"}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			path, err := exec.LookPath(c.argv[0])
			if err != nil {
				b.Skipf("no %s binary", c.argv[0])
			}
			w := NewProcWitness(os.Getpid())
			if err := w.Start(); err != nil {
				b.Fatal(err)
			}
			pids := make([]int, 0, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command(path, c.argv[1:]...)
				if err := cmd.Run(); err != nil {
					b.Fatalf("%s: %v", c.name, err)
				}
				pids = append(pids, cmd.Process.Pid)
			}
			b.StopTimer()
			w.Stop()
			if err := w.Health(); err != nil {
				b.Logf("witness health: %v", err)
			}
			byPID := map[int]ProcessEvent{}
			for _, ev := range w.Events() {
				byPID[ev.PID] = ev
			}
			mine := map[int]bool{}
			for _, pid := range pids {
				mine[pid] = true
			}
			grand := 0
			for _, ev := range byPID {
				if mine[ev.PPID] && ev.Command != selfCmd {
					grand++
				}
			}
			seen, execSeen := 0, 0
			for _, pid := range pids {
				ev, ok := byPID[pid]
				if !ok {
					continue
				}
				seen++
				if ev.Command != selfCmd {
					execSeen++
				}
			}
			b.ReportMetric(float64(seen)/float64(b.N), "seen/op")
			b.ReportMetric(float64(execSeen)/float64(b.N), "exec-seen/op")
			b.ReportMetric(float64(grand)/float64(b.N), "grandchildren-seen/op")
			b.ReportMetric(float64(procs), "host-procs")
		})
	}
}
