// Package cgroup creates one cgroup v2 per agent session, named with the
// session's trace ID, and starts a session's child processes inside it.
//
// The cgroup is the correlation key between a trace and the processes it
// caused. Unlike parent-process lineage it survives double forks and
// reparenting, and a kernel-side witness can read it, by name or by the
// kernel's cgroup ID (Group.ID). See witnesses/README.md.
//
// Creating a cgroup needs a writable cgroup v2 hierarchy (root, or a subtree
// delegated by systemd). Everything here fails soft: callers fall back to
// lineage correlation and record that they did.
package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// EnvRoot names the environment variable that overrides DefaultRoot.
	EnvRoot = "SUBPOENA_CGROUP_ROOT"
	// DefaultRoot is the parent of the per-session cgroups.
	DefaultRoot = "/sys/fs/cgroup/subpoena"

	// controllersFile exists in every cgroup v2 directory, root or not. Its
	// presence is how we tell cgroupfs from a plain directory (such as the
	// tmpfs /sys/fs/cgroup of a v1 or hybrid host, where mkdir would "work"
	// and produce nothing but empty directories).
	controllersFile = "cgroup.controllers"
	procsFile       = "cgroup.procs"
)

var traceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Manager creates session cgroups under Root.
type Manager struct {
	// Root is the directory that holds one subdirectory per session. It must
	// be a cgroup v2 directory. For tests and development it may instead be a
	// plain directory containing a cgroup.controllers file: that is taken as a
	// deliberate stand-in, and Create then makes the cgroup.procs file that
	// cgroupfs would have made.
	Root string
}

// FromEnv returns a Manager rooted at $SUBPOENA_CGROUP_ROOT, or DefaultRoot.
func FromEnv() *Manager {
	root := os.Getenv(EnvRoot)
	if root == "" {
		root = DefaultRoot
	}
	return &Manager{Root: root}
}

// RootBase is the last element of root. A process belongs to a session cgroup
// when its /proc/<pid>/cgroup path has the form .../<RootBase>/<trace-id>...;
// the visible path is relative to the cgroup mount (or namespace) root, so only
// the tail of the filesystem path is comparable.
func RootBase(root string) string { return filepath.Base(filepath.Clean(root)) }

// Group is one session's cgroup.
type Group struct {
	dir     string
	traceID string
	base    string
	real    bool
}

// Create makes <Root>/<traceID>. It creates Root if it is missing and refuses
// to proceed unless Root has a cgroup.controllers file, so a misconfigured root
// (the tmpfs /sys/fs/cgroup of a v1 or hybrid host, say) never silently yields a
// plain directory that looks like a cgroup but isolates nothing.
func (m *Manager) Create(traceID string) (*Group, error) {
	traceID = strings.ToLower(traceID)
	if !traceIDRE.MatchString(traceID) {
		return nil, fmt.Errorf("cgroup: %q is not a 32-digit hex trace ID", traceID)
	}
	if m.Root == "" {
		return nil, errors.New("cgroup: no root configured")
	}
	createdRoot := false
	if err := os.Mkdir(m.Root, 0o755); err == nil {
		createdRoot = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("cgroup: create root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(m.Root, controllersFile)); err != nil {
		if createdRoot {
			_ = os.Remove(m.Root)
		}
		return nil, fmt.Errorf("cgroup: %s is not a cgroup v2 directory (no %s): %w", m.Root, controllersFile, err)
	}
	dir := filepath.Join(m.Root, traceID)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("cgroup: create %s: %w", dir, err)
	}
	procs := filepath.Join(dir, procsFile)
	if _, err := os.Stat(procs); err != nil {
		if isCgroupFS(dir) {
			// cgroupfs always provides cgroup.procs; something is badly wrong.
			_ = os.Remove(dir)
			return nil, fmt.Errorf("cgroup: %s has no %s: %w", dir, procsFile, err)
		}
		// Stand-in directory (see Manager.Root): make the file cgroupfs would have.
		if err := os.WriteFile(procs, nil, 0o644); err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("cgroup: stand-in %s: %w", procs, err)
		}
	}
	return &Group{dir: dir, traceID: traceID, base: RootBase(m.Root), real: isCgroupFS(dir)}, nil
}

// Dir is the cgroup's directory.
func (g *Group) Dir() string { return g.dir }

// TraceID is the trace ID the cgroup is named with.
func (g *Group) TraceID() string { return g.traceID }

// Path is the tail by which /proc/<pid>/cgroup identifies the group:
// "<root base>/<trace id>".
func (g *Group) Path() string { return g.base + "/" + g.traceID }

// ID is the kernel's 64-bit ID for the group: what bpf_get_current_cgroup_id
// returns for a process inside it, and what eBPF-based witnesses report. It is
// read with name_to_handle_at, as bpftrace's cgroupid() does. A stand-in
// directory has no cgroup ID.
func (g *Group) ID() (uint64, error) {
	if !g.real {
		return 0, fmt.Errorf("cgroup: %s is a stand-in directory, not a cgroup", g.dir)
	}
	return cgroupID(g.dir)
}

// Real reports whether the directory is on a cgroup2 filesystem (as opposed to
// a stand-in directory). Real groups place children atomically with
// CLONE_INTO_CGROUP where the kernel supports it.
func (g *Group) Real() bool { return g.real }

// Start starts a command inside the group and returns it. newCmd must return a
// fresh, unstarted command each time it is called.
//
// On a real cgroup the child is created directly inside the group
// (CLONE_INTO_CGROUP, Linux 5.7+), so it never runs outside it. If that is
// unavailable, or the group is a stand-in, the command is started normally and
// its PID is written to cgroup.procs; a process forked in the instant between
// start and the write would escape, which is why the atomic path is preferred.
//
// err is a failure to start. placeErr is non-nil when the process was started
// but could not be placed in the group; the caller must then treat the session
// as lineage-correlated.
func (g *Group) Start(newCmd func() *exec.Cmd) (cmd *exec.Cmd, placeErr, err error) {
	if g.real {
		if cmd, ok := startInto(g.dir, newCmd); ok {
			return cmd, nil, nil
		}
	}
	cmd = newCmd()
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, g.Add(cmd.Process.Pid), nil
}

// Add moves a process into the group by writing its PID to cgroup.procs.
func (g *Group) Add(pid int) error {
	f, err := os.OpenFile(filepath.Join(g.dir, procsFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("cgroup: %w", err)
	}
	_, werr := f.WriteString(strconv.Itoa(pid) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("cgroup: add pid %d: %w", pid, werr)
	}
	return nil
}

// Procs lists the PIDs in cgroup.procs. On a stand-in directory it lists every
// PID that was written, including ones that have since exited.
func (g *Group) Procs() ([]int, error) {
	b, err := os.ReadFile(filepath.Join(g.dir, procsFile))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			pids = append(pids, n)
		}
	}
	return pids, nil
}

// Remove deletes the group. A real cgroup can only be removed once it is empty
// (rmdir); the error says so if processes remain.
func (g *Group) Remove() error {
	err := os.Remove(g.dir)
	if err != nil && !g.real {
		return os.RemoveAll(g.dir) // stand-in directory holding fake control files
	}
	return err
}

// SessionTrace finds the session cgroup in the content of a /proc/<pid>/cgroup
// file: a path element equal to rootBase followed by a trace-ID element. It
// returns that trace ID. Hybrid hosts list many hierarchies; any line matches.
func SessionTrace(procCgroup, rootBase string) (traceID string, ok bool) {
	for _, line := range strings.Split(procCgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		segs := strings.Split(parts[2], "/")
		for i := 0; i+1 < len(segs); i++ {
			if segs[i] == rootBase {
				if id := strings.ToLower(segs[i+1]); traceIDRE.MatchString(id) {
					return id, true
				}
			}
		}
	}
	return "", false
}
