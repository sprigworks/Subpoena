//go:build linux

package cgroup

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// cgroup2SuperMagic is CGROUP2_SUPER_MAGIC from linux/magic.h.
const cgroup2SuperMagic = 0x63677270

// cgroupID returns the kernel's cgroup ID for a cgroup v2 directory: cgroupfs
// (kernfs) encodes it as the 8-byte, native-endian file handle.
func cgroupID(dir string) (uint64, error) {
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		return 0, fmt.Errorf("cgroup: id of %s: %w", dir, err)
	}
	b := h.Bytes()
	if len(b) != 8 {
		return 0, fmt.Errorf("cgroup: id of %s: %d-byte handle, want 8", dir, len(b))
	}
	return binary.NativeEndian.Uint64(b), nil
}

func isCgroupFS(dir string) bool {
	var st syscall.Statfs_t
	return syscall.Statfs(dir, &st) == nil && int64(st.Type) == cgroup2SuperMagic
}

// startInto starts a command directly in the cgroup with CLONE_INTO_CGROUP.
// It reports false, having started nothing, when the kernel or filesystem
// refuses; the caller then falls back to writing the PID.
func startInto(dir string, newCmd func() *exec.Cmd) (*exec.Cmd, bool) {
	fd, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer fd.Close()
	cmd := newCmd()
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(fd.Fd())
	if err := cmd.Start(); err != nil {
		return nil, false
	}
	return cmd, true
}
