//go:build unix

package cross

import (
	"os/exec"
	"syscall"
)

// killGroupOnCancel starts cmd in its own process group and kills the whole
// group when its context ends. Killing only the go command would orphan the
// test binary it started, which then runs on (a hung mutant for as long as it
// hangs) after the verdict.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// orphansOnTimeout is false here: killGroupOnCancel kills the test binary too.
const orphansOnTimeout = false
