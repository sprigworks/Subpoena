//go:build !unix

package cross

import "os/exec"

// killGroupOnCancel kills only the go command here; a test binary it started
// may outlive a timeout.
func killGroupOnCancel(cmd *exec.Cmd) {}
