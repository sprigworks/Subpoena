//go:build !unix

package cross

import "os/exec"

// killGroupOnCancel kills only the go command here; a test binary it started
// may outlive a timeout.
func killGroupOnCancel(cmd *exec.Cmd) {}

// orphansOnTimeout is true where a timed-out mutant's test binary may keep
// running: the run stops at the first timeout rather than judge later mutants
// beside it.
const orphansOnTimeout = true
