//go:build !linux

package cgroup

import "os/exec"

func isCgroupFS(string) bool { return false }

func startInto(string, func() *exec.Cmd) (*exec.Cmd, bool) { return nil, false }
