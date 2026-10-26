//go:build !linux

package cgroup

import (
	"errors"
	"os/exec"
)

func isCgroupFS(string) bool { return false }

func cgroupID(string) (uint64, error) { return 0, errors.New("cgroup: cgroup IDs are Linux-only") }

func startInto(string, func() *exec.Cmd) (*exec.Cmd, bool) { return nil, false }
