//subpoena:impl_derived
//subpoena:pure_logic

package live

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/sprigworks/subpoena/internal/crossmark"
)

// A test binary killed outright runs no cleanup, and a --rm container outlives it:
// a night of killed runs held most of the host's AIO slots, and MySQL could not
// start. So each container names its owner in labels, and the next run removes
// those whose owner is gone. Another run's containers stay, however many suites
// share the host: only a dead owner on this host counts. A container from before
// the labels is not touched, and a PID since reused keeps its container for now.
const suiteLabel = "subpoena.test=dbproxy-live"

var reapOnce sync.Once

// ownerLabels are the docker run flags that name this process as the owner.
func ownerLabels() []string {
	host, _ := os.Hostname()
	return []string{"--label", suiteLabel, "--label", "subpoena.test.host=" + host, "--label", "subpoena.test.pid=" + strconv.Itoa(os.Getpid())}
}

// leftovers picks from listing, lines of "id host pid", the containers to remove.
// A line it cannot read is left alone.
func leftovers(listing, host string, alive func(pid int) bool) []string {
	var ids []string
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != host {
			continue
		}
		if pid, err := strconv.Atoi(f[2]); err == nil && pid > 0 && !alive(pid) {
			ids = append(ids, f[0])
		}
	}
	return ids
}

// ownerAlive is false only if the process is known to be gone. One of another
// user's answers EPERM, and it is there.
func ownerAlive(pid int) bool {
	return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// reapLeftovers removes the containers of runs that were killed. It is housekeeping,
// so a failure is said and the run goes on.
func reapLeftovers() {
	host, err := os.Hostname()
	if err != nil {
		return
	}
	out, err := exec.Command("docker", "ps", "-a", "--filter", "label="+suiteLabel,
		"--format", `{{.ID}} {{.Label "subpoena.test.host"}} {{.Label "subpoena.test.pid"}}`).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "live: list leftover containers:", err)
		return
	}
	for _, id := range leftovers(string(out), host, ownerAlive) {
		if err := exec.Command("docker", "rm", "-f", id).Run(); err != nil {
			fmt.Fprintln(os.Stderr, "live: remove leftover container", id+":", err)
		}
	}
}

func TestLeftoversAreOnlyADeadOwnersOnThisHost(t *testing.T) {
	alive := func(pid int) bool { return pid == 100 }
	listing := strings.Join([]string{
		"gone here 7",
		"running here 100",
		"elsewhere there 7",
		"nohost 7",
		"notapid here x",
		"zero here 0",
		"negative here -1",
		"",
	}, "\n")
	got := leftovers(listing, "here", alive)
	if len(got) != 1 || got[0] != "gone" {
		t.Fatalf("leftovers = %q", got)
	}
}

func TestOwnerAliveSeesAProcessEnd(t *testing.T) {
	if !ownerAlive(os.Getpid()) {
		t.Error("this process reads as gone")
	}
	if !ownerAlive(1) {
		t.Error("another user's process reads as gone")
	}
	if ownerAlive(deadPID(t)) {
		t.Error("an ended process reads as alive")
	}
}

func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

// The same against a real daemon: a dead owner's container goes, a live owner's and
// a stranger's stay. Like the rest of this package it needs Docker and an image.
func TestReapLeftoversRemovesOnlyADeadOwnersContainer(t *testing.T) {
	if crossmark.Active {
		t.Skip("live database tests do not run under subpoena-cross")
	}
	if err := exec.Command("docker", "image", "inspect", pgImage).Run(); err != nil {
		skip(t, "image %s is not present", pgImage)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	sleeper := func(labels ...string) string {
		args := append([]string{"run", "-d", "--rm", "--entrypoint", "sleep"}, labels...)
		out, err := exec.Command("docker", append(args, pgImage, "300")...).Output()
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSpace(string(out))
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", id).Run() })
		return id
	}
	there := func(id string) bool { return exec.Command("docker", "inspect", id).Run() == nil }
	dead := sleeper("--label", suiteLabel, "--label", "subpoena.test.host="+host, "--label", "subpoena.test.pid="+strconv.Itoa(deadPID(t)))
	mine := sleeper(ownerLabels()...)
	stranger := sleeper("--label", suiteLabel)
	reapLeftovers()
	if there(dead) {
		t.Error("a dead owner's container is still there")
	}
	if !there(mine) {
		t.Error("a live run's container was removed")
	}
	if !there(stranger) {
		t.Error("a container with no owner was removed")
	}
}
