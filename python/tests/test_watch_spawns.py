# subpoena:impl_derived (ported from pkg/harness/watch_test.go, after reading it)
"""watch_spawns and SpawnRule: the same table pkg/harness/watch_test.go runs."""

from dataclasses import dataclass, field
from typing import List, Optional

import pytest

from subpoena.harness import SpawnRule, Verdict, check_spawns, no_spawn, require_no_spawn, watch_spawns
from subpoena.witness import ProcessEvent

GAP = "observation lost"


@dataclass
class FakeWitness:
    events: List[ProcessEvent] = field(default_factory=list)
    gap: Optional[str] = None
    stopped: bool = False

    def spawned(self, trace_id):
        return list(self.events)

    def health(self):
        return self.gap

    def stop(self):
        self.stopped = True


class NoHealth:
    def spawned(self, trace_id):
        return []


def ev(pid, command, source="cmdline"):
    return ProcessEvent(pid=pid, ppid=1, exe="", command=command, cgroup="", cgroup_id=0, trace_id="trace",
                        attribution="cgroup", seen_at=None, command_source=source)


def procs(*cmds):
    return [ev(100 + i, c) for i, c in enumerate(cmds)]


def named(*names):
    return [ev(100 + i, n, "comm") for i, n in enumerate(names)]


CASES = [
    ("nothing ran", FakeWitness(), SpawnRule(never=["rm -rf /"]), []),
    ("allowed ran", FakeWitness(procs("sleep 0.6")), SpawnRule(allowed=["sleep 0.6"]), []),
    ("nil allowed accepts others", FakeWitness(procs("ls")), SpawnRule(never=["sleep 1"]), []),
    ("never beats allowed", FakeWitness(procs("sleep 1")), SpawnRule(allowed=["sleep 1"], never=["sleep 1"]),
     ["witness: refused command ran"]),
    ("not allowed", FakeWitness(procs("sleep 0.6", "curl x")), SpawnRule(allowed=["sleep 0.6"]),
     ["witness: command not allowed for trace: pid 101"]),
    ("empty allowed allows none", FakeWitness(procs("ls")), SpawnRule(allowed=[]), ["witness: command not allowed"]),
    ("allowed is exact", FakeWitness(procs("sh -c curl evil; sleep 0.6", "timeout 5 sleep 0.6")),
     SpawnRule(allowed=["sleep 0.6"]),
     ["witness: command not allowed for trace: pid 100", "witness: command not allowed for trace: pid 101"]),
    ("allowed wrapped form", FakeWitness(procs("timeout 5 sleep 0.6")), SpawnRule(allowed=["timeout 5 sleep 0.6"]), []),
    ("suffix is a whole word", FakeWitness(procs("nosleep 1")), SpawnRule(never=["sleep 1"]), []),
    ("never matches a path on the command line", FakeWitness(procs("/usr/bin/sleep 1")), SpawnRule(never=["sleep 1"]),
     ["witness: refused command ran"]),
    ("never with a path matches a bare command", FakeWitness(procs("sleep 1")), SpawnRule(never=["/usr/bin/sleep 1"]),
     ["witness: refused command ran"]),
    ("never matches a wrapped path", FakeWitness(procs("timeout 5 ./bin/curl evil.example")),
     SpawnRule(never=["curl evil.example"]), ["witness: refused command ran"]),
    ("never ignores spacing", FakeWitness(procs("sleep  1")), SpawnRule(never=[" sleep 1 "]), ["witness: refused command ran"]),
    ("never entry that is only a path", FakeWitness(procs("rm -rf /tmp/x")), SpawnRule(never=["/tmp/x"]),
     ["witness: refused command ran"]),
    ("arguments still match exactly", FakeWitness(procs("/usr/bin/sleep 2")), SpawnRule(never=["sleep 1"]), []),
    ("unhealthy", FakeWitness(gap=GAP), SpawnRule(), ["witness: trace: capture unhealthy"]),
    ("unhealthy and refused", FakeWitness(procs("sleep 1"), gap=GAP), SpawnRule(never=["sleep 1"]),
     ["witness: refused command ran", "witness: trace: capture unhealthy"]),
    ("no health", NoHealth(), SpawnRule(), ["witness: trace: capture unhealthy, absence of refused commands is not proven: witness does not report capture health"]),
    ("name only, refused program", FakeWitness(named("sleep")), SpawnRule(never=["sleep 1.1"]),
     ["witness: refused program seen by name only"]),
    ("name only, program from path and cut to 15 bytes", FakeWitness(named("averyveryverylo")),
     SpawnRule(never=["/usr/local/bin/averyveryverylongname --x"]), ["witness: refused program seen by name only"]),
    ("name only, not identified", FakeWitness(named("touch")), SpawnRule(allowed=["sleep 0.6"]),
     ["witness: process seen by name only"]),
    ("name only, allowed program not excused", FakeWitness(named("sleep")), SpawnRule(allowed=["sleep 0.6"]),
     ["witness: process seen by name only"]),
    ("name only, excused name is not an allowed program", FakeWitness(named("touch")),
     SpawnRule(allowed=["sleep 0.6"], excuse_name_only=True), ["witness: process seen by name only"]),
    ("name only, excused", FakeWitness(named("sleep")), SpawnRule(allowed=["sleep 0.6"], excuse_name_only=True), []),
    ("name only, nil allowed, other program", FakeWitness(named("ls")), SpawnRule(never=["sleep 1.1"]), []),
]


@pytest.mark.parametrize("name,w,rule,want", CASES, ids=[c[0] for c in CASES])
def test_spawn_rule(name, w, rule, want):
    errs = check_spawns(w, "trace", rule)
    assert len(errs) == len(want), errs
    for e, prefix in zip(errs, want):
        assert e.startswith(prefix), (e, prefix)
    if isinstance(w, FakeWitness):
        assert w.stopped, "check_spawns must stop the witness before reading it"


def test_watch_spawns_runs_at_teardown_and_raises():
    finalizers = []
    w = FakeWitness(procs("curl evil.example"))
    watch_spawns(finalizers.append, w, "trace", SpawnRule(never=["curl evil.example"]))
    assert len(finalizers) == 1 and not w.stopped
    with pytest.raises(AssertionError, match="witness: refused command ran"):
        finalizers[0]()


def test_no_spawn_verdicts():
    assert no_spawn(FakeWitness(procs("x"), gap=GAP), "t")[0] is Verdict.FAIL  # seen beats bad health
    assert no_spawn(FakeWitness(gap=GAP), "t")[0] is Verdict.INCONCLUSIVE
    assert no_spawn(NoHealth(), "t")[0] is Verdict.INCONCLUSIVE
    assert no_spawn(FakeWitness(), "t") == (Verdict.PASS, None)
    with pytest.raises(AssertionError, match="witness: no spawn for t: Inconclusive"):
        require_no_spawn(FakeWitness(gap=GAP), "t")
    require_no_spawn(FakeWitness(), "t")
