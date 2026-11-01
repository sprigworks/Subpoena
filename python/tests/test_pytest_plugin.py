# subpoena:impl_derived (written after reading subpoena/pytest_plugin.py)
"""The pytest plugin's fixtures, run in a real inner pytest session: the
harness is fresh per test, a watch_spawns check fails the test at teardown
even after an earlier failure, and the sinkhole is stopped at teardown."""

import pytest

from conftest import ROOT


@pytest.fixture
def run(pytester, monkeypatch):
    # Load the plugin explicitly, and only once, whether or not the package
    # is installed with its entry point.
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    def go(src):
        pytester.makepyfile(test_inner=src)
        return pytester.runpytest_subprocess("-p", "subpoena.pytest_plugin", "-q")
    return go


def test_entry_point_is_declared():
    assert '[project.entry-points.pytest11]\nsubpoena = "subpoena.pytest_plugin"' in (
        ROOT / "python" / "pyproject.toml").read_text()


def test_harness_fixture_is_fresh_per_test(run):
    r = run('''
from subpoena.harness import require_absent, require_exists

def test_a(subpoena_harness):
    with subpoena_harness.tracer("t").start_as_current_span("a"):
        pass
    require_exists(subpoena_harness.collect(), '{ name = "a" }')

def test_b(subpoena_harness):
    require_absent(subpoena_harness.collect(), '{ name = "a" }')
''')
    r.assert_outcomes(passed=2)


SPAWN = '''
import io, json
from subpoena.harness import SpawnRule
from subpoena.witness import read_log

T = "c0de00000000000000000000000000a1"

def log(*cmds):
    lines = [{"time": "2026-10-26T12:00:00Z", "record": "start", "healthy": False}]
    lines += [{"time": "2026-10-26T12:00:01Z", "pid": 7, "command": c, "trace_id": T} for c in cmds]
    lines += [{"time": "2026-10-26T12:00:02Z", "record": "stop", "healthy": True}]
    return read_log(io.StringIO("\\n".join(json.dumps(l) for l in lines)))

def test_clean(subpoena_watch_spawns):
    subpoena_watch_spawns(log("ls"), T, SpawnRule(never=["rm -rf /"]))

def test_refused(subpoena_watch_spawns):
    subpoena_watch_spawns(log("rm -rf /"), T, SpawnRule(never=["rm -rf /"]))

def test_refused_after_earlier_failure(subpoena_watch_spawns):
    subpoena_watch_spawns(log("rm -rf /"), T, SpawnRule(never=["rm -rf /"]))
    assert False, "the test failed first"
'''


def test_watch_spawns_fixture_checks_at_teardown(run):
    r = run(SPAWN)
    r.assert_outcomes(passed=2, errors=2, failed=1)
    out = r.stdout.str()
    assert out.count("witness: refused command ran for c0de00000000000000000000000000a1") >= 2, \
        "the check must run at teardown even after the test failed"


def test_sinkhole_fixture(run):
    r = run('''
import socket
from subpoena.harness import require_no_dial

def test_dialed(subpoena_sinkhole):
    socket.create_connection((str(subpoena_sinkhole.addr.addr), subpoena_sinkhole.addr.port), timeout=1).close()
    subpoena_sinkhole.stop()
    require_no_dial(subpoena_sinkhole, "t")

def test_quiet(subpoena_sinkhole):
    subpoena_sinkhole.stop()
    require_no_dial(subpoena_sinkhole, "t")

def test_unstopped_is_inconclusive(subpoena_sinkhole):
    require_no_dial(subpoena_sinkhole, "t")
''')
    r.assert_outcomes(passed=1, failed=2)
    out = r.stdout.str()
    assert ": Fail: " in out and ": Inconclusive: " in out
