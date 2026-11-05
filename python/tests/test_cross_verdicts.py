# subpoena:impl_derived
"""Verdicts that must not overstate proof, each built from a repro of the second
trial-fixes review, through real pytest runs."""

import os
import tempfile
import textwrap
import time

import pytest

from subpoena import cross
from subpoena.cross import CRASHED, INVALID, KILLED, KILLED_BY_SELF_REPORT, SURVIVED

UNCONFIRMED = "enforcement-mutant-unconfirmed"

GATE = '''
# subpoena:enforcement_point
def gate(user):
    if user == "mallory":
        return {"denied": True}  # subpoena:enforcement
    return {"user": user}
'''


@pytest.fixture(autouse=True)
def one_rerun(monkeypatch):
    if hasattr(cross, "_RERUNS"):
        monkeypatch.setattr(cross, "_RERUNS", 1)


def project(tmp_path, files):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body).lstrip())
    return str(tmp_path)


def outcome(tmp_path, files, *args, **kw):
    rep = cross.run(project(tmp_path, files), list(args), **kw)
    assert len(rep.results) == 1, rep.results
    return rep.results[0]


# --- a red suite that has nothing to do with the mutant (q2, q3) ---

OUTSIDE = '''
    import os
    import auth

    def test_first_run_only():
        mark = {mark!r}
        assert not os.path.exists(mark), "already initialised"
        open(mark, "w").close()
'''


def test_a_test_red_without_the_mutant_is_no_kill(tmp_path):
    (tmp_path / "state").mkdir()
    mark = str(tmp_path / "state" / "mark")
    root = tmp_path / "p"
    r = outcome(root, {"auth.py": GATE, "test_a.py": OUTSIDE.format(mark=mark)})
    assert r.outcome == UNCONFIRMED and "already initialised" in r.output


def test_a_self_report_kill_is_confirmed_too(tmp_path):
    (tmp_path / "state").mkdir()
    mark = str(tmp_path / "state" / "mark")
    r = outcome(tmp_path / "p", {"auth.py": GATE, "test_a.py": OUTSIDE.format(mark=mark)}, require_witness=True)
    assert r.outcome == UNCONFIRMED


FLAKE = '''
    import auth

    def test_flaky():
        path = {path!r}
        try:
            n = len(open(path).read())
        except FileNotFoundError:
            n = 0
        open(path, "a").write("x")
        assert n + 1 not in (2, 4), "upstream was slow"
'''


@pytest.mark.parametrize("reruns,want", [(1, KILLED), (3, UNCONFIRMED)])
def test_a_flake_needs_more_than_one_rerun(tmp_path, monkeypatch, reruns, want):
    # Fails on its second and fourth runs: the mutant run and the second rerun.
    monkeypatch.setattr(cross, "_RERUNS", reruns, raising=False)
    (tmp_path / "state").mkdir()
    path = str(tmp_path / "state" / "count")
    r = outcome(tmp_path / "p", {"auth.py": GATE, "test_a.py": FLAKE.format(path=path)})
    assert r.outcome == want


def test_a_real_kill_stands_through_the_reruns(tmp_path, monkeypatch):
    monkeypatch.setattr(cross, "_RERUNS", 3, raising=False)
    r = outcome(tmp_path, {"auth.py": GATE, "test_a.py": """
        from auth import gate
        def test_denied():
            assert gate("mallory") == {"denied": True}
    """})
    assert r.outcome == KILLED


# --- the code under test supplies no witness evidence (p6-tag, p6b) ---

CHATTY = '''
# subpoena:enforcement_point
def gate(user):
    if user == "mallory":
        return "denied"  # subpoena:enforcement
    return "note for witness: none spawned"
'''


@pytest.mark.parametrize("test", [
    'assert gate("mallory") == "denied"',
    'assert gate("mallory") == "denied", "no tag here"',
    'assert gate("mallory") == "denied", "no tag, though the text says witness: here"',
])
def test_a_tag_in_the_values_of_a_diff_is_no_evidence(tmp_path, test):
    r = outcome(tmp_path, {"auth.py": CHATTY, "test_a.py": f"""
from auth import gate
def test_denied():
    {test}
"""}, require_witness=True)
    assert r.outcome == cross.KILLED_BY_SELF_REPORT and r.evidence == "other", (r.outcome, r.first_failure)


def test_a_hand_written_tag_is_no_witness_evidence(tmp_path):
    r = outcome(tmp_path, {"auth.py": CHATTY, "test_a.py": """
        from auth import gate
        def test_denied():
            assert gate("mallory") == "denied", "witness: it ran"
    """}, require_witness=True)
    assert r.outcome == KILLED_BY_SELF_REPORT and r.evidence == "other"


# --- test code is what pytest collected (a2-named, a1-pyfiles) ---

HELPED = '''
from limit_test import use

# subpoena:enforcement_point
def gate(user):
    if user == "mallory":
        return None  # subpoena:enforcement
    return use(user)
'''

INVARIANT = '''
def use(user):
    assert user != "mallory", "internal invariant"
    return "ok"
'''


def test_an_assert_in_a_module_named_like_a_test_is_a_crash(tmp_path):
    r = outcome(tmp_path, {"auth.py": HELPED, "limit_test.py": INVARIANT, "test_auth.py": """
        from auth import gate
        def test_denied():
            gate("mallory")
    """})
    assert r.outcome == CRASHED


def test_an_assert_under_python_files_star_is_a_crash(tmp_path):
    r = outcome(tmp_path, {"pytest.ini": "[pytest]\npython_files = *.py\n", "auth.py": '''
# subpoena:enforcement_point
def gate(user):
    if user == "mallory":
        return None  # subpoena:enforcement
    assert user != "mallory", "internal invariant"
    return "ok"
''', "test_auth.py": """
        from auth import gate
        def test_denied():
            gate("mallory")
    """})
    assert r.outcome == CRASHED


def test_an_assert_in_another_collected_test_file_is_test_code(tmp_path):
    r = outcome(tmp_path, {"auth.py": GATE, "test_helpers.py": """
        def check(value):
            assert value == {"denied": True}, "not denied"
        def test_check():
            check({"denied": True})
    """, "test_auth.py": """
        from auth import gate
        from test_helpers import check
        def test_denied():
            check(gate("mallory"))
    """})
    assert r.outcome == KILLED


# --- order decides nothing (o1-random, o2-xdist-ev) ---

ASSERTS = """
    def test_{a}():
        assert gate("mallory") == {{"denied": True}}
"""
CRASHES = """
    def test_{b}():
        gate("mallory")["denied"]
"""


@pytest.mark.parametrize("args", [(), ("-x",), ("--maxfail=1",)])
@pytest.mark.parametrize("a,b", [("a", "b"), ("b", "a")])
def test_a_crash_beside_an_assertion_is_a_crash_in_either_order(tmp_path, a, b, args):
    body = "    from auth import gate\n" + ASSERTS.format(a=a) + CRASHES.format(b=b)
    r = outcome(tmp_path, {"auth.py": GATE, "test_auth.py": body}, *args)
    assert r.outcome == CRASHED


def test_the_inner_pytest_runs_without_pytest_randomly(tmp_path):
    r = outcome(tmp_path, {"auth.py": GATE, "test_a.py": """
        import auth
        def test_blocked(request):
            assert request.config.pluginmanager.is_blocked("randomly")
    """})
    assert r.outcome == SURVIVED


def test_first_evidence_is_the_first_test_collected_not_the_first_to_finish():
    def failure(test, message):
        return {"kind": "failure", "test": test, "when": "call", "verdict": "assertion", "message": message}
    records = [{"kind": "collected", "tests": ["t::a", "t::b"]},
               failure("t::b", "no error"), dict(failure("t::a", "witness: spawned"), witness=True),
               {"kind": "finished", "missing": []}]
    outcome_, failing, evidence, first = cross.classify(1, records, "")
    assert (outcome_, evidence, first) == (KILLED, "witness", "witness: spawned")
    assert set(failing) == {"t::a", "t::b"}


# --- exit codes that are not pytest's own (p8-exit2, p8-exit4) ---

@pytest.mark.parametrize("code", [2, 3, 4, 5])
def test_a_test_process_that_dies_is_a_crash_whatever_its_code(tmp_path, code):
    r = outcome(tmp_path, {"auth.py": GATE, "test_auth.py": f"""
        import os
        from auth import gate
        def test_denied():
            if "denied" not in gate("mallory"):
                os._exit({code})
    """})
    assert r.outcome == CRASHED


def test_a_mutant_that_stops_collection_stays_invalid(tmp_path):
    r = outcome(tmp_path, {"auth.py": GATE, "test_auth.py": """
        from auth import gate
        assert "denied" in gate("mallory")
        def test_nothing():
            pass
    """})
    assert r.outcome == INVALID


# --- app text is no witness evidence, whatever the message says (review 3: p01) ---

BODY = '''
class R:
    def __init__(self, status, body):
        self.status, self.body = status, body

# subpoena:enforcement_point
def serve(user):
    if user == "mallory":
        return R(403, "denied")  # subpoena:enforcement
    return R(200, "witness: nothing ran, the gate is fine")
'''


def test_a_response_body_used_as_the_assert_message_is_no_witness(tmp_path):
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": """
        from app import serve
        def test_refused():
            r = serve("mallory")
            assert r.status == 403, r.body
    """}, require_witness=True)
    assert r.outcome == KILLED_BY_SELF_REPORT and r.evidence == "other"


def test_an_apps_repr_under_assert_equal_is_no_witness(tmp_path):
    r = outcome(tmp_path, {"app.py": BODY + '''
class Decision:
    def __init__(self, ok):
        self.ok = ok
    def __eq__(self, other):
        return self.ok == other
    def __repr__(self):
        return "witness: refused command ran (the app's repr)"

def decide(user):
    return Decision(serve(user).status == 403)
''', "test_app.py": """
        import unittest
        from app import decide
        class T(unittest.TestCase):
            def test_refused(self):
                self.assertEqual(decide("mallory"), True)
    """}, require_witness=True)
    assert r.outcome == KILLED_BY_SELF_REPORT and r.evidence == "other"


def test_a_harness_witness_failure_is_witness_evidence(tmp_path):
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": """
        from app import serve
        from subpoena.harness import require_no_spawn
        class Saw:
            def spawned(self, trace):
                return ["rm -rf /"] if serve("mallory").status != 403 else []
            def health(self):
                return None
        def test_refused():
            require_no_spawn(Saw(), "t")
    """}, require_witness=True)
    assert r.outcome == KILLED and r.evidence == "witness"


def test_a_test_that_asks_a_witness_itself_reports_through_witness_fail(tmp_path):
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": """
        from app import serve
        from subpoena.harness import witness_fail
        def test_refused():
            if serve("mallory").status != 403:
                witness_fail("refused command ran")
    """}, require_witness=True)
    assert r.outcome == KILLED and r.evidence == "witness"
    assert r.first_failure == "witness: refused command ran"


def test_witness_fail_called_by_the_code_under_test_is_a_crash(tmp_path):
    r = outcome(tmp_path, {"app.py": """
        from subpoena.harness import witness_fail
        # subpoena:enforcement_point
        def serve(user):
            if user == "mallory":
                return 403  # subpoena:enforcement
            if user == "ann":
                return 200
            witness_fail("the app says so")
    """, "test_app.py": """
        from app import serve
        def test_refused():
            assert serve("ann") == 200
            serve("mallory")
    """}, require_witness=True)
    assert r.outcome == CRASHED


# --- a witness that could not see saw nothing (review 3: g11, Python form) ---

BLIND = """
    from app import serve
    from subpoena.harness import {imports}
    class Blind:
        def spawned(self, trace):
            return []
        def dialed(self, trace):
            return []
        def health(self):
            return None if serve("mallory").status == 403 else "37 failed scans"
    def test_refused({args}):
        {call}
"""


@pytest.mark.parametrize("imports,args,call", [
    ("require_no_spawn", "", 'require_no_spawn(Blind(), "t")'),
    ("require_no_dial", "", 'require_no_dial(Blind(), "t")'),
    ("watch_spawns, SpawnRule", "request", 'watch_spawns(request.addfinalizer, Blind(), "t", SpawnRule())'),
    ("check_no_spawn, witness_fail", "", 'witness_fail(check_no_spawn(Blind(), "t") or "")  if serve("mallory").status != 403 else None'),
])
def test_an_inconclusive_capture_is_no_witness_evidence(tmp_path, imports, args, call):
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": BLIND.format(imports=imports, args=args, call=call)},
                require_witness=True)
    assert r.outcome == KILLED_BY_SELF_REPORT and r.evidence == "other"
    assert r.first_failure.startswith("inconclusive:")


def test_a_sighting_ahead_of_bad_health_stays_witness_evidence(tmp_path):
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": """
        from types import SimpleNamespace as P
        from app import serve
        from subpoena.harness import watch_spawns, SpawnRule
        class Saw:
            def spawned(self, trace):
                bad = serve("mallory").status != 403
                return [P(pid=7, command="rm", attribution="cgroup", command_source="cmdline")] if bad else []
            def health(self):
                return None if serve("mallory").status == 403 else "37 failed scans"
        def test_refused(request):
            watch_spawns(request.addfinalizer, Saw(), "t", SpawnRule(never=["rm"]))
    """}, require_witness=True)
    assert r.outcome == KILLED and r.evidence == "witness"


# --- -select keeps an unconfirmed (review 3: p05) ---

def test_select_does_not_replace_unconfirmed_with_a_kill(tmp_path):
    # Runs: baseline, coverage, subset, mutant (red), rerun (red), then a
    # whole-suite retry would be red too, with a green rerun after it.
    count = tmp_path / "count"
    r = outcome(tmp_path / "p", {"app.py": BODY, "test_app.py": f"""
        import os
        from app import serve
        def test_allowed():
            p = {str(count)!r}
            n = (len(open(p).read()) if os.path.exists(p) else 0) + 1
            open(p, "w").write("x" * n)
            assert n not in (4, 5, 6), f"flake on run {{n}}"
            serve("mallory")
            assert serve("ann").status == 200
    """}, select=True)
    assert r.outcome == UNCONFIRMED


# --- a detached child holding the pipe (review 3: p06) ---

DETACHED = """
    import subprocess
    from app import serve
    def test_refused():
        subprocess.Popen(["setsid", "sleep", "25"])
        assert serve("mallory").status == 403
"""


def test_a_detached_child_on_the_pipe_does_not_outlast_the_run(tmp_path, monkeypatch):
    monkeypatch.setattr(cross, "_PIPE_GRACE", 1.0, raising=False)
    start = time.monotonic()
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": DETACHED}, "-s", timeout=5)
    assert r.outcome == KILLED and time.monotonic() - start < 20


def test_a_timeout_stops_waiting_for_a_detached_child(tmp_path, monkeypatch):
    monkeypatch.setattr(cross, "_PIPE_GRACE", 1.0, raising=False)
    root = project(tmp_path, {"test_app.py": """
        import subprocess, time
        def test_hangs():
            subprocess.Popen(["setsid", "sleep", "25"])
            print("before the hang", flush=True)
            time.sleep(60)
    """})
    start = time.monotonic()
    code, out = cross._run_suite(root, ["-s"], 3, "", str(tmp_path / "report"))
    assert code is None and "before the hang" in out and time.monotonic() - start < 15


# --- a read-only directory left by a test (review 3: M7) ---

def test_a_read_only_directory_neither_aborts_nor_stays(tmp_path, monkeypatch):
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    r = outcome(tmp_path / "p", {"app.py": BODY, "test_app.py": """
        import os
        from app import serve
        def test_refused():
            os.makedirs("cache/mod", exist_ok=True)
            open("cache/mod/f", "w").close()
            os.chmod("cache/mod", 0o555)
            os.chmod("cache", 0o555)
            assert serve("mallory").status == 403
    """})
    assert r.outcome == KILLED
    assert os.listdir(scratch) == []


# --- what a test can tell of the run it is in (review 3: p09, p07) ---

def test_a_test_cannot_read_that_it_is_a_mutant_run(tmp_path):
    r = outcome(tmp_path, {"app.py": BODY, "test_app.py": """
        import os
        from app import serve
        def test_allowed():
            assert serve("ann").status == 200
        def test_env():
            assert not os.environ.get("SUBPOENA_CROSS_MUTATED"), "red only under a mutant"
    """})
    assert r.outcome == SURVIVED


def test_reruns_under_xdist_run_the_failed_tests_only(tmp_path):
    count = tmp_path / "count"
    r = outcome(tmp_path / "p", {"app.py": BODY, "test_app.py": f"""
        from app import serve
        def test_refused():
            assert serve("mallory").status == 403
        def test_unrelated():
            with open({str(count)!r}, "a") as f:
                f.write("x")
    """}, "-n", "2")
    assert r.outcome == KILLED
    assert len(count.read_text()) == 2  # baseline and mutant, not the rerun
