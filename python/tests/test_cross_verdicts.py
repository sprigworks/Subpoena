# subpoena:impl_derived
"""Verdicts that must not overstate proof, each built from a repro of the second
trial-fixes review, through real pytest runs."""

import textwrap

import pytest

from subpoena import cross
from subpoena.cross import CRASHED, INVALID, KILLED, SURVIVED

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


def test_the_tests_own_message_still_carries_the_tag(tmp_path):
    r = outcome(tmp_path, {"auth.py": CHATTY, "test_a.py": """
        from auth import gate
        def test_denied():
            assert gate("mallory") == "denied", "witness: it ran"
    """}, require_witness=True)
    assert r.outcome == KILLED and r.evidence == "witness" and r.first_failure == "witness: it ran"


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
               failure("t::b", "no error"), failure("t::a", "witness: spawned"),
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
