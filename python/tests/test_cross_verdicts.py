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


