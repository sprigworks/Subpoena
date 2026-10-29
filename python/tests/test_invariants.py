# subpoena:impl_derived (written after reading invariants/invariants.go and subpoena/invariants.py)
"""Invariants load by name from invariants/*.traceql, trimmed, and an unknown
or path-shaped name is an error, never an empty query."""

import pytest

from conftest import ROOT
from subpoena import invariants
from subpoena.invariants import InvariantError


def test_load_finds_the_repository_invariants_above_the_caller():
    want = (ROOT / "invariants" / "no_exec_after_deny.traceql").read_text().strip()
    assert invariants.load("no_exec_after_deny") == want
    assert invariants.load("no_exec_after_deny", ROOT / "invariants") == want
    assert "no_exec_after_deny" in invariants.names()


def test_load_trims_and_lists_sorted(tmp_path):
    (tmp_path / "b.traceql").write_text("\n  { name = \"b\" }\n\n")
    (tmp_path / "a.traceql").write_text('{ name = "a" }')
    (tmp_path / "notes.txt").write_text("not an invariant")
    assert invariants.load("b", tmp_path) == '{ name = "b" }'
    assert invariants.names(tmp_path) == ["a", "b"]


@pytest.mark.parametrize("name", ["missing", "../invariants/no_exec_after_deny", "a/b", "", "..", ".hidden"])
def test_unknown_or_path_names_are_errors(tmp_path, name):
    (tmp_path / "a.traceql").write_text('{ name = "a" }')
    with pytest.raises(InvariantError):
        invariants.load(name, tmp_path)


def test_missing_directory_is_an_error(tmp_path):
    with pytest.raises(InvariantError):
        invariants.load("a", tmp_path / "nope")
    with pytest.raises(InvariantError):
        invariants.find(tmp_path)
