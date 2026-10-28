# subpoena:spec_derived (from docs/ports.md W3-W4 and conformance/witness.yaml)
"""conformance/witness.yaml through read_log and no_spawn: the same cases the
Go reader passes."""

import io

import pytest
import yaml

from conftest import CONFORMANCE
from subpoena.harness import no_spawn
from subpoena.witness import WitnessError, read_log

DOC = yaml.safe_load((CONFORMANCE / "witness.yaml").read_text())
TRACES, CASES = DOC["traces"], DOC["cases"]


def test_the_cases_are_there():
    assert len(CASES) >= 10
    assert set(DOC) == {"traces", "cases"}


KEYS = {"name", "lines", "read_error", "health", "spawned", "no_spawn"}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_witness_case(case):
    assert set(case) <= KEYS, f"unknown keys {set(case) - KEYS}"
    assert bool(case.get("read_error")) != bool(case.get("health")), "exactly one of read_error and health"
    src = io.StringIO("\n".join(case.get("lines") or []) + "\n")
    if case.get("read_error"):
        with pytest.raises(WitnessError, match=case["read_error"].replace("(", r"\(").replace(")", r"\)")):
            read_log(src)
        return
    log = read_log(src)
    h = log.health()
    if case["health"] == "ok":
        assert h is None
    else:
        assert h is not None and case["health"] in h
    for name, pids in (case.get("spawned") or {}).items():
        assert [e.pid for e in log.spawned(TRACES[name])] == pids
    for name, want in (case.get("no_spawn") or {}).items():
        v, _ = no_spawn(log, TRACES[name])
        assert str(v) == want, name
