# subpoena:spec_derived (from docs/ports.md W3-W4 and conformance/witness.yaml)
"""conformance/witness.yaml through read_log and no_spawn: the same cases the
Go reader passes."""

import io
import os
from pathlib import Path

import pytest
import yaml

from conftest import CONFORMANCE
from subpoena.harness import no_spawn
from subpoena.witness import WitnessError, read_log

DOC = yaml.safe_load((CONFORMANCE / "witness.yaml").read_text())
TRACES, CASES = DOC["traces"], DOC["cases"]

# The cases conformance/witness_kernel_linux_test.go builds from real
# subpoena-witness output on a real kernel (make test-witness-parity). Without
# the file they skip, unless SUBPOENA_WITNESS_CAPTURE_REQUIRE=1.
CAPTURE = os.environ.get("SUBPOENA_WITNESS_CAPTURE")
CAPTURE_DOC = yaml.safe_load(Path(CAPTURE).read_text()) if CAPTURE and Path(CAPTURE).is_file() else None


def test_the_cases_are_there():
    assert len(CASES) >= 10
    assert set(DOC) == {"traces", "cases"}


KEYS = {"name", "lines", "read_error", "health", "spawned", "no_spawn"}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_witness_case(case):
    check_case(case, TRACES)


def test_kernel_capture_cases():
    if CAPTURE_DOC is None:
        msg = f"no kernel capture file at SUBPOENA_WITNESS_CAPTURE={CAPTURE!r}"
        if os.environ.get("SUBPOENA_WITNESS_CAPTURE_REQUIRE") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    assert set(CAPTURE_DOC) == {"traces", "cases"}
    cases = CAPTURE_DOC["cases"]
    assert sorted(c["name"] for c in cases) == sorted([
        "capture_healthy", "capture_killed_before_stop", "capture_execs_only",
        "capture_lost_events", "capture_two_windows", "capture_cut_mid_line"])
    for case in cases:
        try:
            check_case(case, CAPTURE_DOC["traces"])
        except AssertionError as exc:
            raise AssertionError(f"{case['name']}: {exc}") from exc


def check_case(case, traces):
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
        assert [e.pid for e in log.spawned(traces[name])] == pids
    for name, want in (case.get("no_spawn") or {}).items():
        v, _ = no_spawn(log, traces[name])
        assert str(v) == want, name
