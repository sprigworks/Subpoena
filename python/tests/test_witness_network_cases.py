# subpoena:spec_derived (from docs/ports.md W4, W6 and conformance/witness-network.yaml)
"""conformance/witness-network.yaml through read_network_log and no_dial: the
same cases the Go reader passes."""

import io
import os
from pathlib import Path

import pytest
import yaml

from conftest import CONFORMANCE
from subpoena.harness import dial_to, no_dial
from subpoena.witness import NetworkEvent, WitnessError, read_log, read_network_log

DOC = yaml.safe_load((CONFORMANCE / "witness-network.yaml").read_text())
TRACES, CASES = DOC["traces"], DOC["cases"]

# The cases conformance/witness_kernel_linux_test.go builds from real
# subpoena-witness -net-out output on a real kernel (make
# test-witness-parity). Without the file they skip, unless
# SUBPOENA_WITNESS_CAPTURE_REQUIRE=1.
CAPTURE = os.environ.get("SUBPOENA_WITNESS_NETWORK_CAPTURE")
CAPTURE_DOC = yaml.safe_load(Path(CAPTURE).read_text()) if CAPTURE and Path(CAPTURE).is_file() else None

KEYS = {"name", "lines", "read_error", "health", "dialed", "no_dial"}


def test_the_cases_are_there():
    assert len(CASES) >= 30
    assert set(DOC) == {"traces", "cases"}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_witness_network_case(case):
    check_case(case, TRACES)


def test_kernel_network_capture_cases():
    if CAPTURE_DOC is None:
        msg = f"no kernel network capture file at SUBPOENA_WITNESS_NETWORK_CAPTURE={CAPTURE!r}"
        if os.environ.get("SUBPOENA_WITNESS_CAPTURE_REQUIRE") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    assert set(CAPTURE_DOC) == {"traces", "cases"}
    cases = CAPTURE_DOC["cases"]
    assert sorted(c["name"] for c in cases) == sorted([
        "capture_healthy", "capture_killed_before_stop", "capture_attempts_only",
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
            read_network_log(src)
        return
    log = read_network_log(src)
    h = log.health()
    if case["health"] == "ok":
        assert h is None
    else:
        assert h is not None and case["health"] in h
    for name, dests in (case.get("dialed") or {}).items():
        assert [str(e.dest) for e in log.dialed(traces[name])] == (dests or [])
    for name, want in (case.get("no_dial") or {}).items():
        v, _ = no_dial(log, traces[name])
        assert str(v) == want, name


A = TRACES["A"]
START = '{"time":"2026-10-28T12:00:00Z","record":"start","healthy":false}'
STOP = '{"time":"2026-10-28T12:00:09Z","record":"stop","healthy":true}'


def read(*lines):
    return read_network_log(io.StringIO("\n".join(lines) + "\n"))


def test_dialed_maps_every_field():
    log = read(START, '{"time":"2026-10-28T12:00:01Z","op":"sendmsg","protocol":"udp","dest":"[::ffff:192.0.2.1]:9",'
               '"pid":7,"host_pid":4007,"comm":"curl","sock_type":2,"cgroup_id":91,"cgroup":"subpoena/' + A + '",'
               '"trace_id":"' + A + '","attribution":"cgroup"}', STOP)
    (e,) = log.dialed(A)
    assert isinstance(e, NetworkEvent)
    assert (str(e.dest), e.op, e.protocol, e.pid, e.comm, e.cgroup, e.cgroup_id, e.trace_id, e.attribution) == (
        "192.0.2.1:9", "sendmsg", "udp", 7, "curl", "subpoena/" + A, 91, A, "cgroup")
    assert e.seen_at.isoformat() == "2026-10-28T12:00:01+00:00"
    assert log.dialed("") == [] and len(log) == 1
    assert len(log.dialed(A.upper())) == 1, "a trace ID matches whatever its case, as netbpf.Witness.Dialed"


def test_dial_to_and_no_dial_work_unchanged():
    log = read(START, '{"time":"2026-10-28T12:00:01Z","dest":"127.0.0.1:5000","trace_id":"' + A + '"}', STOP)
    assert str(no_dial(log, A, dial_to("127.0.0.1:5000"))[0]) == "Fail"
    assert str(no_dial(log, A, dial_to("127.0.0.1:0"))[0]) == "Fail"
    assert str(no_dial(log, A, dial_to("192.0.2.1:9"))[0]) == "Pass"


def test_faults_read_as_in_the_exec_file():
    # One set of window rules: the same fault in both files, but for the noun.
    exec_line = '{"time":"2026-10-28T12:00:01Z","pid":7,"trace_id":"' + A + '"}'
    net_line = '{"time":"2026-10-28T12:00:01Z","dest":"192.0.2.1:9","pid":7,"trace_id":"' + A + '"}'
    for shape in (["E"], ["S", "E"], ["E", "S", "T"], ["S", "T", "S", "T"], ["S", "S", "T"], ["T"]):
        def file(ev):
            return io.StringIO("\n".join({"S": START, "T": STOP, "E": ev}[x] for x in shape) + "\n")
        eh, nh = read_log(file(exec_line)).health(), read_network_log(file(net_line)).health()
        assert eh is not None and eh == nh.replace("a connection attempt", "an exec"), shape
