# subpoena:impl_derived (ported from pkg/witness/log_test.go, after reading it)
"""The witness-file reader (docs/ports.md W3): the cases witness.ReadLog
passes, through subpoena.witness.read_log."""

import io
import json

import pytest

from conftest import ROOT
from subpoena.witness import WitnessError, read_log

A = "c0de00000000000000000000000000a1"
B = "c0de00000000000000000000000000b2"


def line(**kw):
    base = {"time": "2026-10-26T12:00:00Z", "pid": 7, "ppid": 1, "host_pid": 7, "comm": "x", "exe": "/x",
            "command": "x", "args": ["x"], "cgroup_id": 1, "cgroup": "subpoena/" + A,
            "trace_id": A, "attribution": "cgroup"}
    base.update(kw)
    return json.dumps({k: v for k, v in base.items() if v is not None})


def test_spawned_returns_every_line_of_that_trace():
    log = read_log(io.StringIO("\n".join([
        line(pid=7, command="rm -rf /tmp/x", exe="/usr/bin/rm"),
        line(pid=8, trace_id=B, cgroup="subpoena/" + B),
        line(pid=9, command="curl x", time="2026-10-26T12:00:02.123456789Z"),
    ]) + "\n"))
    got = log.spawned(A)
    assert [e.pid for e in got] == [7, 9]
    assert got[0].command == "rm -rf /tmp/x" and got[0].attribution == "cgroup"
    assert got[1].seen_at.microsecond == 123456
    assert len(log.spawned(B)) == 1
    assert log.spawned("c0de00000000000000000000000000ff") == []


def test_command_source_says_line_or_name():
    log = read_log(io.StringIO("\n".join([
        line(pid=7, command="rm -rf /tmp/x"),
        line(pid=8, comm="rm", command="", args=[]),
        line(pid=9, comm="", command="", args=[]),
    ]) + "\n"))
    got = {e.pid: (e.command, e.command_source) for e in log.spawned(A)}
    assert got == {7: ("rm -rf /tmp/x", "cmdline"), 8: ("rm", "comm"), 9: ("", "")}


def test_spawned_does_not_filter_on_the_command():
    log = read_log(io.StringIO(line(comm="", exe="", command="", args=[]) + "\n"))
    assert len(log.spawned(A)) == 1


def test_lines_without_a_trace_belong_to_no_session():
    log = read_log(io.StringIO(line(trace_id=None, attribution=None, cgroup="system.slice/cron.service") + "\n"))
    assert log.spawned("") == [] and len(log) == 1


def test_unknown_fields_and_blank_lines_are_ignored():
    log = read_log(io.StringIO("\n" + line(added_later={"a": 1}) + "\n\n"))
    assert len(log.spawned(A)) == 1


@pytest.mark.parametrize("bad", [
    '{"time":"2026-10-26T12:00:00Z","pid":7',
    '{"time":"2026-10-26T12:00:00Z","pid":"seven","trace_id":"' + A + '"}',
    "[1,2]",
    '{"pid":7,"trace_id":"' + A + '","attribution":"cgroup"}',
])
def test_a_malformed_line_is_an_error_with_its_line_number(bad):
    with pytest.raises(WitnessError, match="line 2"):
        read_log(io.StringIO('{"time":"2026-10-26T12:00:00Z","pid":1}\n' + bad + "\n"))


def test_the_schema_names_the_fields_the_reader_checks():
    schema = json.loads((ROOT / "docs" / "witness-event.schema.json").read_text())
    from subpoena import witness
    exec_fields = set(witness._INT_FIELDS) | set(witness._STR_FIELDS) | {"time", "args"}
    record_fields = {"time", "record", "healthy", "error"}
    assert exec_fields | record_fields == set(schema["properties"])
    assert schema["if"] == {"required": ["record"]}
    assert schema["additionalProperties"] is True
