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
    row_fields = set(witness._ROW_STR_FIELDS) | {"time", "event", "conn", "tables", "opaque", "rows", "outcome"}
    assert exec_fields | record_fields | row_fields == set(schema["properties"])
    assert schema["if"] == {"required": ["record"]}
    assert schema["else"]["if"] == {"required": ["event"]}
    assert tuple(schema["properties"]["outcome"]["enum"]) == witness.OUTCOMES
    assert schema["additionalProperties"] is True


ROW = {"time": "2026-11-06T12:00:01Z", "event": "row", "engine": "postgres", "conn": 1, "dest": "127.0.0.1:5432",
       "statement": "INSERT INTO users VALUES (1)", "verb": "INSERT", "tables": ["users"], "opaque": False,
       "rows": 1, "outcome": "committed", "attribution": "destination"}
START = '{"time":"2026-11-06T12:00:00Z","record":"start","healthy":false}'
STOP = '{"time":"2026-11-06T12:00:09Z","record":"stop","healthy":true}'


def row_file(*rows):
    return io.StringIO("\n".join([START, *[json.dumps(r) for r in rows], STOP]) + "\n")


def test_rows_are_read_and_filtered_by_outcome():
    log = read_log(row_file(ROW, {**ROW, "outcome": "rolled_back"}, {**ROW, "outcome": "read"}))
    assert log.health() is None
    assert len(log.rows()) == 3 and len(log) == 0
    for trace in (A, B, ""):
        got = log.committed(trace)
        assert [e.tables for e in got] == [["users"]] and got[0].attribution == "destination"


@pytest.mark.parametrize("rows,effect", [(1, True), (-1, True), (0, False)])
def test_row_effect(rows, effect):
    assert read_log(row_file({**ROW, "rows": rows})).committed()[0].effect is effect


def test_only_committed_is_an_effect():
    assert not read_log(row_file({**ROW, "outcome": "rolled_back"})).rows()[0].effect


@pytest.mark.parametrize("event,table,want", [
    (ROW, "users", True),
    (ROW, "USERS", True),
    (ROW, "orders", False),
    (ROW, "public.users", True),
    (ROW, "", True),
    ({**ROW, "tables": ["public.users"]}, "users", True),
    ({**ROW, "tables": ["public.users"]}, "other.users", False),
    ({**ROW, "tables": ["superusers"]}, "users", False),
    ({**ROW, "opaque": True}, "orders", True),
    ({**ROW, "tables": []}, "orders", True),
])
def test_row_touches(event, table, want):
    assert read_log(row_file(event)).rows()[0].touches(table) is want


@pytest.mark.parametrize("bad", [
    {"event": "file"},
    {"outcome": "maybe"},
    {"rows": None},
    {"rows": -2},
    {"rows": "1"},
    {"rows": True},
    {"conn": "1"},
    {"tables": "users"},
    {"tables": [1]},
    {"opaque": "no"},
    {"statement": 1},
    {"time": None},
])
def test_rows_it_cannot_read_are_errors(bad):
    with pytest.raises(WitnessError):
        read_log(row_file({**ROW, **bad}))


def test_row_with_no_count_is_an_error():
    r = dict(ROW)
    del r["rows"]
    with pytest.raises(WitnessError, match="no usable rows field"):
        read_log(row_file(r))
