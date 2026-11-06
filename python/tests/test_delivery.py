# subpoena:impl_derived (ported from pkg/harness/delivery_test.go, after reading it)
"""The delivery checks over the witness file: no_delivery, require_no_delivery,
check_no_delivery and delivery_to. conformance/witness.yaml holds the reader's
cases; these are the matching rules and the messages."""

import io
import json

import pytest

from subpoena.harness import Verdict, check_no_delivery, delivery_to, no_delivery, require_no_delivery
from subpoena.witness import OP_DELIVER, OP_SENDMSG, AddrPort, DeliveryEvent, read_log

TRACE = "c0de00000000000000000000000000a1"
SUBSCRIBER = "127.0.0.1:40001"
PUBLISHER = "127.0.0.1:40002"


def log(*peers, stop=None):
    lines = [{"time": "2026-11-05T12:00:00Z", "record": "start", "healthy": False, "captures": ["exec", "delivery"]}]
    for p in peers:
        lines.append({"time": "2026-11-05T12:00:01Z", "delivery_op": OP_DELIVER, "pid": 7, "host_pid": 4007,
                      "comm": "broker", "protocol": "tcp", "peer": p, "local": "127.0.0.1:1883", "bytes": 21,
                      "cgroup_id": 91, "cgroup": "subpoena/" + TRACE, "trace_id": TRACE, "attribution": "cgroup"})
    lines.append(stop or {"time": "2026-11-05T12:00:09Z", "record": "stop", "healthy": True,
                          "coverage": "2 send(s) reported"})
    return read_log(io.StringIO("\n".join(json.dumps(l) for l in lines) + "\n"))


def test_a_line_reads_back_as_an_event():
    (e,) = log(SUBSCRIBER).delivered(TRACE)
    assert (e.op, e.peer, e.local, e.protocol, e.bytes) == (OP_DELIVER, AddrPort.of(SUBSCRIBER), AddrPort.of("127.0.0.1:1883"), "tcp", 21)
    assert (e.pid, e.comm, e.cgroup_id, e.attribution) == (7, "broker", 91, "cgroup")
    assert e.seen_at is not None and not e.peer_unknown


def test_the_empty_trace_matches_nothing_and_the_stop_record_gives_coverage():
    l = log(SUBSCRIBER)
    assert l.delivered("") == []
    assert l.coverage() == "2 send(s) reported"
    assert log(SUBSCRIBER, stop={"time": "2026-11-05T12:00:09Z", "record": "stop", "healthy": True}).coverage() == ""


def test_a_file_with_no_delivery_capture_proves_no_absence():
    def file(start):
        lines = [{"time": "2026-11-05T12:00:00Z", "record": "start", "healthy": False, **start},
                 {"time": "2026-11-05T12:00:09Z", "record": "stop", "healthy": True}]
        return read_log(io.StringIO("\n".join(json.dumps(l) for l in lines) + "\n"))
    assert no_delivery(file({}), TRACE)[0] is Verdict.INCONCLUSIVE
    assert no_delivery(file({"captures": ["exec"]}), TRACE)[0] is Verdict.INCONCLUSIVE
    assert no_delivery(file({"captures": ["exec", "delivery"]}), TRACE)[0] is Verdict.PASS
    assert "no delivery capture" in check_no_delivery(file({}), TRACE)


@pytest.mark.parametrize("bad", ["[1.2.3.4]:5", "1.2.3.4:5\n", "[fe80::1%eth0]:5"])
def test_an_address_go_refuses_is_refused(bad):
    with pytest.raises(ValueError):
        AddrPort.of(bad)


def test_a_delivery_line_is_not_an_exec():
    l = log(SUBSCRIBER)
    assert len(l) == 0 and l.spawned(TRACE) == []


@pytest.mark.parametrize("peers,want", [
    ([SUBSCRIBER], Verdict.FAIL),
    ([PUBLISHER], Verdict.PASS),
    ([SUBSCRIBER, PUBLISHER], Verdict.FAIL),
])
def test_no_delivery_is_about_the_peer(peers, want):
    assert no_delivery(log(*peers), TRACE, delivery_to(SUBSCRIBER))[0] is want


def test_an_unhealthy_capture_proves_no_absence_but_a_sighting_stands():
    bad = {"time": "2026-11-05T12:00:09Z", "record": "stop", "healthy": False, "error": "lost 3 kernel event(s)"}
    assert no_delivery(log(PUBLISHER, stop=bad), TRACE, delivery_to(SUBSCRIBER))[0] is Verdict.INCONCLUSIVE
    assert no_delivery(log(SUBSCRIBER, stop=bad), TRACE, delivery_to(SUBSCRIBER))[0] is Verdict.FAIL


def test_a_witness_with_no_health_proves_no_absence():
    class NoHealth:
        def delivered(self, trace_id):
            return []
    assert no_delivery(NoHealth(), TRACE)[0] is Verdict.INCONCLUSIVE


def test_messages_are_tagged():
    assert check_no_delivery(log(PUBLISHER), TRACE, delivery_to(SUBSCRIBER)) is None
    assert check_no_delivery(log(SUBSCRIBER), TRACE).startswith("witness: no delivery")
    bad = {"time": "2026-11-05T12:00:09Z", "record": "stop", "healthy": False}
    assert check_no_delivery(log(stop=bad), TRACE).startswith("inconclusive: no delivery")
    with pytest.raises(AssertionError):
        require_no_delivery(log(SUBSCRIBER), TRACE)
    require_no_delivery(log(PUBLISHER), TRACE, delivery_to(SUBSCRIBER))


@pytest.mark.parametrize("rule,peer,want", [
    ([SUBSCRIBER], SUBSCRIBER, True),
    ([SUBSCRIBER], PUBLISHER, False),
    ([SUBSCRIBER], "192.0.2.8:40001", False),
    (["127.0.0.1:0"], PUBLISHER, True),
    (["0.0.0.0:40001"], "192.0.2.8:40001", True),
    (["0.0.0.0:40001"], PUBLISHER, False),
    (["[::ffff:127.0.0.1]:40001"], SUBSCRIBER, True),
    ([PUBLISHER, SUBSCRIBER], SUBSCRIBER, True),
    ([SUBSCRIBER], None, True),
    ([SUBSCRIBER], "0.0.0.0:0", True),
    ([SUBSCRIBER], "127.0.0.1:0", True),
    ([SUBSCRIBER], "192.0.2.8:0", False),
    ([], PUBLISHER, True),
])
def test_delivery_to(rule, peer, want):
    e = DeliveryEvent(op=OP_SENDMSG, peer=AddrPort.of(peer) if peer else None, local=None)
    assert delivery_to(*rule)(e) is want
