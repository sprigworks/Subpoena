# subpoena:impl_derived (ported from pkg/witness/sinkhole_test.go and pkg/harness/network_test.go, after reading them)
"""The network witness and its absence checks: Sinkhole, no_dial,
require_no_dial, check_no_dial and dial_to."""

import socket

import pytest
import yaml

from conftest import CONFORMANCE
from subpoena import witness
from subpoena.harness import (Verdict, check_no_dial, check_no_spawn, dial_to, no_dial, require_no_dial)
from subpoena.witness import BY_DESTINATION, MARK_HEADER, OP_CONNECT, AddrPort, NetworkEvent, Sinkhole


def dial(s, n=1):
    for _ in range(n):
        c = socket.create_connection((str(s.addr.addr), s.addr.port), timeout=1)
        c.close()


def test_sinkhole_records_arrivals_for_every_trace():
    s = Sinkhole()
    dial(s, 3)
    assert s.stop() is None
    assert s.health() is None
    for trace in ("a", "b"):
        got = s.dialed(trace)
        assert len(got) == 3
        for e in got:
            assert (e.dest, e.op, e.protocol, e.attribution) == (s.addr, OP_CONNECT, "tcp", BY_DESTINATION)


def test_sinkhole_counts_every_connection_before_stop():
    # Many connections that hang up at once, right before stop: every
    # completed one is counted, whether the accept loop or stop's drain took it.
    s = Sinkhole()
    dial(s, 200)
    assert s.stop() is None
    assert len(s.dialed("")) == 200


def test_sinkhole_drain_counts_queued_connections():
    s = Sinkhole()
    s._wake_w.send(b"x")  # stop the accept loop: nobody accepts, all five queue
    s._thread.join()
    dial(s, 5)
    assert s._drain() == (5, None)
    assert s._drain() == (0, None)
    s.stop()


def test_sinkhole_health_needs_stop():
    s = Sinkhole()
    assert s.health() is not None, "a running sinkhole must not certify absence"
    s.stop()
    assert s.health() is None and s.stop() is None, "stopped sinkhole should be healthy, and stop repeatable"


def test_sinkhole_failed_drain_cannot_certify_absence(monkeypatch):
    # A failed drain means queued connections may have gone unseen: stop and
    # health must both say so, and keep saying so, though dialed is empty.
    monkeypatch.setattr(witness, "_drain", lambda s: (0, OSError("accept queue unreadable")))
    s = Sinkhole()
    err = s.stop()
    assert err is not None and "accept queue unreadable" in err
    assert s.health() == err
    assert s.dialed("") == []
    assert s.stop() == err, "second stop erased the failure"


class UnknownNet:
    def __init__(self, events=()):
        self.events = list(events)

    def dialed(self, trace_id):
        return self.events


class HealthNet(UnknownNet):
    def __init__(self, events=(), err=None):
        super().__init__(events)
        self.err = err

    def health(self):
        return self.err


EVIL = AddrPort.of("192.0.2.7:443")
ALLOWED = AddrPort.of("198.51.100.1:443")
GAP = "observation lost"


def seen(d):
    return [NetworkEvent(dest=d, pid=42)]


@pytest.mark.parametrize("w,match,want", [
    (HealthNet(), None, Verdict.PASS),
    (HealthNet(err=GAP), None, Verdict.INCONCLUSIVE),
    (UnknownNet(), None, Verdict.INCONCLUSIVE),
    (HealthNet(seen(EVIL)), None, Verdict.FAIL),
    (HealthNet(seen(EVIL), GAP), None, Verdict.FAIL),
    (HealthNet(seen(ALLOWED)), dial_to(EVIL), Verdict.PASS),
    (HealthNet(seen(ALLOWED), GAP), dial_to(EVIL), Verdict.INCONCLUSIVE),
    (HealthNet(seen(EVIL)), dial_to(EVIL), Verdict.FAIL),
], ids=["healthy empty", "unhealthy empty", "unknown empty", "healthy observed", "unhealthy observed",
        "observed, not matched", "observed, not matched, unhealthy", "matched"])
def test_no_dial_needs_healthy_capture(w, match, want):
    got, err = no_dial(w, "trace", match)
    assert got is want
    assert (err is None) == (got is Verdict.PASS)
    msg = check_no_dial(w, "trace", match)
    assert (msg is None) == (got is Verdict.PASS)
    if got is Verdict.PASS:
        require_no_dial(w, "trace", match)
    else:
        tag = "inconclusive" if got is Verdict.INCONCLUSIVE else "witness"
        assert msg.startswith(f"{tag}: no dial for trace: ")
        with pytest.raises(AssertionError, match=f"^{tag}: no dial for trace: "):
            require_no_dial(w, "trace", match)


@pytest.mark.parametrize("rule,dest,want", [
    ("192.0.2.7:443", "192.0.2.7:443", True),
    ("192.0.2.7:443", "192.0.2.7:80", False),
    ("192.0.2.7:0", "192.0.2.7:80", True),
    ("192.0.2.7:443", "[::ffff:192.0.2.7]:443", True),
    ("[::ffff:192.0.2.7]:443", "192.0.2.7:443", True),
    ("192.0.2.7:443", "192.0.2.8:443", False),
    (("2001:db8::1", 443), "[2001:db8::1]:443", True),
], ids=["exact", "other port", "any port", "mapped dest", "mapped rule", "other addr", "v6 pair"])
def test_dial_to(rule, dest, want):
    assert dial_to(rule)(NetworkEvent(dest=AddrPort.of(dest))) is want


def test_dial_to_refuses_names():
    with pytest.raises(ValueError):
        dial_to("example.com:443")


def test_sinkhole_end_to_end_with_require_no_dial():
    s = Sinkhole()
    dial(s)
    s.stop()
    with pytest.raises(AssertionError, match=": Fail: "):
        require_no_dial(s, "c0de00000000000000000000000000a1", dial_to(s.addr))
    quiet = Sinkhole()
    with pytest.raises(AssertionError, match=": Inconclusive: "):
        require_no_dial(quiet, "c0de00000000000000000000000000a1")
    quiet.stop()
    require_no_dial(quiet, "c0de00000000000000000000000000a1")


def test_check_no_spawn_reports_without_raising():
    assert check_no_spawn(HealthSpawns([]), "t") is None
    assert check_no_spawn(HealthSpawns(["x"]), "t").startswith("witness: no spawn for t: ")


class HealthSpawns:
    def __init__(self, spawned):
        self._spawned = spawned

    def spawned(self, trace_id):
        return self._spawned

    def health(self):
        return None


@pytest.mark.parametrize("bad", ["2001:db8::1:443", "1.2.3.4: 80", "1.2.3.4:+80", "1.2.3.4:", "1.2.3.4:70000",
                                 "[1.2.3.4]:80x", "1.2.3.4"])
def test_addr_port_parses_as_go_does(bad):
    with pytest.raises(ValueError):
        AddrPort.of(bad)


def test_addr_port_refuses_a_non_integer_port():
    for port in ("443", True, 4.0):
        with pytest.raises(ValueError):
            AddrPort.of(("192.0.2.7", port))


def test_concurrent_stops_agree():
    import threading
    s = Sinkhole()
    dial(s, 2)
    results = []
    ts = [threading.Thread(target=lambda: results.append(s.stop())) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert results == [None] * 8 and s.health() is None and len(s.dialed("")) == 2


def test_addrport_normalizes_a_directly_constructed_mapped_address():
    import ipaddress

    from subpoena.witness import AddrPort

    mapped = AddrPort(ipaddress.ip_address("::ffff:127.0.0.1"), 0)
    assert mapped == AddrPort.of("127.0.0.1:0")
    assert isinstance(mapped.addr, ipaddress.IPv4Address)
    with pytest.raises(ValueError):
        AddrPort(ipaddress.ip_address("127.0.0.1"), 65536)


def test_a_mapped_filter_still_sees_a_real_connection():
    import ipaddress
    import socket

    from subpoena.harness import Verdict, dial_to, no_dial, require_no_dial
    from subpoena.witness import AddrPort, Sinkhole

    s = Sinkhole()
    try:
        socket.create_connection((str(s.addr.addr), s.addr.port), timeout=1).close()
    finally:
        s.stop()
    assert s.health() is None
    assert len(s.dialed("trace")) == 1
    for port in (s.addr.port, 0):
        mapped = AddrPort(ipaddress.ip_address("::ffff:" + str(s.addr.addr)), port)
        verdict, _ = no_dial(s, "trace", dial_to(mapped))
        assert verdict is Verdict.FAIL
        with pytest.raises(AssertionError):
            require_no_dial(s, "trace", dial_to(mapped))


# --- answering Sinkhole: an upstream that must answer, with marks ---

def _get(s, mark=""):
    import http.client
    c = http.client.HTTPConnection(str(s.addr.addr), s.addr.port, timeout=5)
    c.request("POST", "/secret?x=1", body=b"a body", headers={MARK_HEADER: mark} if mark else {})
    r = c.getresponse()
    out = r.status, r.read()
    c.close()
    return out


def test_answering_sinkhole_answers_and_records_the_request():
    s = Sinkhole(answer=True)
    assert _get(s, "a") == (200, b"")
    assert s.stop() is None and s.health() is None
    (e,) = s.marked("a")
    assert e.request == "POST /secret?x=1 HTTP/1.1"
    assert e.attribution == BY_DESTINATION
    assert e.headers[MARK_HEADER.lower()] == "a"
    assert "secret" not in repr(e)


def test_a_mark_hides_no_arrival():
    s = Sinkhole(answer=True)
    for mark in ("a", "b", ""):
        _get(s, mark)
    s.stop()
    assert len(s.marked("a")) == 1
    assert len(s.dialed("c")) == 3


def test_a_client_that_keeps_sending_does_not_hold_stop():
    import socket
    import time
    s = Sinkhole(answer=True)
    c = socket.create_connection((str(s.addr.addr), s.addr.port))
    c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    done = time.monotonic() + 4
    try:
        while time.monotonic() < 1 + (done - 4):
            c.sendall(b"x")
            time.sleep(0.05)
    except OSError:
        pass
    start = time.monotonic()
    s.stop()
    c.close()
    assert time.monotonic() - start < 2.5


def test_an_arrival_that_is_not_http_still_counts():
    import socket
    s = Sinkhole(answer=True)
    c = socket.create_connection((str(s.addr.addr), s.addr.port))
    c.sendall(b"not http\r\n\r\n")
    c.close()
    assert s.stop() is None
    (e,) = s.dialed("any")
    assert e.request == "" and e.attribution == BY_DESTINATION


# Review 6, finding 14, and Review 7, finding 9: the same bytes read the same in
# both languages, from one table (pkg/witness/sinkhole_test.go reads it too). Only
# marked() and the answer differ by request: dialed() sees every arrival.
SINKHOLE = yaml.safe_load((CONFORMANCE / "sinkhole.yaml").read_text())


def test_the_sinkhole_cases_are_there():
    assert len(SINKHOLE["cases"]) >= 60


@pytest.mark.parametrize("case", SINKHOLE["cases"], ids=[c["name"] for c in SINKHOLE["cases"]])
def test_marked_reads_a_request_as_go_does(case):
    raw = case["request"].replace("@FILL@", "y" * case.get("fill", 0)).encode("latin-1")
    s = Sinkhole(answer=True)
    c = socket.create_connection((str(s.addr.addr), s.addr.port), timeout=5)
    c.sendall(raw)
    c.shutdown(socket.SHUT_WR)
    reply = b""
    while True:
        chunk = c.recv(4096)
        if not chunk:
            break
        reply += chunk
    c.close()
    s.stop()
    assert bool(reply) == case["answered"], reply
    for mark in SINKHOLE["probes"]:
        assert len(s.marked(mark)) == (1 if mark in case["marks"] else 0), mark
    assert len(s.dialed("any")) == 1
