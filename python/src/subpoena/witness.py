"""The witness, read from the file subpoena-witness writes (docs/ports.md, W;
schema: docs/witness-event.schema.json). A port of witness.ReadLog, and of
the Sinkhole network witness."""

from __future__ import annotations

import ipaddress
import json
import re
import selectors
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO, List, Optional, Tuple, Union

BY_CGROUP = "cgroup"


@dataclass
class ProcessEvent:
    pid: int
    ppid: int
    exe: str
    command: str
    cgroup: str
    cgroup_id: int
    trace_id: str
    attribution: str
    seen_at: datetime
    args: List[str] = field(default_factory=list)
    # "cmdline" when command is the argument list; "comm" when a line had no
    # argv and command is the task name (seen, not identified); "" when there
    # is neither.
    command_source: str = ""

    @property
    def name_only(self) -> bool:
        """The process was seen by its task name only: "touch" may have been
        an allowed "touch approved" or a refused "touch rejected"."""
        return self.command_source == "comm"


class WitnessError(ValueError):
    pass


# The integer fields and the range Go's reader decodes each into (int64 for
# the PIDs, uint64 for cgroup_id). A value outside it is an error there, so it
# is one here. null is the same as an absent field, as in Go.
_INT_FIELDS = {"pid": (-(2**63), 2**63 - 1), "ppid": (-(2**63), 2**63 - 1),
               "host_pid": (-(2**63), 2**63 - 1), "cgroup_id": (0, 2**64 - 1)}
_STR_FIELDS = ("comm", "exe", "command", "cgroup", "trace_id", "attribution")


_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_ZERO = datetime(1, 1, 1, tzinfo=timezone.utc)

# Every field name of an exec line or a record. A key that differs from one
# only by case is refused: Go's decoder would read it as that field.
_KNOWN = ("time", "pid", "ppid", "host_pid", "comm", "exe", "command", "args", "cgroup_id", "cgroup",
          "trace_id", "attribution", "record", "healthy", "error")


def _no_constant(name: str):
    """NaN and Infinity are not JSON, and Go's reader refuses them."""
    raise ValueError(f"{name} is not JSON")


def _parse_time(s) -> datetime:
    """RFC 3339 exactly, as Go's reader takes it, and never Go's zero time."""
    if not isinstance(s, str) or not _RFC3339.match(s):
        raise ValueError(f"time {s!r} is not RFC 3339")
    t = _parse_time_text(s)
    if t == _ZERO:
        raise ValueError("no time")
    return t


def _parse_time_text(s: str) -> datetime:
    # RFC 3339 with up to nanoseconds; fromisoformat takes microseconds at most.
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        n = 0
        while n < len(rest) and rest[n].isdigit():
            n += 1
        frac, tz = rest[:n], rest[n:]
        s = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    return datetime.fromisoformat(s)


_NO_RECORDS = ("witness: the file has no start or stop records, so its capture health is unknown "
               "(an older subpoena-witness wrote it, or it was cut short)")


class Log:
    """What subpoena-witness wrote, as a witness."""

    def __init__(self, lines: List[dict], health: Optional[str] = None):
        self._lines, self._health = lines, health

    def health(self) -> Optional[str]:
        """The first capture fault in the file, or None: no start or stop
        records, an exec outside a start..stop window, a window that never
        stopped, or a stop record saying the capture was unhealthy. Absence
        can rest on the file only when this is None."""
        return self._health

    def __len__(self) -> int:
        return len(self._lines)

    def lines(self) -> List[dict]:
        return [dict(l) for l in self._lines]

    def spawned(self, trace_id: str) -> List[ProcessEvent]:
        """Every exec whose trace ID, read by the kernel side from its cgroup,
        is trace_id. Nothing the application controls is consulted. The empty
        trace ID matches nothing."""
        if not trace_id:
            return []
        return [self._event(l) for l in self._lines if (l.get("trace_id") or "") == trace_id]

    @staticmethod
    def _event(l: dict) -> ProcessEvent:
        # subpoena-witness writes argv as the command. Without it, the task
        # name stands in, marked as name-only ("comm"), as in the Go reader.
        # A missing or null field is its zero value, as in Go.
        g = lambda k, zero: l.get(k) if l.get(k) is not None else zero  # noqa: E731
        command, source = g("command", ""), "cmdline"
        if not command:
            command = g("comm", "")
            source = "comm" if command else ""
        return ProcessEvent(
            pid=g("pid", 0), ppid=g("ppid", 0), exe=g("exe", ""), command=command,
            cgroup=g("cgroup", ""), cgroup_id=g("cgroup_id", 0), trace_id=g("trace_id", ""),
            attribution=g("attribution", ""), seen_at=_parse_time(l["time"]), args=list(g("args", [])),
            command_source=source,
        )


def read_log(f: IO[str]) -> Log:
    """Read subpoena-witness JSON lines. Blank lines and unknown fields are
    ignored. A line that does not decode, or has no time, raises WitnessError
    naming its line number: skipping it could turn an exec into an absence.
    Capture faults (see Log.health) do not stop the read: the execs are still
    evidence that something ran."""
    lines = []
    health: Optional[str] = None
    open_at, records, windows = 0, 0, 0  # open_at: line of the open window's start record

    def fault(msg: str) -> None:
        nonlocal health
        if health is None:
            health = msg

    for n, raw in enumerate(f, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            l = json.loads(raw, parse_constant=_no_constant)
            if not isinstance(l, dict):
                raise ValueError("not a JSON object")
            for k in l:
                for known in _KNOWN:
                    if k != known and k.lower() == known.lower():
                        raise ValueError(f"key {k!r} is {known!r} in another case")
            if l.get("record") is not None:
                rec = l["record"]
                if not l.get("time"):
                    raise ValueError("no time")
                _parse_time(l["time"])
                if l.get("healthy") is not None and not isinstance(l["healthy"], bool):
                    raise ValueError("healthy is not a boolean")
                if l.get("error") is not None and not isinstance(l["error"], str):
                    raise ValueError("error is not a string")
                if not isinstance(rec, str):
                    raise ValueError(f"record {rec!r} is not a string")
                if rec == "start":
                    if open_at:
                        fault(f"witness: line {n}: a capture started while the one from line {open_at} was still open")
                    open_at = n
                    windows += 1
                elif rec == "stop":
                    if not open_at:
                        fault(f"witness: line {n}: a stop with no capture open")
                    elif not l.get("healthy") or l.get("error"):
                        fault(f"witness: line {n}: capture unhealthy: {l.get('error') or ''}")
                    open_at = 0
                else:
                    raise ValueError(f"unknown record {rec!r}")
                records += 1
                continue
            for k, (lo, hi) in _INT_FIELDS.items():
                v = l.get(k)
                if v is None:
                    continue
                if isinstance(v, bool) or not isinstance(v, int):
                    raise ValueError(f"{k} is not an integer")
                if not lo <= v <= hi:
                    raise ValueError(f"{k} {v} is out of range")
            for k in _STR_FIELDS:
                if l.get(k) is not None and not isinstance(l[k], str):
                    raise ValueError(f"{k} is not a string")
            args = l.get("args")
            if args is not None and (not isinstance(args, list) or not all(isinstance(a, str) for a in args)):
                raise ValueError("args is not a list of strings")
            if not l.get("time"):
                raise ValueError("no time")
            _parse_time(l["time"])
        except ValueError as e:
            raise WitnessError(f"witness: line {n}: {e}") from None
        if not open_at:
            fault(f"witness: line {n}: an exec outside any capture window")
        lines.append(l)
    if records == 0:
        health = _NO_RECORDS  # every exec was outside a window too; say why, once
    elif open_at:
        fault(f"witness: the capture from line {open_at} never stopped: the witness was killed, "
              "or the file was read before it stopped")
    elif windows > 1:
        # Execs are tied to a window by file order, not time, and spawned()
        # filters by trace: a process that ran between two windows is in
        # neither, so nothing vouches for its absence.
        fault(f"witness: the file holds {windows} capture windows, and nothing watched between them; "
              "use one witness run per file")
    return Log(lines, health)


# The network witness (pkg/witness's NetworkEvent and Sinkhole). Go's eBPF
# connect witness (netbpf) is not ported; the sinkhole needs no root and no
# kernel support.

OP_CONNECT = "connect"  # connect() on an inet socket
OP_SENDMSG = "sendmsg"  # a send with an explicit destination
BY_DESTINATION = "destination"


# "v4:port" or "[v6]:port", as Go's netip.ParseAddrPort takes them: an
# unbracketed IPv6 address would split at its last colon into another address.
_ADDR_PORT = re.compile(r"^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)):([0-9]{1,5})$")


@dataclass(frozen=True)
class AddrPort:
    """An IP address and port. An IPv4-mapped IPv6 address is unmapped."""

    addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: int

    def __post_init__(self) -> None:
        # Normalize here, not only in of(): a directly constructed mapped
        # address would otherwise compare unequal to the same IPv4 address,
        # and a filter could miss a connection the witness saw.
        addr, port = self.addr, self.port
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError(f"port {port!r} is not 0 to 65535")
        if not isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            addr = ipaddress.ip_address(addr)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        object.__setattr__(self, "addr", addr)

    @staticmethod
    def of(a: Union["AddrPort", str, Tuple[str, int]]) -> "AddrPort":
        """An AddrPort from itself, a (host, port) pair, or "host:port"
        ("[v6]:port" for IPv6). Hosts are addresses, never names."""
        if isinstance(a, AddrPort):
            return a
        if isinstance(a, str):
            m = _ADDR_PORT.match(a)
            if not m:
                raise ValueError(f"{a!r} is not host:port ([host]:port for IPv6)")
            a = (m.group(1) or m.group(2), int(m.group(3)))
        host, port = a
        return AddrPort(ipaddress.ip_address(host), port)

    def __str__(self) -> str:
        if isinstance(self.addr, ipaddress.IPv6Address):
            return f"[{self.addr}]:{self.port}"
        return f"{self.addr}:{self.port}"


@dataclass
class NetworkEvent:
    """One observed outbound connection attempt. It records the attempt, not
    its outcome: a refused connect still counts, because "the code tried"
    contradicts "the code was denied"."""

    dest: AddrPort
    op: str = OP_CONNECT
    protocol: str = "tcp"
    pid: int = 0
    comm: str = ""
    cgroup: str = ""
    cgroup_id: int = 0
    trace_id: str = ""
    attribution: str = ""
    seen_at: Optional[datetime] = None


class Sinkhole:
    """A tier-1 network witness: a TCP listener the test stands up as a
    destination the code under test must never reach, then points that code
    at. Every connection that arrives is recorded and closed. The application
    cannot unsay a connection the listener accepted.

    It sees only its own address: "nothing reached the sinkhole" is the claim
    it can certify. Arrivals carry no PID or cgroup, so dialed() returns every
    arrival for every trace (BY_DESTINATION).

        s = Sinkhole()
        ... point the code at s.addr, run it ...
        s.stop()
        require_no_dial(s, trace_id)
    """

    def __init__(self) -> None:
        self._ln = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._ln.bind(("127.0.0.1", 0))
            self._ln.listen(socket.SOMAXCONN)
            self._ln.setblocking(False)
            self._wake_r, self._wake_w = socket.socketpair()
        except OSError as e:
            self._ln.close()
            raise OSError(f"sinkhole: {e}") from e
        self.addr = AddrPort.of(self._ln.getsockname())
        self._mu = threading.Lock()
        self._stopping = threading.Lock()  # one stop at a time
        self._events: List[NetworkEvent] = []
        self._err: Optional[str] = None
        self._finished = False
        self._thread = threading.Thread(target=self._accept, name="subpoena-sinkhole", daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        sel = selectors.DefaultSelector()  # not select.select: it fails on an fd over 1023
        try:
            sel.register(self._ln, selectors.EVENT_READ)
            sel.register(self._wake_r, selectors.EVENT_READ)
            while True:
                ready = [k.fileobj for k, _ in sel.select()]
                if self._wake_r in ready:
                    return
                n, err = self._drain()
                self._record(n)
                if err is not None:
                    self._fail(f"sinkhole: accept: {err}")
                    return
        except Exception as e:  # noqa: BLE001: any failure means arrivals may be unseen
            self._fail(f"sinkhole: accept: {e}")
        finally:
            sel.close()

    def _drain(self) -> "tuple[int, Optional[BaseException]]":
        """Accept and close every connection already queued, without waiting,
        and say how many there were."""
        n = 0
        while True:
            try:
                c, _ = self._ln.accept()
            except (BlockingIOError, InterruptedError):
                return n, None
            except ConnectionAbortedError:
                n += 1  # completed a handshake, then reset: it still arrived
                continue
            except OSError as e:
                return n, e
            n += 1  # it arrived; closing our end cannot unsay that
            try:
                c.close()
            except OSError:
                pass

    def _record(self, n: int) -> None:
        if not n:
            return
        now = datetime.now(timezone.utc)
        with self._mu:
            for _ in range(n):
                self._events.append(NetworkEvent(dest=self.addr, op=OP_CONNECT, protocol="tcp",
                                                 attribution=BY_DESTINATION, seen_at=now))

    def _fail(self, err: str) -> None:
        with self._mu:
            if self._err is None:
                self._err = err

    def stop(self) -> Optional[str]:
        """End the capture: stop the accept loop, drain connections the kernel
        has completed but not yet handed over, close the listener. A
        connection that finished its handshake before stop is recorded even
        if its client has already hung up; one arriving during stop may be
        refused unseen, so stop only after the code under test is done. Call
        it before dialed() or health(); later calls return the same result."""
        with self._stopping:
            return self._stop()

    def _stop(self) -> Optional[str]:
        with self._mu:
            if self._finished:
                return self._err
        try:
            self._wake_w.send(b"x")
        except OSError as e:
            self._fail(f"sinkhole: stop: {e}")
        self._thread.join()
        n, err = _drain(self)
        self._record(n)
        if err is not None:
            self._fail(f"sinkhole: drain (queued connections may be unseen): {err}")
        self._ln.close()
        self._wake_r.close()
        self._wake_w.close()
        with self._mu:
            self._finished = True
            return self._err

    def dialed(self, trace_id: str) -> List[NetworkEvent]:
        """Every connection that reached the sinkhole, whatever the trace:
        arrivals cannot be told apart by trace."""
        with self._mu:
            return list(self._events)

    def health(self) -> Optional[str]:
        """None if the capture is complete: stopped, drained, and no accept
        error along the way. Otherwise the fault."""
        with self._mu:
            if self._err is not None:
                return self._err
            if not self._finished:
                return "sinkhole: capture has not stopped"
            return None


def _drain(s: Sinkhole) -> "tuple[int, Optional[BaseException]]":
    """Sinkhole.stop's drain, replaceable in tests to inject a failed one."""
    return s._drain()
