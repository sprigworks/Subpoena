"""The witness, read from the file subpoena-witness writes (docs/ports.md, W;
schema: docs/witness-event.schema.json). A port of witness.ReadLog, exec,
file, delivery and the database witness's row lines, and of the Sinkhole network
witness. Running a witness of files, deliveries or rows stays Go-only."""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
import selectors
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO, Dict, List, Optional, Tuple, Union

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


FILE_CREATE = "create"
FILE_WRITE = "write"
FILE_RENAME = "rename"
FILE_UNLINK = "unlink"
BY_ROOT = "root"
_FILE_OPS = (FILE_CREATE, FILE_WRITE, FILE_RENAME, FILE_UNLINK)


def _path_within(p: str, directory: str) -> bool:
    """Whether p is directory or lies below it, comparing normalized paths."""
    p, directory = posixpath.normpath(p), posixpath.normpath(directory)
    return p == directory or directory == "/" or p.startswith(directory + "/")


@dataclass
class FileEvent:
    """One change under a watched root, as the file witness saw it. There is
    no PID: inotify has none to give."""

    op: str
    path: str
    root: str
    is_dir: bool
    source: str  # "inotify", "scan" for an entry a new directory's scan found, "stat" for a difference Stop found
    rename: str  # "from" or "to" on a rename, else ""
    cookie: int  # ties a rename's two sides, 0 otherwise
    trace_id: str
    attribution: str
    seen_at: datetime

    def within(self, path: str) -> bool:
        """The event's path is path, or lies below it."""
        return _path_within(self.path, path)

    def touches(self, path: str) -> bool:
        """The event says something happened to path: it is path, lies below
        it, or renamed a directory above it, which moved path with no event
        naming it."""
        return self.within(path) or (self.op == FILE_RENAME and _path_within(path, self.path))


ROWS_UNKNOWN = -1  # the server's reply gave no usable count
OUTCOMES = ("read", "committed", "rolled_back", "failed", "unknown")


@dataclass
class RowEvent:
    """One statement a database witness saw. It has no trace ID: attribution is
    by destination, so it holds for every trace."""
    engine: str
    conn: int
    dest: str
    statement: str
    verb: str
    tables: List[str]
    opaque: bool
    reason: str
    rows: int
    outcome: str
    attribution: str
    seen_at: datetime

    @property
    def effect(self) -> bool:
        """A committed write of any number of rows other than zero. An unknown
        count is an effect."""
        return self.outcome == "committed" and self.rows != 0

    def touches(self, table: str) -> bool:
        """Whether this counts against table. The empty table is every table.
        An opaque event, or one naming no table, counts against every table.
        Names compare without case, on their dotted parts from the right, so
        users and public.users match each other."""
        if not table or self.opaque or not self.tables:
            return True
        return any(_same_table(t, table) for t in self.tables)


def _same_table(a: str, b: str) -> bool:
    return all(x == y for x, y in zip(reversed(a.lower().split(".")), reversed(b.lower().split("."))))


class WitnessError(ValueError):
    pass


OP_DELIVER = "deliver"  # a send on a connected socket, to the peer it holds
_DELIVERY_OPS = ("deliver", "sendmsg")
_DELIVERY_STR_FIELDS = ("delivery_op", "comm", "protocol", "peer", "local", "cgroup", "trace_id", "attribution")


# The integer fields and the range Go's reader decodes each into (int64 for
# the PIDs, uint64 for cgroup_id). A value outside it is an error there, so it
# is one here. null is the same as an absent field, as in Go.
_INT_FIELDS = {"pid": (-(2**63), 2**63 - 1), "ppid": (-(2**63), 2**63 - 1),
               "host_pid": (-(2**63), 2**63 - 1), "cgroup_id": (0, 2**64 - 1)}
_STR_FIELDS = ("comm", "exe", "command", "cgroup", "trace_id", "attribution")
_ROW_STR_FIELDS = ("engine", "dest", "statement", "verb", "reason", "attribution")


_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_ZERO = datetime(1, 1, 1, tzinfo=timezone.utc)

# Every field name of an exec line, a record or a row line. A key that differs
# from one only by case is refused: Go's decoder would read it as that field.
_KNOWN = ("time", "pid", "ppid", "host_pid", "comm", "exe", "command", "args", "cgroup_id", "cgroup",
          "trace_id", "attribution", "record", "healthy", "error", "roots", "coverage", "silent_closes", "symlinks",
          "file_op", "path", "root", "is_dir", "source", "rename", "cookie",
          "delivery_op", "protocol", "peer", "local", "bytes",
          "event", "engine", "conn", "dest", "statement", "verb", "tables", "opaque", "reason", "rows", "outcome")
_FILE_STR_FIELDS = ("file_op", "path", "root", "source", "rename", "trace_id", "attribution")


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

    def __init__(self, lines: List[dict], health: Optional[str] = None, files: Optional[List[dict]] = None,
                 roots: Optional[List[str]] = None, coverage: str = "",
                 deliveries: Optional[List["DeliveryEvent"]] = None, rows: Optional[List[dict]] = None,
                 silent: Optional[List[str]] = None, symlinks: Optional[List[str]] = None):
        self._lines, self._health = lines, health
        self._files, self._roots, self._coverage = files or [], roots or [], coverage
        self._deliveries, self._rows = deliveries or [], rows or []
        self._silent, self._symlinks = silent or [], symlinks or []

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

    def wrote(self, trace_id: str) -> List[FileEvent]:
        """The file changes for trace_id: lines naming it, and every line that
        names no trace, which a tier-1 witness's never do."""
        out = []
        for l in self._files:
            tid = l.get("trace_id") or ""
            if tid and tid != trace_id:
                continue
            out.append(FileEvent(
                op=l["file_op"], path=l["path"], root=l.get("root") or "", is_dir=bool(l.get("is_dir")),
                source=l.get("source") or "", rename=l.get("rename") or "", cookie=l.get("cookie") or 0,
                trace_id=tid, attribution=l.get("attribution") or "", seen_at=_parse_time(l["time"])))
        return out

    def covers(self, path: str) -> bool:
        """Whether path lies under a root the file's start record names and
        crosses no symlink its stop record names. A path that does not could
        never appear in wrote(), so no absence rests on it."""
        return (posixpath.isabs(path) and any(_path_within(path, r) for r in self._roots)
                and not any(_path_within(path, s) for s in self._symlinks))

    def roots(self) -> List[str]:
        """The directories the start record names. An exec witness's file
        names none, and then no file absence rests on it."""
        return list(self._roots)

    def silent_closes(self) -> List[str]:
        """The files the stop record names as opened for writing and closed
        with no write seen: all a change by mmap or native AIO may leave."""
        return list(self._silent)

    def delivered(self, trace_id: str) -> "List[DeliveryEvent]":
        """Every send whose trace ID, read by the kernel side from its cgroup,
        is trace_id. Nothing the application controls is consulted. The empty
        trace ID matches nothing."""
        if not trace_id:
            return []
        return [e for e in self._deliveries if e.trace_id == trace_id]


    def coverage(self) -> str:
        """The stop record's account of what the capture might have missed
        even when healthy, or "" if it gives none."""
        return self._coverage

    def rows(self) -> List[RowEvent]:
        """Every row line, in file order, whatever its outcome."""
        return [self._row(l) for l in self._rows]

    def committed(self, trace_id: str = "") -> List[RowEvent]:
        """Every committed row line, for every trace: a database witness
        attributes by destination, and a row line has no trace ID. A rolled-back
        or refused write is not here. Zero-row writes are: see RowEvent.effect.
        Absence rests on these only when health() is None."""
        return [e for e in self.rows() if e.outcome == "committed"]

    @staticmethod
    def _row(l: dict) -> RowEvent:
        g = lambda k, zero: l.get(k) if l.get(k) is not None else zero  # noqa: E731
        return RowEvent(
            engine=g("engine", ""), conn=g("conn", 0), dest=g("dest", ""), statement=g("statement", ""),
            verb=g("verb", ""), tables=list(g("tables", [])), opaque=g("opaque", False), reason=g("reason", ""),
            rows=l["rows"], outcome=l["outcome"], attribution=g("attribution", ""), seen_at=_parse_time(l["time"]),
        )

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


def _check_row(l: dict) -> None:
    """A row line it cannot read could be a write, so anything out of shape is an
    error, as in Go's reader, and never a skip. A missing count would read as
    zero rows, which is no effect."""
    if l["event"] != "row":
        raise ValueError(f"unknown event {l['event']!r}")
    rows = l.get("rows")
    if rows is None or isinstance(rows, bool) or not isinstance(rows, int) or not ROWS_UNKNOWN <= rows <= 2**63 - 1:
        raise ValueError("no usable rows field")
    if l.get("outcome") not in OUTCOMES:
        raise ValueError(f"unknown outcome {l.get('outcome')!r}")
    conn = l.get("conn")
    if conn is not None and (isinstance(conn, bool) or not isinstance(conn, int) or not -(2**63) <= conn <= 2**63 - 1):
        raise ValueError("conn is not an integer")
    for k in _ROW_STR_FIELDS:
        if l.get(k) is not None and not isinstance(l[k], str):
            raise ValueError(f"{k} is not a string")
    tables = l.get("tables")
    if tables is not None and (not isinstance(tables, list) or not all(isinstance(t, str) for t in tables)):
        raise ValueError("tables is not a list of strings")
    if l.get("opaque") is not None and not isinstance(l["opaque"], bool):
        raise ValueError("opaque is not a boolean")
    if not l.get("time"):
        raise ValueError("no time")
    _parse_time(l["time"])


def read_log(f: IO[str]) -> Log:
    """Read subpoena-witness JSON lines. Blank lines and unknown fields are
    ignored. A line that does not decode, or has no time, raises WitnessError
    naming its line number: skipping it could turn an exec into an absence.
    Capture faults (see Log.health) do not stop the read: the execs are still
    evidence that something ran."""
    lines, files, roots, silent, symlinks = [], [], [], [], []
    deliveries: "List[DeliveryEvent]" = []
    rows: List[dict] = []
    coverage = ""
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
                rs = l.get("roots")
                if rs is not None and (not isinstance(rs, list) or not all(isinstance(r, str) for r in rs)):
                    raise ValueError("roots is not a list of strings")
                if l.get("coverage") is not None and not isinstance(l["coverage"], str):
                    raise ValueError("coverage is not a string")
                for k in ("silent_closes", "symlinks"):
                    v = l.get(k)
                    if v is not None and (not isinstance(v, list) or not all(isinstance(p, str) for p in v)):
                        raise ValueError(f"{k} is not a list of strings")
                roots.extend(rs or [])
                silent.extend(l.get("silent_closes") or [])
                symlinks.extend(l.get("symlinks") or [])
                coverage = l.get("coverage") or coverage
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
            if l.get("file_op") is not None:
                for k in _FILE_STR_FIELDS:
                    if l.get(k) is not None and not isinstance(l[k], str):
                        raise ValueError(f"{k} is not a string")
                if l.get("is_dir") is not None and not isinstance(l["is_dir"], bool):
                    raise ValueError("is_dir is not a boolean")
                c = l.get("cookie")
                if c is not None and (isinstance(c, bool) or not isinstance(c, int) or not 0 <= c <= 2**32 - 1):
                    raise ValueError("cookie is not a uint32")
                if not l.get("time"):
                    raise ValueError("no time")
                _parse_time(l["time"])
                if not l.get("path"):
                    raise ValueError("no path")
                if l["file_op"] not in _FILE_OPS:
                    raise ValueError(f"unknown file_op {l['file_op']!r}")
                if not open_at:
                    fault(f"witness: line {n}: a file event outside any capture window")
                files.append(l)
                continue
            if l.get("delivery_op") is not None:
                deliveries.append(_delivery(l))
                if not open_at:
                    fault(f"witness: line {n}: a delivery outside any capture window")
                continue
            if l.get("event") is not None:
                _check_row(l)
                if not open_at:
                    fault(f"witness: line {n}: a row outside any capture window")
                if l["outcome"] == "unknown":
                    fault(f"witness: line {n}: a write whose outcome was not seen")
                rows.append(l)
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
    return Log(lines, health, files, roots, coverage, deliveries, rows, silent, symlinks)


# The network witness (pkg/witness's NetworkEvent and Sinkhole). Go's eBPF
# connect witness (netbpf) is not ported; the sinkhole needs no root and no
# kernel support.

OP_CONNECT = "connect"  # connect() on an inet socket
OP_SENDMSG = "sendmsg"  # a send with an explicit destination
BY_DESTINATION = "destination"
# A request header the test sends through the code under test, so marked() can
# tell arrivals apart. It decides nothing: dialed() returns every arrival.
MARK_HEADER = "X-Subpoena-Mark"
_ANSWER_READ = 2.0  # seconds in all on one connection; the arrival is already recorded
_ANSWER_HEAD = 1 << 16
_ANSWER_200 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


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
    # From an answering Sinkhole. Left out of repr: failure text prints events.
    request: str = field(default="", repr=False)  # HTTP request line
    headers: Dict[str, str] = field(default_factory=dict, repr=False)  # names in lower case; first of a repeat


@dataclass
class DeliveryEvent:
    """One send seen leaving a process in a session cgroup: to the peer a
    connected socket holds (OP_DELIVER), or to the destination it named
    (OP_SENDMSG). A broker's write to a subscriber on an accepted socket is
    one. It records the attempt, and says nothing of content: an ack on a
    peer's socket looks like a message on it."""

    op: str
    peer: Optional[AddrPort]  # None when the witness could not read it
    local: Optional[AddrPort]
    protocol: str = "tcp"
    bytes: int = 0  # what the caller asked to send, not what the peer got
    pid: int = 0
    comm: str = ""
    cgroup: str = ""
    cgroup_id: int = 0
    trace_id: str = ""
    attribution: str = ""
    seen_at: Optional[datetime] = None

    @property
    def peer_unknown(self) -> bool:
        """The send was seen, but not where it went: it may have gone to any
        peer."""
        return self.peer is None or self.peer.addr.is_unspecified


def _delivery(l: dict) -> DeliveryEvent:
    """A delivery line. A peer that does not parse is an error, never an
    unknown peer: an empty one is how the witness says it could not tell."""
    for k in _DELIVERY_STR_FIELDS:
        if l.get(k) is not None and not isinstance(l[k], str):
            raise ValueError(f"{k} is not a string")
    for k, (lo, hi) in {**_INT_FIELDS, "bytes": (0, 2**64 - 1)}.items():
        v = l.get(k)
        if v is None:
            continue
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{k} is not an integer")
        if not lo <= v <= hi:
            raise ValueError(f"{k} {v} is out of range")
    if not l.get("time"):
        raise ValueError("no time")
    seen_at = _parse_time(l["time"])
    if l["delivery_op"] not in _DELIVERY_OPS:
        raise ValueError(f"unknown delivery_op {l['delivery_op']!r}")
    g = lambda k, zero: l.get(k) if l.get(k) is not None else zero  # noqa: E731
    return DeliveryEvent(
        op=l["delivery_op"], peer=AddrPort.of(l["peer"]) if l.get("peer") else None,
        local=AddrPort.of(l["local"]) if l.get("local") else None, protocol=g("protocol", ""),
        bytes=g("bytes", 0), pid=g("pid", 0), comm=g("comm", ""), cgroup=g("cgroup", ""),
        cgroup_id=g("cgroup_id", 0), trace_id=g("trace_id", ""), attribution=g("attribution", ""), seen_at=seen_at,
    )


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

    A proxy turns a closed connection into a 502, which can hide what it did
    next. Sinkhole(answer=True) stands in for an upstream that must answer: it
    replies 200 with an empty body and records the request line and headers.
    An arrival is recorded before a byte is read, so one that sends nothing, or
    something that is not HTTP, still counts.
    """

    def __init__(self, answer: bool = False) -> None:
        self._answer = answer
        self._conns: List[threading.Thread] = []
        self._draining = False
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
            if self._answer and not self._draining:
                event = self._record_one()
                t = threading.Thread(target=self._serve, args=(c, event), name="subpoena-sinkhole-conn", daemon=True)
                self._conns.append(t)
                t.start()
                continue
            n += 1  # it arrived; closing our end cannot unsay that
            try:
                c.close()
            except OSError:
                pass

    def _record_one(self) -> NetworkEvent:
        e = NetworkEvent(dest=self.addr, op=OP_CONNECT, protocol="tcp", attribution=BY_DESTINATION,
                         seen_at=datetime.now(timezone.utc))
        with self._mu:
            self._events.append(e)
        return e

    def _serve(self, c: socket.socket, event: NetworkEvent) -> None:
        """Read one request, fill in the event, answer and close. A request it
        cannot read leaves the arrival as it is, which holds for every trace."""
        try:
            deadline = time.monotonic() + _ANSWER_READ

            def read() -> bytes:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("sinkhole: read deadline")
                c.settimeout(left)
                return c.recv(4096)

            data = b""
            while not re.search(rb"\r?\n\r?\n", data) and len(data) < _ANSWER_HEAD:
                chunk = read()
                if not chunk:
                    return
                data += chunk
            head = re.split(rb"\r?\n\r?\n", data, maxsplit=1)[0]
            lines = re.split(r"\r?\n", head.decode("latin-1"))
            if len(lines[0].split(" ")) != 3 or not lines[0].split(" ")[2].startswith("HTTP/"):
                return
            # As Go's http.ReadRequest: a folded line joins the one above, a space
            # before the colon stays in the name, and a line with no colon is no
            # request. Sinkholes in both languages must read the same bytes alike.
            fields: List[List[str]] = []
            for line in lines[1:]:
                if line[:1] in (" ", "\t"):
                    if not fields:
                        return
                    fields[-1][1] = f"{fields[-1][1]} {line.strip()}".strip()
                    continue
                name, sep, value = line.partition(":")
                if not sep:
                    return
                fields.append([name.lower(), value.strip()])
            headers = {}
            for name, value in fields:
                headers.setdefault(name, value)
            with self._mu:
                event.request, event.headers = lines[0], headers
            c.sendall(_ANSWER_200)
            c.shutdown(socket.SHUT_WR)
            while read():  # closing on unread bytes can reset the answer away
                pass
        except OSError:
            pass
        finally:
            c.close()

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
        self._draining = True
        for t in self._conns:
            t.join()
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
        arrivals cannot be told apart by trace, and a mark does not change that,
        because the code under test could send any mark it liked."""
        with self._mu:
            return list(self._events)

    def marked(self, mark: str) -> List[NetworkEvent]:
        """The arrivals whose first MARK_HEADER is mark, for telling one request
        from another: an arrival with no such header matches no mark, "" included.
        It is no absence check: ask dialed() for that."""
        with self._mu:
            return [e for e in self._events if e.headers.get(MARK_HEADER.lower()) == mark]

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
