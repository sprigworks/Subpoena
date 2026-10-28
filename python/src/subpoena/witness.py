"""The witness, read from the file subpoena-witness writes (docs/ports.md, W;
schema: docs/witness-event.schema.json). A port of witness.ReadLog."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import IO, List, Optional

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


_INT_FIELDS = ("pid", "ppid", "host_pid", "cgroup_id")
_STR_FIELDS = ("comm", "exe", "command", "cgroup", "trace_id", "attribution")


def _parse_time(s: str) -> datetime:
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
        return [self._event(l) for l in self._lines if l.get("trace_id") == trace_id]

    @staticmethod
    def _event(l: dict) -> ProcessEvent:
        # subpoena-witness writes argv as the command. Without it, the task
        # name stands in, marked as name-only ("comm"), as in the Go reader.
        command, source = l.get("command", ""), "cmdline"
        if not command:
            command = l.get("comm", "")
            source = "comm" if command else ""
        return ProcessEvent(
            pid=l["pid"], ppid=l["ppid"], exe=l.get("exe", ""), command=command,
            cgroup=l.get("cgroup", ""), cgroup_id=l.get("cgroup_id", 0), trace_id=l["trace_id"],
            attribution=l.get("attribution", ""), seen_at=_parse_time(l["time"]), args=list(l.get("args") or []),
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
    open_at, records = 0, 0  # open_at: line of the open window's start record

    def fault(msg: str) -> None:
        nonlocal health
        if health is None:
            health = msg

    for n, raw in enumerate(f, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            l = json.loads(raw)
            if not isinstance(l, dict):
                raise ValueError("not a JSON object")
            if l.get("record") is not None:
                rec = l["record"]
                if not l.get("time"):
                    raise ValueError("no time")
                _parse_time(l["time"])
                if not isinstance(l.get("healthy", False), bool) or not isinstance(l.get("error", ""), str):
                    raise ValueError("healthy is not a boolean, or error not a string")
                if rec == "start":
                    if open_at:
                        fault(f"witness: line {n}: a capture started while the one from line {open_at} was still open")
                    open_at = n
                elif rec == "stop":
                    if not open_at:
                        fault(f"witness: line {n}: a stop with no capture open")
                    elif not l.get("healthy", False) or l.get("error"):
                        fault(f"witness: line {n}: capture unhealthy: {l.get('error', '')}")
                    open_at = 0
                else:
                    raise ValueError(f"unknown record {rec!r}")
                records += 1
                continue
            for k in _INT_FIELDS:
                if k in l and (isinstance(l[k], bool) or not isinstance(l[k], int)):
                    raise ValueError(f"{k} is not an integer")
            for k in _STR_FIELDS:
                if k in l and not isinstance(l[k], str):
                    raise ValueError(f"{k} is not a string")
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
    return Log(lines, health)
