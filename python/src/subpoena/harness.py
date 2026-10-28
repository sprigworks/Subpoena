"""The tier-1 harness (docs/ports.md, H): an in-memory OpenTelemetry recorder
with completeness tracking, and TraceQL queries over what it saw.

    h = Harness()
    tracer = h.tracer("my-app")
    ... run the code under test with tracer (or h.tracer_provider) ...
    tr = h.collect()                 # required before asserting
    require_absent(tr, '{ ... } >> { ... }')

A port of pkg/harness; conformance/harness.yaml holds the cases it must pass.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from opentelemetry import trace as trace_api
from opentelemetry.context import Context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanLimits, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from . import traceql

DEFAULT_CAPACITY = 10000

# The harness owns its span limits: all unlimited, so OTEL_* environment
# variables cannot drop or truncate an attribute the test asserts on (H1).
_SPAN_LIMITS = SpanLimits(
    max_attributes=SpanLimits.UNSET,
    max_events=SpanLimits.UNSET,
    max_links=SpanLimits.UNSET,
    max_span_attributes=SpanLimits.UNSET,
    max_event_attributes=SpanLimits.UNSET,
    max_link_attributes=SpanLimits.UNSET,
    max_attribute_length=SpanLimits.UNSET,
    max_span_attribute_length=SpanLimits.UNSET,
)


class Recorder(SpanProcessor):
    """Records finished spans synchronously (no queue that could overflow),
    and remembers which spans started but never ended, how many finished
    spans it dropped for lack of capacity, and which spans were recorded with
    attributes, events or links dropped by their span limits."""

    def __init__(self, capacity: int = 0):
        self._capacity = capacity if capacity > 0 else DEFAULT_CAPACITY
        self._lock = threading.Lock()
        self._started: Dict[int, str] = {}
        self._ended: List[ReadableSpan] = []
        self._dropped = 0
        self._late_ends = 0
        self._lossy: set = set()
        self._closed = False

    def on_start(self, span: Span, parent_context: Optional[Context] = None) -> None:
        with self._lock:
            self._started[span.context.span_id] = span.name

    def on_end(self, span: ReadableSpan) -> None:
        with self._lock:
            self._started.pop(span.context.span_id, None)
            if _lossy(span):
                self._lossy.add(span.name)
            if self._closed:
                self._late_ends += 1
            elif len(self._ended) >= self._capacity:
                self._dropped += 1
            else:
                self._ended.append(span)

    def shutdown(self) -> None:
        """Spans ending afterwards are counted as dropped."""
        with self._lock:
            self._closed = True

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True  # synchronous: nothing buffered

    def _snapshot(self):
        with self._lock:
            return (list(self._ended), self._dropped + self._late_ends,
                    sorted(self._started.values()), sorted(self._lossy))


def _lossy(span: ReadableSpan) -> bool:
    """Whether span limits dropped any attribute, event or link of span."""
    if span.dropped_attributes or span.dropped_events or span.dropped_links:
        return True
    for e in span.events:
        if getattr(e.attributes, "dropped", 0):
            return True
    for link in span.links:
        if getattr(link.attributes, "dropped", 0):
            return True
    return False


class IncompleteError(Exception):
    """collect() could not capture everything: absence claims on the snapshot
    are Inconclusive. The snapshot is on .trace."""

    def __init__(self, trace: "Trace", dropped: int, unfinished: List[str],
                 truncated: Optional[List[str]] = None):
        truncated = truncated or []
        parts = []
        if dropped:
            parts.append(f"{dropped} span(s) dropped")
        if unfinished:
            parts.append(f"{len(unfinished)} span(s) never ended: {', '.join(unfinished)}")
        if truncated:
            parts.append("spans lost attributes, events or links: " + ", ".join(truncated))
        super().__init__("harness: capture incomplete: " + "; ".join(parts))
        self.trace, self.dropped, self.unfinished = trace, dropped, unfinished
        self.truncated = truncated


class Verdict(enum.Enum):
    """Three-valued: absence is only provable from a complete capture."""

    PASS = "Pass"
    FAIL = "Fail"
    INCONCLUSIVE = "Inconclusive"

    def __str__(self) -> str:
        return self.value


class Trace:
    """An immutable, queryable snapshot of the captured spans."""

    def __init__(self, traces: List[traceql.Trace], complete: bool):
        self._traces, self._complete = traces, complete

    @property
    def complete(self) -> bool:
        return self._complete

    def trace_ids(self) -> List[str]:
        return sorted(t.id for t in self._traces)

    def span_count(self) -> int:
        return sum(len(t.spans) for t in self._traces)

    def query(self, q: str) -> List[traceql.Match]:
        """Raises traceql.ParseError, or traceql.UnsupportedValueError if q reads
        an attribute that holds an array value in the snapshot."""
        return traceql.parse(q).eval(self._traces)

    def absent(self, q: str) -> Verdict:
        """Fail on any match, even from an incomplete capture; Pass on none from
        a complete one; Inconclusive otherwise. Raises if q cannot be evaluated."""
        if self.query(q):
            return Verdict.FAIL
        return Verdict.PASS if self._complete else Verdict.INCONCLUSIVE

    def exists(self, q: str) -> Verdict:
        """Pass on a match; Fail on none from a complete capture; Inconclusive
        otherwise. Raises if q cannot be evaluated."""
        if self.query(q):
            return Verdict.PASS
        return Verdict.FAIL if self._complete else Verdict.INCONCLUSIVE


class Harness:
    """Owns a TracerProvider wired to a Recorder. Inject tracer_provider (or
    tracer()) into the code under test; never install another provider."""

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        self._rec = Recorder(capacity)
        self.tracer_provider = TracerProvider(
            sampler=ALWAYS_ON, resource=Resource.get_empty(), span_limits=_SPAN_LIMITS)
        # OTEL_SDK_DISABLED=true makes the SDK hand out no-op tracers: nothing
        # is recorded, and every absence would pass. The harness owns its
        # provider, as with the span limits, so the variable is ignored; if
        # the SDK still hands out a no-op tracer, refuse to start.
        if hasattr(self.tracer_provider, "_disabled"):
            self.tracer_provider._disabled = False
        if isinstance(self.tracer_provider.get_tracer("subpoena.harness"), trace_api.NoOpTracer):
            raise RuntimeError("subpoena: the TracerProvider is disabled (OTEL_SDK_DISABLED?) "
                               "and would record nothing; refusing to run")
        self.tracer_provider.add_span_processor(self._rec)

    def tracer(self, name: str) -> trace_api.Tracer:
        return self.tracer_provider.get_tracer(name)

    def collect(self) -> Trace:
        """Force-flush and return a snapshot. Raises IncompleteError (carrying
        the snapshot) if a span was dropped, a started span has not ended, or
        a span lost attributes, events or links to span limits."""
        self.tracer_provider.force_flush()
        spans, dropped, unfinished, truncated = self._rec._snapshot()
        complete = dropped == 0 and not unfinished and not truncated
        t = Trace(_convert(spans), complete)
        if not complete:
            raise IncompleteError(t, dropped, unfinished, truncated)
        return t

    def shutdown(self) -> None:
        self.tracer_provider.shutdown()


def _value(v: Any) -> Any:
    if isinstance(v, (bool, str, int, float)):
        return v
    return traceql.Unsupported("array")  # sequences: refused by queries that read them


def _convert(spans: Sequence[ReadableSpan]) -> List[traceql.Trace]:
    out: List[traceql.Trace] = []
    idx: Dict[str, int] = {}
    for s in spans:
        tid = format(s.context.trace_id, "032x")
        if tid not in idx:
            idx[tid] = len(out)
            out.append(traceql.Trace(tid))
        parent = s.parent.span_id if s.parent is not None and s.parent.is_valid else 0
        out[idx[tid]].spans.append(traceql.Span(
            id=format(s.context.span_id, "016x"),
            name=s.name,
            parent_id=format(parent, "016x") if parent else "",
            attrs={k: _value(v) for k, v in (s.attributes or {}).items()},
        ))
    return out


def require_absent(t: Trace, q: str, allow_inconclusive: bool = False) -> None:
    """Fail the test (AssertionError) unless q matches nothing in a complete
    capture. allow_inconclusive downgrades Inconclusive; off by default."""
    _report("absent", t.absent, q, allow_inconclusive)


def require_exists(t: Trace, q: str, allow_inconclusive: bool = False) -> None:
    """Fail the test (AssertionError) unless q matches at least one trace."""
    _report("exists", t.exists, q, allow_inconclusive)


def _report(kind: str, check, q: str, allow_inconclusive: bool) -> None:
    __tracebackhide__ = True
    try:
        v = check(q)
    except (traceql.ParseError, traceql.UnsupportedValueError) as e:
        raise AssertionError(f"testimony: {kind} {q}: cannot evaluate: {e}") from None
    if v is Verdict.PASS:
        return
    if v is Verdict.INCONCLUSIVE:
        if allow_inconclusive:
            return
        raise AssertionError(f"testimony: {kind} {q}: INCONCLUSIVE: capture incomplete, absence is not proven")
    raise AssertionError(f"testimony: {kind} {q}: {v}")


# Witness checks (docs/ports.md W4, W5): absence of a process, proven by the
# independent witness, not by the spans. A witness here is anything with
# spawned(trace_id) and, to certify absence, health() -> Optional[str]
# (subpoena.witness.Log has both). A port of pkg/harness's NoSpawn,
# RequireNoSpawn and WatchSpawns.

_NO_HEALTH = "witness does not report capture health"


def _capture_health(w: Any) -> Optional[str]:
    health = getattr(w, "health", None)
    if not callable(health):
        return _NO_HEALTH
    return health()


def no_spawn(w: Any, trace_id: str) -> "tuple[Verdict, Optional[str]]":
    """Fail if the witness saw any process for trace_id, even from an
    unhealthy capture. With none, missing or bad capture health is
    Inconclusive; Pass needs a healthy witness. Stop the witness first."""
    spawned = w.spawned(trace_id)
    if spawned:
        return Verdict.FAIL, f"witness saw processes for {trace_id}: {spawned}"
    err = _capture_health(w)
    if err is not None:
        return Verdict.INCONCLUSIVE, err
    return Verdict.PASS, None


def require_no_spawn(w: Any, trace_id: str) -> None:
    """Fail the test (AssertionError) unless a healthy witness saw no process
    for trace_id. Inconclusive fails too."""
    __tracebackhide__ = True
    v, err = no_spawn(w, trace_id)
    if v is not Verdict.PASS:
        raise AssertionError(f"witness: no spawn for {trace_id}: {v}: {err}")


@dataclass
class SpawnRule:
    """Which commands a watch_spawns check accepts; each list matches in the
    direction that fails closed. Never matches loosely: a command line whose
    words end with the entry's words, the entry's program compared without
    its directory on either side, so it fires through timeout or env and on
    /usr/bin/x. Allowed matches the whole command line exactly; None allows
    any command not in Never, an empty list allows none. A name-only sighting
    fails when its name is the program of a Never entry; otherwise, with an
    Allowed list, it fails as unidentified unless excuse_name_only is set and
    the name is the program of an Allowed entry. A program is an entry's
    first word, without its directory, cut to the kernel's 15-byte task name."""

    allowed: Optional[List[str]] = None
    never: List[str] = field(default_factory=list)
    excuse_name_only: bool = False


def _base(p: str) -> str:
    """Go's path.Base: the last element, trailing slashes removed first."""
    if not p:
        return "."
    p = p.rstrip("/")
    if not p:
        return "/"
    return p.rsplit("/", 1)[-1]


def _task_name(s: str) -> str:
    """s cut as the kernel cuts a task name, to 15 bytes, with a character the
    cut split dropped, so both sides of a comparison read the same."""
    return s.encode("utf-8")[:15].decode("utf-8", "ignore").rstrip("\ufffd")


def _programs(rules: Sequence[str]) -> List[str]:
    out = []
    for r in rules:
        f = r.split()
        if f:
            out.append(_task_name(_base(f[0])))
    return out


def _matches_any(cmd: str, rules: Sequence[str]) -> bool:
    words = cmd.split()
    for r in rules:
        rw = r.split()
        if not rw or len(rw) > len(words):
            continue
        tail = words[len(words) - len(rw):]
        if _base(tail[0]) == _base(rw[0]) and tail[1:] == rw[1:]:
            return True
    return False


def check_spawns(w: Any, trace_id: str, rule: SpawnRule) -> List[str]:
    """Stop the witness (if it can be stopped) and return one failure message
    per process the rule refuses, then one for missing or bad capture health.
    An empty list means the check passed."""
    stop = getattr(w, "stop", None)
    if callable(stop):
        stop()
    errs = []
    for p in w.spawned(trace_id):
        name_only = p.command_source == "comm"
        name = _task_name(p.command) if name_only else ""
        if name_only and name in _programs(rule.never):
            errs.append(f"witness: refused program seen by name only for {trace_id}, arguments unknown: "
                        f"pid {p.pid} {p.command!r} ({p.attribution})")
        elif name_only and rule.allowed is not None and not (
                rule.excuse_name_only and name in _programs(rule.allowed)):
            errs.append(f"witness: process seen by name only for {trace_id}, not identified: "
                        f"pid {p.pid} {p.command!r} ({p.attribution})")
        elif name_only and rule.allowed is not None:
            pass  # excused
        elif _matches_any(p.command, rule.never):
            errs.append(f"witness: refused command ran for {trace_id}: pid {p.pid} {p.command!r} ({p.attribution})")
        elif rule.allowed is not None and p.command not in rule.allowed:
            errs.append(f"witness: command not allowed for {trace_id}: pid {p.pid} {p.command!r} ({p.attribution})")
    err = _capture_health(w)
    if err is not None:
        errs.append(f"witness: {trace_id}: capture unhealthy, absence of refused commands is not proven: {err}")
    return errs


def watch_spawns(addfinalizer, w: Any, trace_id: str, rule: SpawnRule) -> None:
    """Register check_spawns to run at test teardown, even after an earlier
    failure: pass pytest's request.addfinalizer. Register it when the witness
    starts, so a test that stops early still reports what ran."""
    def finalize() -> None:
        __tracebackhide__ = True
        errs = check_spawns(w, trace_id, rule)
        if errs:
            raise AssertionError("\n".join(errs))
    addfinalizer(finalize)
