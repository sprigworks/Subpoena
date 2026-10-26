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
from typing import Any, Dict, List, Optional, Sequence

from opentelemetry import trace as trace_api
from opentelemetry.context import Context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from . import traceql

DEFAULT_CAPACITY = 10000


class Recorder(SpanProcessor):
    """Records finished spans synchronously (no queue that could overflow),
    and remembers which spans started but never ended and how many finished
    spans it dropped for lack of capacity."""

    def __init__(self, capacity: int = 0):
        self._capacity = capacity if capacity > 0 else DEFAULT_CAPACITY
        self._lock = threading.Lock()
        self._started: Dict[int, str] = {}
        self._ended: List[ReadableSpan] = []
        self._dropped = 0
        self._late_ends = 0
        self._closed = False

    def on_start(self, span: Span, parent_context: Optional[Context] = None) -> None:
        with self._lock:
            self._started[span.context.span_id] = span.name

    def on_end(self, span: ReadableSpan) -> None:
        with self._lock:
            self._started.pop(span.context.span_id, None)
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
            return list(self._ended), self._dropped + self._late_ends, sorted(self._started.values())


class IncompleteError(Exception):
    """collect() could not capture everything: absence claims on the snapshot
    are Inconclusive. The snapshot is on .trace."""

    def __init__(self, trace: "Trace", dropped: int, unfinished: List[str]):
        parts = []
        if dropped:
            parts.append(f"{dropped} span(s) dropped")
        if unfinished:
            parts.append(f"{len(unfinished)} span(s) never ended: {', '.join(unfinished)}")
        super().__init__("harness: capture incomplete: " + "; ".join(parts))
        self.trace, self.dropped, self.unfinished = trace, dropped, unfinished


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
        self.tracer_provider = TracerProvider(sampler=ALWAYS_ON, resource=Resource.get_empty())
        self.tracer_provider.add_span_processor(self._rec)

    def tracer(self, name: str) -> trace_api.Tracer:
        return self.tracer_provider.get_tracer(name)

    def collect(self) -> Trace:
        """Force-flush and return a snapshot. Raises IncompleteError (carrying
        the snapshot) if a span was dropped or a started span has not ended."""
        self.tracer_provider.force_flush()
        spans, dropped, unfinished = self._rec._snapshot()
        complete = dropped == 0 and not unfinished
        t = Trace(_convert(spans), complete)
        if not complete:
            raise IncompleteError(t, dropped, unfinished)
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
        raise AssertionError(f"{kind} {q}: cannot evaluate: {e}") from None
    if v is Verdict.PASS:
        return
    if v is Verdict.INCONCLUSIVE:
        if allow_inconclusive:
            return
        raise AssertionError(f"{kind} {q}: INCONCLUSIVE: capture incomplete, absence is not proven")
    raise AssertionError(f"{kind} {q}: {v}")
