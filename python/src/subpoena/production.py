"""Keeps test-tier attributes out of production telemetry. A port of
pkg/production.

Every registry attribute carries a tier: "test" (never exported in
production, such as session.id) or "all". Weaver generates the map,
ATTRIBUTE_TIERS in generated/python/semconv.py. Two ways to apply it:

    exporter = Exporter(OTLPSpanExporter(), ATTRIBUTE_TIERS)   # in the service
    text = collector_config("subpoena-drop-test-tier", ATTRIBUTE_TIERS)

collector_config emits an OpenTelemetry Collector transform processor for
services in other languages; examples/gateway/production/otelcol.yaml holds
the registry's own.
"""

from __future__ import annotations

import json
from typing import Any, List, Mapping, Sequence

from opentelemetry.attributes import BoundedAttributes
from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util import BoundedList
from opentelemetry.trace import Link

TEST_TIER = "test"


def _tier(t: Any) -> str:
    return str(getattr(t, "value", t))


def test_tier_keys(tiers: Mapping[str, Any]) -> List[str]:
    """The keys whose tier is TEST_TIER, sorted."""
    return sorted(k for k, t in tiers.items() if _tier(t) == TEST_TIER)


test_tier_keys.__test__ = False  # not a pytest test


def _keep(attrs: Any, drop: frozenset, dropped: int) -> Any:
    if attrs is None:
        return None
    kept = {k: v for k, v in attrs.items() if k not in drop}
    out = BoundedAttributes(attributes=kept, immutable=True)
    out.dropped = dropped
    return out


def _bounded(items: Sequence[Any], dropped: int) -> BoundedList:
    # ReadableSpan reports dropped events and links only from a BoundedList.
    out = BoundedList(None)
    out.extend(items)
    out.dropped = dropped
    return out


class Exporter(SpanExporter):
    """Wraps next_exporter so test-tier attributes are removed from every span,
    span event and link before export. Attributes not in tiers pass through."""

    def __init__(self, next_exporter: SpanExporter, tiers: Mapping[str, Any]) -> None:
        self._next = next_exporter
        self._drop = frozenset(test_tier_keys(tiers))

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self._next.export([self._filter(s) for s in spans])

    def shutdown(self) -> None:
        self._next.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._next.force_flush(timeout_millis)

    def _filter(self, s: ReadableSpan) -> ReadableSpan:
        events = []
        for ev in s.events:
            events.append(Event(ev.name, _keep(ev.attributes, self._drop, ev.dropped_attributes), ev.timestamp))
        links = [Link(l.context, _keep(l.attributes, self._drop, l.dropped_attributes)) for l in s.links]
        out = ReadableSpan(
            name=s.name,
            context=s.get_span_context(),
            parent=s.parent,
            resource=s.resource,
            # s.attributes is a read-only view without the drop count; the
            # dropped_* properties are the SDK's public record of the loss.
            attributes=_keep(s.attributes, self._drop, s.dropped_attributes),
            events=_bounded(events, s.dropped_events),
            links=_bounded(links, s.dropped_links),
            kind=s.kind,
            status=s.status,
            start_time=s.start_time,
            end_time=s.end_time,
            instrumentation_scope=s.instrumentation_scope,
        )
        return out


def _quote(s: str) -> str:
    # Go's %q (strconv.Quote) and json.dumps agree on printable ASCII keys.
    return json.dumps(s)


def collector_config(name: str, tiers: Mapping[str, Any]) -> str:
    """An OpenTelemetry Collector `processors:` block holding one transform
    processor, transform/<name>, that deletes the test-tier attributes from
    spans and span events (OTTL has no span-link context; links keep theirs,
    the one difference from Exporter). "" when no attribute is test-tier."""
    keys = test_tier_keys(tiers)
    if not keys:
        return ""
    b = ["processors:\n  transform/%s:\n    error_mode: ignore\n    trace_statements:\n" % name]
    for ctx in ("span", "spanevent"):
        b.append("      - context: %s\n        statements:\n" % ctx)
        for k in keys:
            b.append("          - delete_key(attributes, %s)\n" % _quote(k))
    return "".join(b)
