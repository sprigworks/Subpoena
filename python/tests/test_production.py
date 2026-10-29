# subpoena:impl_derived (ported from pkg/production/production_test.go, after reading it)
"""Test-tier attribute dropping (pkg/production): the Exporter and the
collector config, against the generated registry tiers."""

import importlib.util

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from conftest import ROOT
from subpoena.production import TEST_TIER, Exporter, collector_config, test_tier_keys

_spec = importlib.util.spec_from_file_location("semconv", ROOT / "generated" / "python" / "semconv.py")
semconv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(semconv)

# An attribute outside the registry (an upstream semantic convention).
UPSTREAM = "http.request.method"


def _provider():
    mem = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(Exporter(mem, semconv.ATTRIBUTE_TIERS)))
    return mem, tp


def keys(attrs):
    return list(attrs.keys())


def test_exporter_drops_test_tier_everywhere():
    mem, tp = _provider()
    tr = tp.get_tracer("t")
    linked = tr.start_span(semconv.SPAN_AGENT_SESSION_OPEN)
    linked.end()
    s = tr.start_span(
        semconv.SPAN_AGENT_SESSION_AUTHORIZE,
        links=[trace.Link(linked.get_span_context(),
                          {semconv.ATTR_SESSION_ID: "s", UPSTREAM: "GET"})],
        attributes={
            semconv.ATTR_SESSION_ID: "sess-1",
            semconv.ATTR_AUTHORIZATION_ALLOWED: False,
            semconv.ATTR_AUTHORIZATION_POLICY_ID: "p",
            UPSTREAM: "POST",
        },
    )
    s.add_event("e", {semconv.ATTR_PROCESS_COMMAND_LINE: "sleep 1",
                      semconv.ATTR_AUTHORIZATION_ALLOWED: False})
    s.end()

    got = mem.get_finished_spans()
    assert len(got) == 2
    sp = got[1]
    assert sorted(keys(sp.attributes)) == sorted(
        [semconv.ATTR_AUTHORIZATION_ALLOWED, semconv.ATTR_AUTHORIZATION_POLICY_ID, UPSTREAM])
    assert keys(sp.events[0].attributes) == [semconv.ATTR_AUTHORIZATION_ALLOWED]
    assert keys(sp.links[0].attributes) == [UPSTREAM]
    # Everything else is the original span.
    assert sp.name == semconv.SPAN_AGENT_SESSION_AUTHORIZE
    assert sp.get_span_context() == s.get_span_context()
    assert sp.start_time == s.start_time and sp.end_time == s.end_time
    assert sp.resource == s.resource and sp.kind == s.kind and sp.status == s.status
    assert sp.instrumentation_scope == s.instrumentation_scope
    # The original is not mutated.
    assert semconv.ATTR_SESSION_ID in s.attributes
    assert semconv.ATTR_PROCESS_COMMAND_LINE in s.events[0].attributes
    assert semconv.ATTR_SESSION_ID in s.links[0].attributes


def test_exporter_keeps_parent_and_dropped_counts():
    mem, tp = _provider()
    tr = tp.get_tracer("t")
    with tr.start_as_current_span("outer") as outer:
        with tr.start_as_current_span("inner"):
            pass
    inner = mem.get_finished_spans()[0]
    assert inner.parent == outer.get_span_context()
    assert (inner.dropped_attributes, inner.dropped_events, inner.dropped_links) == (0, 0, 0)


def test_exporter_delegates_shutdown_and_force_flush():
    calls = []

    class Next(InMemorySpanExporter):
        def shutdown(self):
            calls.append("shutdown")

        def force_flush(self, timeout_millis=30000):
            calls.append("flush")
            return True

    e = Exporter(Next(), semconv.ATTRIBUTE_TIERS)
    assert e.force_flush() is True
    e.shutdown()
    assert calls == ["flush", "shutdown"]


def test_every_test_tier_key_is_dropped():
    # The registry's test-tier set, so a new test-tier attribute is covered
    # without editing this test, and the set is never empty by accident.
    ks = test_tier_keys(semconv.ATTRIBUTE_TIERS)
    assert ks, "no test-tier attributes in the registry"
    mem, tp = _provider()
    tp.get_tracer("t").start_span(semconv.SPAN_AGENT_SESSION_EXEC,
                              attributes={k: "x" for k in ks}).end()
    assert len(mem.get_finished_spans()[0].attributes) == 0


def test_test_tier_keys_sorted_and_by_value():
    assert TEST_TIER == "test"
    assert test_tier_keys({"b": "test", "a": "test", "c": "all"}) == ["a", "b"]


def test_collector_config_empty_without_test_tier():
    assert collector_config("x", {"a": "all"}) == ""
    assert collector_config("x", {}) == ""


def test_collector_config_matches_the_example():
    cfg = collector_config("subpoena-drop-test-tier", semconv.ATTRIBUTE_TIERS)
    for k in test_tier_keys(semconv.ATTRIBUTE_TIERS):
        assert 'delete_key(attributes, "%s")' % k in cfg
    path = ROOT / "examples" / "gateway" / "production" / "otelcol.yaml"
    assert cfg in path.read_text(), "%s is out of step with the registry tiers; it must contain:\n%s" % (path, cfg)
