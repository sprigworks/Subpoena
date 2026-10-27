# subpoena:impl_derived (written after reading harness.py and pkg/harness/limits_test.go)
"""H1 and H3 limits: the harness keeps every attribute, whole, whatever the
OTEL_* variables say, and records under OTEL_SDK_DISABLED. A span that lost
attributes, events or links to span limits makes the capture incomplete, so
an absence check on it is Inconclusive, not Pass. A value truncated by a
length limit is not counted by the SDK, so it cannot be detected; only the
harness's own unlimited length guards against it."""

import pytest
from opentelemetry import trace as trace_api
from opentelemetry.sdk.trace import SpanLimits, TracerProvider

from subpoena.harness import Harness, IncompleteError, Verdict

LIMIT_VARS = [
    "OTEL_ATTRIBUTE_COUNT_LIMIT",
    "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT",
    "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT",
    "OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT",
]


def test_decision_set_before_200_others_is_kept():
    # Python's SDK drops the oldest attribute when a span is full, so a
    # decision set first is the one that would be lost under the default 128.
    h = Harness()
    span = h.tracer("t").start_span("authorize")
    span.set_attribute("allowed", False)
    for i in range(200):
        span.set_attribute(f"filler.{i}", i)
    span.end()
    tr = h.collect()
    assert tr.exists("{ span.allowed = false }") == Verdict.PASS


@pytest.mark.parametrize("var", LIMIT_VARS)
def test_env_limits_do_not_reach_the_harness(monkeypatch, var):
    monkeypatch.setenv(var, "2")
    h = Harness()
    span = h.tracer("t").start_span("authorize")
    span.set_attribute("allowed", False)
    for i in range(5):
        span.set_attribute(f"filler.{i}", i)
    span.set_attribute("decision", "deny")
    span.end()
    tr = h.collect()
    assert tr.exists('{ span.allowed = false && span.decision = "deny" }') == Verdict.PASS


def test_span_that_lost_attributes_makes_capture_incomplete():
    # Code under test that ignores H1 and records through a limited provider
    # into the same recorder: the loss must surface, not pass silently.
    h = Harness()
    limited = TracerProvider(span_limits=SpanLimits(max_span_attributes=1))
    limited.add_span_processor(h._rec)
    span = limited.get_tracer("t").start_span("authorize")
    span.set_attribute("allowed", False)
    span.set_attribute("filler", 1)
    span.end()
    with pytest.raises(IncompleteError) as e:
        h.collect()
    assert e.value.truncated == ["authorize"]
    assert "spans lost attributes, events or links: authorize" in str(e.value)
    assert e.value.trace.absent("{ span.allowed = false }") == Verdict.INCONCLUSIVE


def test_event_that_lost_attributes_makes_capture_incomplete():
    h = Harness()
    limited = TracerProvider(span_limits=SpanLimits(max_event_attributes=1))
    limited.add_span_processor(h._rec)
    span = limited.get_tracer("t").start_span("authorize")
    span.add_event("decision", {"a": 1, "b": 2})
    span.end()
    with pytest.raises(IncompleteError) as e:
        h.collect()
    assert e.value.truncated == ["authorize"]


def test_sdk_disabled_does_not_reach_the_harness(monkeypatch):
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    h = Harness()
    h.tracer("t").start_span("exec").end()
    h.tracer_provider.get_tracer("u").start_span("spawn").end()
    tr = h.collect()
    assert tr.absent('{ name = "exec" }') == Verdict.FAIL
    assert tr.absent('{ name = "spawn" }') == Verdict.FAIL


def test_harness_refuses_a_provider_that_records_nothing(monkeypatch):
    monkeypatch.setattr(TracerProvider, "get_tracer", lambda self, *a, **k: trace_api.NoOpTracer())
    with pytest.raises(RuntimeError, match="record nothing"):
        Harness()
