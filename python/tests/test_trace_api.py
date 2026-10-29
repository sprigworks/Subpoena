# subpoena:impl_derived (written after reading pkg/harness/trace.go and subpoena/harness.py)
"""Trace.spans and Trace.query's Result, as in Go: a query result carries
the snapshot's completeness, so a caller cannot read matches without it."""

from subpoena.harness import Harness, IncompleteError, Result


def snapshot(unfinished=False):
    h = Harness()
    t = h.tracer("t")
    with t.start_as_current_span("parent"):
        with t.start_as_current_span("child") as c:
            c.set_attribute("k", "v")
    if unfinished:
        t.start_span("open")
    try:
        return h.collect()
    except IncompleteError as e:
        return e.trace


def test_spans_returns_one_trace():
    tr = snapshot()
    (tid,) = tr.trace_ids()
    spans = tr.spans(tid)
    assert sorted(s.name for s in spans) == ["child", "parent"]
    child = next(s for s in spans if s.name == "child")
    parent = next(s for s in spans if s.name == "parent")
    assert child.parent_id == parent.id and child.attrs == {"k": "v"}
    assert tr.spans("0" * 32) == []
    spans.clear()
    assert len(tr.spans(tid)) == 2, "the snapshot is immutable"


def test_query_result_carries_completeness():
    r = snapshot().query('{ name = "child" }')
    assert isinstance(r, Result) and r.complete and r.count() == 1 and len(r) == 1
    assert [m.trace_id for m in r] == [m.trace_id for m in r.matches]
    r = snapshot(unfinished=True).query('{ name = "child" }')
    assert not r.complete and r.count() == 1
    assert snapshot().query('{ name = "none" }').count() == 0
