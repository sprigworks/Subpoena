# subpoena:impl_derived (ported alongside the Go reference, after reading it)
"""conformance/harness.yaml (docs/ports.md H1-H6) through the Python harness:
the same cases the Go harness passes."""

import pytest
import yaml
from opentelemetry import trace as trace_api
from opentelemetry.context import Context

from conftest import CONFORMANCE
from subpoena.harness import Harness, IncompleteError, require_absent, require_exists

CASES = yaml.safe_load((CONFORMANCE / "harness.yaml").read_text())["cases"]


def test_the_cases_are_there():
    assert len(CASES) >= 6


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_harness_case(case, monkeypatch):
    for k, v in (case.get("env") or {}).items():
        monkeypatch.setenv(k, v)
    h = Harness(case.get("capacity", 0) or 10000)
    tracer = h.tracer("harness-case")
    ctxs, to_end = {}, []
    for s in case["spans"]:
        parent = ctxs[s["parent"]] if s.get("parent") else Context()
        span = tracer.start_span(s["name"], context=parent)
        for i in range(s.get("filler", 0)):
            span.set_attribute(f"filler.{i}", i)
        for k, v in (s.get("attrs") or {}).items():
            span.set_attribute(k, v)
        ctxs[s["id"]] = trace_api.set_span_in_context(span)
        if s.get("ended", True):
            to_end.append(span)
    for span in reversed(to_end):
        span.end()

    want = case["collect"]
    try:
        tr = h.collect()
        dropped, unfinished = 0, []
    except IncompleteError as e:
        tr, dropped, unfinished = e.trace, e.dropped, e.unfinished
    assert (tr.complete, dropped, unfinished, len(tr.trace_ids())) == (
        want["complete"], want["dropped"], want.get("unfinished") or [], want["traces"])

    for a in case["assertions"]:
        kind, q = ("exists", a["exists"]) if "exists" in a else ("absent", a["absent"])
        check = tr.exists if kind == "exists" else tr.absent
        require = require_exists if kind == "exists" else require_absent
        if a.get("error"):
            with pytest.raises(ValueError):
                check(q)
            with pytest.raises(AssertionError):
                require(tr, q)
            continue
        assert str(check(q)) == a["verdict"], f"{kind} {q}"
        failed = False
        try:
            require(tr, q)
        except AssertionError:
            failed = True
        assert failed == (a["require"] == "fails"), f"{kind} {q}: require failed={failed}"
    h.shutdown()
