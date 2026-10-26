# subpoena:impl_derived (ported alongside the Go reference, after reading it)
"""The query corpus (docs/ports.md Q1-Q3) through the Python evaluator, without
Go: expected.yaml, the unsupported pairs and rejected.traceql. CI also runs
subpoena-conform over `python -m subpoena.traceql`, the protocol check."""

import json

import pytest
import yaml

from conftest import CONFORMANCE, ROOT
from subpoena import traceql

EXPECTED = yaml.safe_load((CONFORMANCE / "expected.yaml").read_text())
QUERIES = {f"invariants/{p.stem}": p.read_text().strip() for p in sorted((ROOT / "invariants").glob("*.traceql"))}
QUERIES.update({f"queries/{p.stem}": p.read_text().strip() for p in sorted((CONFORMANCE / "queries").glob("*.traceql"))})
FIXTURES = {p.stem: traceql.traces_from_otlp(json.loads(p.read_text())) for p in sorted((CONFORMANCE / "fixtures").glob("*.json"))}
REJECTED = [l.strip() for l in (CONFORMANCE / "rejected.traceql").read_text().splitlines() if l.strip() and not l.startswith("#")]
PAIRS = [(q, f) for q in QUERIES for f in FIXTURES]


@pytest.mark.parametrize("query,fixture", PAIRS, ids=[f"{q}@{f}" for q, f in PAIRS])
def test_corpus(query, fixture):
    q = traceql.parse(QUERIES[query])
    if fixture in (EXPECTED.get("unsupported") or {}).get(query, []):
        with pytest.raises(traceql.UnsupportedValueError):
            q.eval(FIXTURES[fixture])
        return
    got = sorted(m.trace_id for m in q.eval(FIXTURES[fixture]))
    assert got == sorted(((EXPECTED["queries"].get(query) or {}).get(fixture)) or [])


@pytest.mark.parametrize("src", REJECTED)
def test_rejected(src):
    with pytest.raises(traceql.ParseError):
        traceql.parse(src)


def test_attributes():
    q = traceql.parse('{ span.b = 1 && name = "x" } >> { span.a = "y" || span.b = 2 }')
    assert q.attributes() == ["a", "b"]
