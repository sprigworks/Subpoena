# Subpoena for Python

The Python port of Subpoena's tier-1 harness. It meets the contract in
[docs/ports.md](../docs/ports.md), checked the same way as the Go reference.

| Part | Module | Checked by |
| --- | --- | --- |
| Harness (H1–H6) | `subpoena.harness` | `conformance/harness.yaml`, all cases (`tests/test_harness_cases.py`) |
| TraceQL subset (Q1–Q3) | `subpoena.traceql`, native, no Go needed | the whole corpus in `tests/test_traceql.py`, and `subpoena-conform` over `python -m subpoena.traceql`: 139 cases, 0 mismatches |
| Witness file (W3) | `subpoena.witness` | the `witness.ReadLog` cases (`tests/test_witness.py`) |
| Generated names | `generated/python/semconv.py` (Weaver) | `pkg/production/languages_test.go` |
| Lint (L1), cross-examination (G1) | not yet | — |

```python
from subpoena.harness import Harness, require_absent, require_exists

def test_denied_session_never_execs():
    h = Harness()
    gateway = Gateway(tracer_provider=h.tracer_provider)  # inject; never install another provider
    gateway.handle(denied_request)
    tr = h.collect()                                        # before any assertion
    require_absent(tr, NO_EXEC_AFTER_DENY)                  # Inconclusive fails, too
```

`collect()` raises `IncompleteError` (carrying the snapshot) if a span was
dropped or never ended. Absence on an incomplete snapshot is Inconclusive, and
`require_absent` fails on it unless `allow_inconclusive=True` is passed.

## Development

```
make python        # from the repo root: venv (uv), pytest, subpoena-conform
```

Python 3.9+; depends on `opentelemetry-api` and `opentelemetry-sdk` only. CI
runs 3.9 and 3.12. Not yet published to PyPI.
