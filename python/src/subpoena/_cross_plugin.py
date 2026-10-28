"""The pytest plugin subpoena-cross loads into each suite run (-p). It writes
one JSON line per event to $SUBPOENA_CROSS_REPORT: each test failure with
whether it was an assertion, collection errors, and, at the end, whether the
mutated file was imported from the copy. A run that never writes "finished"
died."""

import json
import os
import sys

import pytest

_REPORT = os.environ.get("SUBPOENA_CROSS_REPORT", "")
_MUTATED = os.environ.get("SUBPOENA_CROSS_MUTATED", "")


def _write(rec):
    if _REPORT:
        with open(_REPORT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def _is_assertion(excinfo):
    # pytest.fail raises Failed, an OutcomeException; it is an assertion.
    return excinfo.errisinstance(AssertionError) or excinfo.errisinstance(pytest.fail.Exception)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.failed and call.excinfo is not None:
        _write({"kind": "failure", "test": item.nodeid, "when": call.when,
                "assertion": _is_assertion(call.excinfo), "type": call.excinfo.typename,
                "message": str(call.excinfo.value)[:2000]})


def pytest_collectreport(report):
    if report.failed:
        _write({"kind": "collect_error", "node": report.nodeid, "message": str(report.longrepr)[-2000:]})


def pytest_sessionfinish(session, exitstatus):
    loaded = True
    if _MUTATED:
        want = os.path.realpath(_MUTATED)
        loaded = any(os.path.realpath(getattr(m, "__file__", "") or "") == want
                     for m in list(sys.modules.values()))
    _write({"kind": "finished", "exitstatus": int(exitstatus), "mutated_loaded": loaded})
