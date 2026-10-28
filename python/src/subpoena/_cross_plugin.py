"""The pytest plugin subpoena-cross loads into each suite run (-p). It writes
one JSON line per event to $SUBPOENA_CROSS_REPORT: each test failure with its
verdict, collection errors, and, at the end, whether the mutated file was
imported from the copy. A run that never writes "finished" died.

A failure's verdict:

- timeout: pytest-timeout stopped the test (its frame raised the failure).
- invalid: a SyntaxError in the mutated file, raised when a test imported it.
- assertion: an AssertionError, pytest.fail or failed pytest.raises whose
  innermost frame, past pytest's and subpoena's own helper frames, is in test
  code: a module pytest collects as tests (python_files), a conftest.py, or
  the failing test's own file. One raised wholly inside subpoena's helpers,
  run by pytest (a watch_spawns finalizer), is an assertion too.
- crash: anything else, including an assert in the code under test.

Every record carries $SUBPOENA_CROSS_NONCE, and cross rejects a report line
without it. That raises the bar only: test code runs in this process and can
still forge a record. Both variables are removed from the environment when
the plugin loads, so the tests do not see them by accident.
"""

import fnmatch
import json
import os
import sys

import pytest

_REPORT = os.environ.pop("SUBPOENA_CROSS_REPORT", "")
_NONCE = os.environ.pop("SUBPOENA_CROSS_NONCE", "")
_MUTATED = os.environ.get("SUBPOENA_CROSS_MUTATED", "")

# Frames from these packages are assertion machinery, not where a failure
# came from: skip past them to the code that called them.
_HELPERS = {"_pytest", "pytest", "pluggy", "unittest", "subpoena"}


def _write(rec):
    if _REPORT:
        rec["nonce"] = _NONCE
        with open(_REPORT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def _frames(excinfo):
    """(top-level package, filename) of each traceback frame, innermost last."""
    out, tb = [], excinfo.tb
    while tb is not None:
        f = tb.tb_frame
        out.append(((f.f_globals.get("__name__") or "").split(".")[0], f.f_code.co_filename))
        tb = tb.tb_next
    return out


def _is_test_file(item, filename):
    base = os.path.basename(filename)
    if base == "conftest.py":
        return True
    try:
        if os.path.realpath(filename) == os.path.realpath(str(item.path)):
            return True
    except (OSError, AttributeError):
        pass
    patterns = item.config.getini("python_files") or ["test_*.py", "*_test.py"]
    return any(fnmatch.fnmatch(base, p) for p in patterns)


def _same_file(a, b):
    return bool(a) and bool(b) and os.path.realpath(a) == os.path.realpath(b)


def _verdict(item, excinfo):
    frames = _frames(excinfo)
    if any(pkg == "pytest_timeout" for pkg, _ in frames):
        return "timeout"
    if excinfo.errisinstance(SyntaxError) and _same_file(getattr(excinfo.value, "filename", ""), _MUTATED):
        return "invalid"
    if not (excinfo.errisinstance(AssertionError) or excinfo.errisinstance(pytest.fail.Exception)):
        return "crash"
    for pkg, filename in reversed(frames):
        if pkg in _HELPERS:
            continue
        return "assertion" if _is_test_file(item, filename) else "crash"
    # Raised and run wholly by pytest and subpoena: a subpoena teardown check.
    return "assertion" if any(pkg == "subpoena" for pkg, _ in frames) else "crash"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.failed and call.excinfo is not None:
        verdict = _verdict(item, call.excinfo)
        _write({"kind": "failure", "test": item.nodeid, "when": call.when, "verdict": verdict,
                "assertion": verdict == "assertion", "type": call.excinfo.typename,
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
