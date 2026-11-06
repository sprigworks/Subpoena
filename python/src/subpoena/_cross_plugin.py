"""The pytest plugin subpoena-cross loads into each suite run (-p). It writes
one JSON line per event to $SUBPOENA_CROSS_REPORT: each test failure with its
verdict, collection errors, and, at the end, whether the mutated file was
imported from the copy. A run that never writes "finished" died.

A failure's verdict:

- timeout: pytest-timeout stopped the test (its frame raised the failure).
- invalid: a SyntaxError in the mutated file, raised when a test imported it.
- assertion: an AssertionError, pytest.fail or failed pytest.raises whose
  innermost frame, past pytest's and subpoena's own helper frames, is in test
  code: a file pytest collected a test from, or a conftest.py. Past conftest.py
  a file's name decides nothing: python_files can match production code. A
  production module named conftest.py that pytest walks past is loaded as a
  conftest, so it counts as test code. One raised wholly inside subpoena's helpers,
  run by pytest (a watch_spawns finalizer), is an assertion too. So is
  webtest's check of a status the test stated, read the same way: webtest
  raises its own AppError for it, not an AssertionError. A 5xx is not one: see
  _status_check.
- crash: anything else, including an assert in the code under test.

An assertion is witness evidence only when it is a WitnessFailure, which the
harness raises. Text decides nothing there: a message can be a value the code
under test returned. The same frame rule holds, so the code under test raising
one is a crash.

Every record carries $SUBPOENA_CROSS_NONCE, and cross rejects a report line
without it. That raises the bar only: test code runs in this process and can
still forge a record. All of cross's variables are removed from the environment
when the plugin loads, so the tests do not see them by accident.

Under pytest-xdist the tests run in worker processes, which start after that
and so never see the variables. The controller hands them over in xdist's
workerinput. Each worker writes its own records, and its last one is
"worker_finished", since the module under test may be imported only there. A
worker that dies is a crash, as the whole process dying is without xdist.
"""

import json
import os
import sys
import threading

import pytest

from subpoena._evidence import WitnessFailure

_REPORT = os.environ.pop("SUBPOENA_CROSS_REPORT", "")
_NONCE = os.environ.pop("SUBPOENA_CROSS_NONCE", "")
_MUTATED = os.environ.pop("SUBPOENA_CROSS_MUTATED", "")
_MUTATED_FILES = json.loads(os.environ.pop("SUBPOENA_CROSS_MUTATED_FILES", "[]")) or ([_MUTATED] if _MUTATED else [])
_SELECTED = os.environ.pop("SUBPOENA_CROSS_SELECTED", "")
_SELECTED = set(json.loads(_SELECTED)) if _SELECTED else None
_COVERAGE = {os.path.realpath(p) for p in json.loads(os.environ.pop("SUBPOENA_CROSS_COVERAGE", "[]"))}
_ROOT = os.path.realpath(os.environ.pop("SUBPOENA_CROSS_ROOT", ""))
_WORKER_INPUT = "subpoena_cross"

# The files pytest collected a test from, ahead of any deselection.
_TEST_FILES = set()

# Frames from these packages are assertion machinery, not where a failure
# came from: skip past them to the code that called them.
_HELPERS = {"_pytest", "pytest", "pluggy", "unittest", "subpoena"}


def _write(rec):
    if _REPORT:
        rec["nonce"] = _NONCE
        # One write on an append descriptor: xdist workers share the file.
        fd = os.open(_REPORT, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(rec) + "\n").encode("utf-8"))
        finally:
            os.close(fd)


def pytest_configure(config):
    global _REPORT, _NONCE, _MUTATED_FILES, _SELECTED
    settings = getattr(config, "workerinput", {}).get(_WORKER_INPUT)
    if settings:
        _REPORT, _NONCE, _MUTATED_FILES = settings["report"], settings["nonce"], settings["mutated"]
        _SELECTED = None if settings["selected"] is None else set(settings["selected"])


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
    node.workerinput[_WORKER_INPUT] = {"report": _REPORT, "nonce": _NONCE, "mutated": _MUTATED_FILES,
                                       "selected": None if _SELECTED is None else sorted(_SELECTED)}


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    if error:
        _write({"kind": "failure", "test": f"xdist worker {node.gateway.id}", "when": "worker",
                "verdict": "crash", "assertion": False, "type": "WorkerDied", "message": str(error)[:2000]})


def _frames(excinfo):
    """(top-level package, filename) of each traceback frame, innermost last."""
    out, tb = [], excinfo.tb
    while tb is not None:
        f = tb.tb_frame
        out.append(((f.f_globals.get("__name__") or "").split(".")[0], f.f_code.co_filename))
        tb = tb.tb_next
    return out


def _is_test_file(filename):
    return os.path.basename(filename) == "conftest.py" or os.path.realpath(filename) in _TEST_FILES


def _same_file(a, b):
    return bool(a) and bool(b) and os.path.realpath(a) == os.path.realpath(b)


def _status_check(excinfo):
    """webtest's TestApp found a status other than the one the test stated, and
    the app did not answer 5xx. Read from _check_status's own arguments, since
    the message holds the app's status line. With no status= the test stated
    nothing: webtest's default check raised. A 5xx is the app falling over, as a
    catch-all answers any exception, and not a refusal the test saw."""
    kind = excinfo.type
    if kind.__name__ != "AppError" or kind.__module__.split(".")[0] != "webtest":
        return False
    tb = excinfo.tb
    while tb.tb_next is not None:
        tb = tb.tb_next
    if tb.tb_frame.f_code.co_name != "_check_status":
        return False  # AppError also reports errors the app logged
    stated, res = tb.tb_frame.f_locals.get("status"), tb.tb_frame.f_locals.get("res")
    return stated is not None and res is not None and res.status_int < 500


def _verdict(item, excinfo):
    frames = _frames(excinfo)
    if any(pkg == "pytest_timeout" for pkg, _ in frames):
        return "timeout"
    if excinfo.errisinstance(SyntaxError) and any(
            _same_file(getattr(excinfo.value, "filename", ""), path) for path in _MUTATED_FILES):
        return "invalid"
    status_check = _status_check(excinfo)
    if not (status_check or excinfo.errisinstance(AssertionError) or excinfo.errisinstance(pytest.fail.Exception)):
        return "crash"
    for pkg, filename in reversed(frames):
        if pkg in _HELPERS or (status_check and pkg == "webtest"):
            continue
        return "assertion" if _is_test_file(filename) else "crash"
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
                "witness": verdict == "assertion" and call.excinfo.errisinstance(WitnessFailure),
                "message": str(call.excinfo.value)[:2000]})


def pytest_collectreport(report):
    if report.failed:
        _write({"kind": "collect_error", "node": report.nodeid, "message": str(report.longrepr)[-2000:]})


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    # pytest.Function only: a doctest or a linter item has a production file's path.
    _TEST_FILES.update(os.path.realpath(str(item.path)) for item in items if isinstance(item, pytest.Function))
    if _SELECTED is None:
        return
    available = {item.nodeid for item in items}
    if not _SELECTED <= available:
        raise pytest.UsageError("subpoena-cross: selected tests were not collected")
    deselected = [item for item in items if item.nodeid not in _SELECTED]
    items[:] = [item for item in items if item.nodeid in _SELECTED]
    config.hook.pytest_deselected(items=deselected)


def pytest_collection_finish(session):
    _write({"kind": "collected", "tests": [item.nodeid for item in session.items]})


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    if not _COVERAGE:
        yield
        return
    lines = {}
    previous = sys.gettrace()
    previous_thread = threading.gettrace() if hasattr(threading, "gettrace") else None
    filenames = {}
    def line_trace(frame, event, arg):
        if event == "line":
            lines.setdefault(filenames[frame.f_code.co_filename], set()).add(frame.f_lineno)
        return line_trace
    def trace(frame, event, arg):
        filename = frame.f_code.co_filename
        if filename not in filenames:
            real = os.path.realpath(filename)
            filenames[filename] = (os.path.relpath(real, _ROOT).replace(os.sep, "/")
                                   if real in _COVERAGE else None)
        return line_trace if filenames[filename] is not None else None
    sys.settrace(trace)
    threading.settrace(trace)
    try:
        yield
    finally:
        sys.settrace(previous)
        threading.settrace(previous_thread)
        _write({"kind": "coverage", "test": item.nodeid,
                "lines": {p: sorted(hit) for p, hit in lines.items()}})


def pytest_sessionfinish(session, exitstatus):
    loaded = {os.path.realpath(getattr(m, "__file__", "") or "") for m in list(sys.modules.values())}
    missing = [path for path in _MUTATED_FILES if os.path.realpath(path) not in loaded]
    kind = "worker_finished" if hasattr(session.config, "workerinput") else "finished"
    _write({"kind": kind, "exitstatus": int(exitstatus), "missing": missing})
