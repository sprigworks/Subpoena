"""Cross-examination for Python (docs/ports.md G1): remove each statement
marked as enforcement, in a copy of the project, and require the test suite
to fail. A port of internal/cross; its verdict rules are the same.

Markers, as comments:

    # subpoena:enforcement_point          on the line directly above a def
                                          (or above its decorators)
    return DENIED  # subpoena:enforcement on a simple statement inside it
    if not admin:  # subpoena:enforcement_guard true
                                          on an if inside it: the condition
                                          is forced to that value

A mutant replaces the marked statement with `pass`, or the guarded
condition with True or False. A return that ends the function, in a function
that never gives None otherwise, has no mutant: None would stand in for a value
that can carry the allow decision, so it is invalid. Mark the guard. Verdicts:

- killed: a test failed on an assertion raised from test code: an
  AssertionError, pytest.fail or a failed pytest.raises whose innermost frame
  (past pytest's and subpoena's own helpers) is in test code (a file pytest
  collected a test from, or a conftest.py), or a subpoena
  teardown check such as watch_spawns, or webtest's check of the status a test
  expected. An assert in the code under test is a crash, as a panic is in Go.
  A kill says a test noticed, not that it examined the refusal: a removal that
  stops the allowed path too is killed by an allowed-path test alone
  (docs/architecture.md, "What a kill does not prove").
- unconfirmed: a kill, but the suite passed in one of _REPEATS runs with the
  mutant, or failed in one of _RERUNS reruns without it, each on a fresh copy:
  state outside the copy, or a flake. A flake can still pass them all, and state
  that clears itself is gone by the first rerun. -select does not retry it. The
  run fails.
- survived: the suite stayed green. The run fails.
- crashed: the suite went red only by another exception, or the test process
  died. A crash is not evidence that the enforcement is tested; the run fails.
- invalid: the mutant has no honest stand-in (above), does not import (a
  SyntaxError, or any collection error), or the suite never imported the mutated module from the copy (an
  installed copy of the package shadowed it). It proves nothing; the run
  fails.
- timeout: the suite ran past the timeout, or a test failed by
  pytest-timeout. The run fails.

A marker that takes no effect is an error, never skipped: a statement or
guard marker outside an enforcement point, on the wrong kind of line, with
trailing text, or misspelt; and an enforcement point with no statement or
guard marker.

The point marker is read as Go reads a doc comment: the run of full-line
comments directly above the def (or its decorators), any of which mentions
subpoena:enforcement_point. A trailing comment on the line above is not one.

Setup faults (unreadable or non-UTF-8 marked files, a tree that cannot be
copied, a copy that drifted from the discovery snapshot) are errors, exit 2,
never a verdict.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import math
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import tokenize
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

KILLED = "enforcement-mutant-killed"
KILLED_BY_SELF_REPORT = "enforcement-mutant-killed-by-self-report"
SURVIVED = "enforcement-mutant-survived"
CRASHED = "enforcement-mutant-crashed"
UNCONFIRMED = "enforcement-mutant-unconfirmed"
INVALID = "enforcement-mutant-invalid"
TIMED_OUT = "enforcement-mutant-timeout"
MASKED = "enforcement-layer-masked"

# How many times a kill's test run repeats with the mutant in place. A red run
# the mutant caused is red again; a rare flake is not, and runs without the
# mutant pass one nearly every time.
_REPEATS = 1

# How many times a kill's test run happens again without the mutant. One rerun
# catches a test that fails half the time only half the time.
_RERUNS = 3

_ANY_MARKER = re.compile(r"#\s*subpoena\s*:\s*enforc")  # cross's markers, misspelt ones too
# A marker after an upstream comment on the same line: return x  # why  # subpoena:enforcement
_TRAILING = re.compile(r"\s#\s*(subpoena:enforcement(_guard)?(\s+(true|True|false|False|group=\S+))*)\s*$")
_SOURCE_MARKER = re.compile(r"#\s*subpoena:enforcement(_guard)?(\s|$)")
_ONLY_MARKER = re.compile(r"^\s*#\s*subpoena\s*:\s*enforc")
_POINT = "subpoena:enforcement_point"
_STATEMENT = "subpoena:enforcement"
_SIMPLE = (ast.Return, ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Raise, ast.Pass,
           ast.Break, ast.Continue, ast.Delete, ast.Assert)
_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".tox", ".nox", ".pytest_cache", "node_modules", ".mypy_cache", ".ruff_cache"}


def _skipped(parent: str, name: str) -> bool:
    """Whether a directory is tooling, not source: a known cache or environment
    name, egg-info, or a virtual environment under any name (it has pyvenv.cfg)."""
    if name in _SKIP_DIRS or name.endswith(".egg-info"):
        return True
    return os.path.isfile(os.path.join(parent, name, "pyvenv.cfg"))


class CrossError(Exception):
    """A setup error: bad markers, a red baseline. Never a verdict."""


@dataclass
class Mutant:
    file: str      # relative to the project root, with /
    func: str
    line: int
    removed: str   # the statement or condition text
    bypass: str    # "" for a removed statement, "True"/"False" for a guard
    span: Tuple[int, int] = (0, 0)  # byte offsets of the replaced text in the file
    breaks: int = 0                 # line breaks inside the span, kept by apply
    digest: str = ""                # sha256 of the file at discovery
    group: str = ""
    no_stand_in: bool = False       # see _no_stand_in
    upstream: int = 0               # line with the marker-only lines above it taken out

    def name(self) -> str:
        return f"{self.func} ({self.file}:{self.line})"


@dataclass
class Result:
    mutant: Mutant
    outcome: str
    failing: List[str] = field(default_factory=list)
    evidence: str = ""        # witness, testimony or other, for killed
    first_failure: str = ""
    output: str = ""
    with_mutants: List[Mutant] = field(default_factory=list)
    group: str = ""
    masked_by: List[str] = field(default_factory=list)
    accepted: str = ""
    selected: List[str] = field(default_factory=list)
    evidence_file: str = ""


@dataclass
class Report:
    enforcement_points: int = 0
    markers: int = 0  # statement and guard markers in the source of the mutated files
    unplaced: List[str] = field(default_factory=list)  # those that made no mutant, as file:line
    results: List[Result] = field(default_factory=list)

    stale_accepted: List[str] = field(default_factory=list)
    snapshot: Dict[str, str] = field(default_factory=dict)

    def failed(self) -> bool:
        return (not self.results or bool(self.stale_accepted) or
                any(r.outcome != KILLED and not (r.outcome == MASKED and r.accepted)
                    for r in self.results))


# --- discovery -------------------------------------------------------------

def _comments(text: str) -> Dict[int, Tuple[str, bool]]:
    """Line number -> (the comment text on it without the leading #, whether
    the comment is the whole line). Lines are counted as ast counts them:
    universal newlines, and nothing else (not U+2028 or form feed)."""
    out = {}
    for tok in tokenize.generate_tokens(io.StringIO(text, newline=None).readline):
        if tok.type == tokenize.COMMENT:
            out[tok.start[0]] = (_marker_text(tok.string[1:].strip()), not tok.line[:tok.start[1]].strip())
    return out


_BREAK = re.compile(rb"\r\n|\r|\n")
_BOM = b"\xef\xbb\xbf"


def _line_starts(data: bytes) -> List[int]:
    """Byte offset of each line's start, lines numbered as ast numbers them.
    Line 1 starts after a BOM, which ast's columns do not count."""
    starts = [len(_BOM) if data.startswith(_BOM) else 0]
    starts.extend(m.end() for m in _BREAK.finditer(data))
    return starts


def _read_source(path: str, rel: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise CrossError(f"cross: {rel}: cannot read: {e}") from None


def _decode(data: bytes, rel: str) -> str:
    # ast's columns are UTF-8 bytes of the line; a file in another encoding
    # would put every offset somewhere else.
    try:
        enc, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        if enc not in ("utf-8", "utf-8-sig"):
            raise SyntaxError(f"declares encoding {enc}")
        return data.decode("utf-8-sig")
    except (SyntaxError, UnicodeDecodeError) as e:
        raise CrossError(f"cross: {rel}: not UTF-8 source, cannot place markers: {e}") from None


def _point_marked(comments: Dict[int, Tuple[str, bool]], first: int) -> List[int]:
    """The lines of the doc block above line first that carry the point
    marker: the full-line comments directly above, as Go's ast.FuncDecl.Doc,
    matched loosely as Go's hasPointMarker matches (fail closed)."""
    lines, line = [], first - 1
    while line in comments and comments[line][1]:
        if _POINT in comments[line][0]:
            lines.append(line)
        line -= 1
    return lines


def _marker(comment: str):
    parts = comment.split()
    if not parts or parts[0] not in (_STATEMENT, "subpoena:enforcement_guard"):
        return None
    guard = parts.pop(0) != _STATEMENT
    bypass = ""
    if guard:
        if not parts or parts[0] not in {"true", "false"}:
            raise CrossError("cross: not a marker cross applies: enforcement_guard needs the bypass value first: true or false")
        bypass = parts.pop(0).title()
    group = ""
    for arg in parts:
        match = re.fullmatch(r"group=([A-Za-z0-9_.-]+)", arg)
        if not match or group:
            raise CrossError(f"cross: not a marker cross applies: marker argument {arg!r}: want at most one group=<name>")
        group = match.group(1)
    return bypass, group


def _groups(mutants):
    groups = {}
    for m in mutants:
        if m.group:
            groups.setdefault(m.group, []).append(m)
    for group, members in groups.items():
        if len(members) == 1:
            raise CrossError(f"cross: group={group} has one layer; a group needs at least two")
        if len(members) > 8:
            raise CrossError(f"cross: group={group} has {len(members)} layers; at most 8")
    return groups


def _marker_text(comment: str) -> str:
    """A comment's marker: all of it, or the end of it when the marker follows
    an upstream comment, so marking a line needs no upstream text removed."""
    m = _TRAILING.search(comment)
    return m.group(1) if m else comment


def _upstream_line(text: str, line: int) -> int:
    """line with the marker-only lines above it taken out."""
    return line - sum(1 for l in text.split("\n")[:line - 1] if _ONLY_MARKER.match(l))


def marker_count(root: str, mutants: List[Mutant]) -> Tuple[int, List[str]]:
    """The statement and guard markers in the source of the mutated files, and,
    as file:line, those that made no mutant."""
    n, unplaced = 0, []
    for file in sorted({m.file for m in mutants}):
        lines = {m.line for m in mutants if m.file == file}
        text = _read_source(os.path.join(root, file), file).decode("utf-8")
        for i, l in enumerate(text.split("\n"), 1):
            if _SOURCE_MARKER.search(l):
                n += 1
                if i not in lines:
                    unplaced.append(f"{file}:{i}")
    return n, unplaced


def _where(m: Mutant) -> str:
    """A mutant's file and line, with the unmarked line when markers moved it."""
    if m.upstream and m.upstream != m.line:
        return f"{m.file}:{m.line} (upstream line {m.upstream})"
    return f"{m.file}:{m.line}"


def find_mutants(root: str) -> Tuple[int, List[Mutant]]:
    """Every marked mutant under root, and the number of enforcement points.
    Raises CrossError for any marker that would take no effect."""
    points, mutants = 0, []
    for path in sorted(_python_files(root)):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        data = _read_source(path, rel)
        if b"subpoena" not in data:
            continue
        text = _decode(data, rel)
        try:
            tree = ast.parse(data, filename=rel)
        except (SyntaxError, ValueError) as e:
            raise CrossError(f"cross: {rel}: {e}") from None
        comments = _comments(text)
        starts = _line_starts(data)
        digest = hashlib.sha256(data).hexdigest()

        def mutant(func: str, line: int, node: ast.AST, bypass: str) -> Mutant:
            a = starts[node.lineno - 1] + node.col_offset
            b = starts[node.end_lineno - 1] + node.end_col_offset
            return Mutant(rel, func, line, data[a:b].decode("utf-8"), bypass, (a, b),
                          node.end_lineno - node.lineno, digest, upstream=_upstream_line(text, line))

        placed = set()
        missing = []  # points with nothing to mutate; reported after stray markers, which explain them
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            first = min([node.lineno] + [d.lineno for d in node.decorator_list])
            doc = _point_marked(comments, first)
            if not doc:
                continue
            placed.update(doc)
            points += 1
            found = 0
            for st in _statements(node):
                c = comments.get(st.lineno, ("", False))[0]
                if not c or not _ANY_MARKER.match("#" + c) or st.lineno in placed:
                    continue
                marker = _marker(c)
                if marker is None:
                    continue
                bypass, group = marker
                if not bypass:
                    if not isinstance(st, _SIMPLE):
                        continue  # an if or a loop starting here: not this marker's line
                    m = mutant(node.name, st.lineno, st, "")
                    m.no_stand_in = _no_stand_in(node, st)
                else:
                    if not isinstance(st, ast.If):
                        continue
                    m = mutant(node.name, st.lineno, st.test, bypass)
                m.group = group
                placed.add(st.lineno)
                mutants.append(m)
                found += 1
            if found == 0:
                missing.append(f"cross: {rel}: {node.name} is marked {_POINT} but has no "
                               f"{_STATEMENT} statement, so it cannot be cross-examined")
        for line, (c, _) in sorted(comments.items()):
            if _ANY_MARKER.match("#" + c) and line not in placed:
                raise CrossError(
                    f"cross: {rel}:{line}: {'#' + c!r} is not a marker cross applies: statement and guard "
                    f"markers go on a simple statement or an if inside a function marked {_POINT}, the "
                    f"point marker on a full-line comment directly above the def, and markers take no "
                    f"other text")
        if missing:
            raise CrossError(missing[0])
    return points, mutants


def _gives_none(st: ast.Return) -> bool:
    return st.value is None or (isinstance(st.value, ast.Constant) and st.value.value is None)


def _ends(body: List[ast.stmt], st: ast.stmt) -> bool:
    """Removing st from body runs off body's end with nothing left to decide.
    An if with no else does not count: it could run off the end already."""
    if not body:
        return False
    last = body[-1]
    if last is st:
        return True
    blocks = []
    if isinstance(last, ast.If) and last.orelse:
        blocks = [last.body, last.orelse]
    elif isinstance(last, (ast.With, ast.AsyncWith)):
        blocks = [last.body]
    elif isinstance(last, ast.Try):
        blocks = [last.body, last.orelse] + [h.body for h in last.handlers]
    elif hasattr(ast, "Match") and isinstance(last, ast.Match):
        blocks = [c.body for c in last.cases]
    return any(_ends(b, st) for b in blocks)


def _no_stand_in(fn: ast.AST, st: ast.stmt) -> bool:
    """Removing a return that ends fn leaves None in its place, as Go's stand-in
    leaves zero values. None means "enforcement gone" only where fn gives None
    on another path. Otherwise the return can carry the allow decision (return
    user in ADMINS), and None forces enforcement on: only an allowed-path test
    notices, and the refusal goes unexamined."""
    if not isinstance(st, ast.Return) or _gives_none(st) or not _ends(fn.body, st):
        return False
    return not any(isinstance(r, ast.Return) and _gives_none(r) for r in _statements(fn))


def _statements(fn: ast.AST):
    """The statements of fn's body, outermost first, not descending into
    nested functions or classes (their markers belong to them)."""
    todo = list(fn.body)
    while todo:
        st = todo.pop(0)
        yield st
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for name in ("body", "orelse", "finalbody", "handlers"):
            todo.extend(getattr(st, name, []) or [])
        for case in getattr(st, "cases", []) or []:
            todo.extend(case.body)


def _python_files(root: str):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if not _skipped(d, x)]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(d, f)


def apply(data: bytes, m: Mutant) -> bytes:
    """The file bytes with m's span replaced, line numbers kept. data must be
    the discovery snapshot (run checks m.digest first)."""
    a, b = m.span
    repl = (m.bypass or "pass").encode()
    # Keep every later line where it was, so tracebacks and markers line up.
    # A condition's line breaks need brackets: outside them they end the if.
    if m.bypass and m.breaks:
        return data[:a] + b"(" + repl + b"\n" * m.breaks + b")" + data[b:]
    return data[:a] + repl + b"\n" * m.breaks + data[b:]


# --- running ----------------------------------------------------------------

_PLUGIN = "subpoena._cross_plugin"

# How long a pipe may stay open once pytest has gone, in seconds.
_PIPE_GRACE = 5.0


def _run_suite(copy: str, args: List[str], timeout: float, mutated: str, report: str,
               nonce: str = "", *, selected=None, coverage=None, cancel=None,
               mutated_files=None, test_helpers=()) -> Tuple[Optional[int], str]:
    # The report is created fresh, by cross, before every run: nothing left
    # from an earlier run (or planted) is read as this one's.
    if os.path.lexists(report):
        os.remove(report)
    os.close(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    env = dict(os.environ)
    env["SUBPOENA_CROSS_REPORT"] = report
    env["SUBPOENA_CROSS_NONCE"] = nonce
    env["SUBPOENA_CROSS_MUTATED"] = os.path.join(copy, mutated) if mutated else ""
    env["SUBPOENA_CROSS_MUTATED_FILES"] = json.dumps(
        [os.path.join(copy, f) for f in (mutated_files or ([mutated] if mutated else []))])
    env["SUBPOENA_CROSS_SELECTED"] = json.dumps(selected) if selected is not None else ""
    env["SUBPOENA_CROSS_COVERAGE"] = json.dumps([os.path.join(copy, f) for f in (coverage or [])])
    env["SUBPOENA_CROSS_ROOT"] = copy
    env["SUBPOENA_CROSS_TEST_HELPERS"] = json.dumps([os.path.join(copy, f) for f in test_helpers])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = copy + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    # Every test runs, whatever the arguments say: pytest stopped at the first
    # failure would never see a crash behind it, so order would decide. And a
    # plugin that shuffles would decide it again, or trip the baseline.
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:randomly",
           "-p", _PLUGIN] + args + ["--maxfail=0"]
    p = subprocess.Popen(cmd, cwd=copy, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, start_new_session=True)
    try:
        deadline = time.monotonic() + timeout
        while True:
            if cancel is not None and cancel.is_set():
                raise CrossError("cross: run canceled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(cmd, timeout)
            try:
                out, _ = p.communicate(timeout=min(remaining, 0.2))
                return p.returncode, out
            except subprocess.TimeoutExpired:
                # pytest is gone and a child it left holds the pipe. Its exit
                # code and report stand, as with Go's WaitDelay.
                if p.poll() is not None:
                    return p.returncode, _drain(p)
    except subprocess.TimeoutExpired:
        # The whole session: pytest and anything the tests started. A child
        # that left the session is out of reach and can hold the pipe.
        _kill_group(p)
        return None, _drain(p)
    except BaseException:
        # Ctrl-C (or any other way out): the suite is in its own session, so
        # it did not get the SIGINT; never leave it running.
        _kill_group(p)
        p.wait()
        raise


def _drain(p: subprocess.Popen) -> str:
    """What p printed, waiting at most _PIPE_GRACE for the pipe to close, and
    then closing it: a detached child can hold it for as long as it lives."""
    try:
        return p.communicate(timeout=_PIPE_GRACE)[0]
    except subprocess.TimeoutExpired as e:
        p.stdout.close()
        p.wait()
        out = e.output or b""
        return out.decode("utf-8", "replace") if isinstance(out, bytes) else out


def _kill_group(p: subprocess.Popen) -> None:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _read_report(path: str, nonce: str = "") -> List[dict]:
    """The plugin's records. A line that is not a record carrying this run's
    nonce is kept as a "tampered" record, which classify never reads as a
    verdict. The nonce raises the bar only: test code runs in the same process
    as the plugin and can still forge a record if it goes looking."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    rec = None
                if not isinstance(rec, dict) or rec.get("nonce") != nonce:
                    out.append({"kind": "tampered"})
                else:
                    out.append(rec)
    except FileNotFoundError:
        pass
    return out


def classify(code: Optional[int], records: List[dict], out: str) -> Tuple[str, List[str], str, str]:
    """(outcome, failing tests, evidence, first failure) for one mutant run."""
    if code is None:
        return TIMED_OUT, [], "", ""
    if any(r.get("kind") == "tampered" for r in records):
        return CRASHED, [], "", ""  # someone else wrote the report: it proves nothing
    finished = [r for r in records if r.get("kind") == "finished"]
    fails = [r for r in records if r.get("kind") == "failure"]
    if any(r.get("verdict") == "timeout" for r in fails):
        return TIMED_OUT, [r["test"] for r in fails], "", ""
    started = any(r.get("kind") == "collected" for r in records)
    if any(r.get("kind") == "collect_error" for r in records) or code in (2, 4, 5) and not finished and not started:
        return INVALID, [], "", ""  # pytest never reached a test; past that, those codes are a death
    if any(r.get("verdict") == "invalid" for r in fails):
        return INVALID, [r["test"] for r in fails], "", ""
    workers = [r for r in records if r.get("kind") == "worker_finished"]
    if finished and set.intersection(*(set(r.get("missing", [])) for r in finished[-1:] + workers)):
        return INVALID, [], "", ""  # no process of the run imported it
    if code == 0 and finished:
        return SURVIVED, [], "", ""
    if code != 1 or not finished:
        return CRASHED, [], "", ""  # the process died, or pytest stopped abnormally
    assertion = [r for r in fails if r.get("verdict") == "assertion"]
    crashed = [r for r in fails if r.get("verdict") != "assertion"]
    if crashed or not assertion:
        return CRASHED, [r["test"] for r in fails], "", ""
    # The first test collected, not the first to finish: under xdist the
    # order of the records is timing. Records of one test keep their order.
    collected = next((r.get("tests") or [] for r in records if r.get("kind") == "collected"), [])
    rank = {test: i for i, test in enumerate(collected)}
    head = min(assertion, key=lambda r: rank.get(r["test"], len(rank)))
    msg = head.get("message", "").strip()
    first = msg.splitlines()[0].strip() if msg else ""
    # Witness evidence is the failure's type, which the plugin read: the text can
    # be the code under test's own (assert r.ok, r.body; an object's repr under
    # assertEqual). Testimony claims no independence, so its tag is enough, at
    # the start only: past it comes pytest's diff of the app's values.
    ev = "witness" if head.get("witness") else "testimony" if first.startswith("testimony:") else "other"
    return KILLED, [r["test"] for r in fails], ev, first


def _baseline_reason(code, records, timeout) -> str:
    """Why a baseline run was not clean. Pytest's output can be empty (a
    timeout kills it mid-run), so this never rests on it."""
    if code is None:
        return (f"pytest did not finish within the timeout ({timeout:g}s); raise --timeout. "
                "A timeout on a busy host is not a red test")
    if any(r.get("kind") == "tampered" for r in records):
        return "the report holds a line that is not this run's"
    errors = [r for r in records if r.get("kind") == "collect_error"]
    if errors:
        return f"pytest could not collect {errors[0].get('node') or 'the tests'}"
    fails = [r for r in records if r.get("kind") == "failure"]
    if fails:
        first = fails[0]
        lines = str(first.get("message", "")).strip().splitlines()
        text = f"{first.get('type', 'failure')}: {lines[0]}" if lines else first.get("type", "failure")
        return f"{first.get('test')} failed: {text}"
    if code == 5:
        return "pytest collected no tests"
    if any(r.get("kind") == "finished" for r in records):
        return f"pytest exited {code}"
    return f"pytest exited {code} without finishing"


def _clean(code, records):
    return (code == 0 and any(r.get("kind") == "finished" for r in records) and
            not any(r.get("kind") in {"tampered", "failure", "collect_error"} for r in records))


def _masked_key(m):
    return f"{m.file} | {m.func} | group={m.group} | {' '.join(m.removed.split())}"


def _accept_masked(rep, path):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return
    reasons = {}
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = [s.strip() for s in line.split(" | ", 4)]
        if len(fields) != 5 or not fields[2].startswith("group=") or not fields[4]:
            raise CrossError(f"cross: cross-masked.txt:{number}: want <file> | <func> | group=<group> | <removed text> | <reason>, each layer listed once")
        key = " | ".join(fields[:3] + [' '.join(fields[3].split())])
        if key in reasons:
            raise CrossError(f"cross: cross-masked.txt:{number}: each layer listed once")
        reasons[key] = fields[4]
    layers = {}
    for result in rep.results:
        if result.outcome == MASKED:
            layers.setdefault(_masked_key(result.mutant), []).append(result)
    for key, reason in reasons.items():
        matches = layers.get(key, [])
        if len(matches) > 1:
            raise CrossError(f"cross: cross-masked.txt: {key!r} matches {len(matches)} masked layers")
        if matches:
            matches[0].accepted = reason
        else:
            rep.stale_accepted.append(key)


def run(target: str, pytest_args: Optional[List[str]] = None, timeout: float = 300.0, log=None,
        _before_mutate: Optional[Callable[[str], None]] = None, *, jobs: int = 1,
        select: bool = False, evidence_dir: Optional[str] = None,
        require_witness: bool = False, test_helpers: Sequence[str] = ()) -> Report:
    """Cross-examine immutable copies. Selection confirms every non-kill but an unconfirmed on the full suite.
    Parallel workers share no mutable files. Group runs always use the whole suite.
    """
    if not isinstance(jobs, int) or jobs < 1 or not math.isfinite(timeout) or timeout <= 0:
        raise CrossError("cross: jobs must be positive and timeout must be finite and positive")
    log = log or (lambda s: None)
    target = os.path.abspath(target)
    if not os.path.isdir(target):
        raise CrossError(f"cross: target is not a directory: {target}")
    args = list(pytest_args or [])
    cancel = threading.Event()
    lock = threading.Lock()
    run_id = secrets.token_hex(8)
    counter = 0
    if evidence_dir is not None:
        evidence_dir = os.path.abspath(evidence_dir)
        if os.path.realpath(target) == os.path.realpath(evidence_dir):
            raise CrossError("cross: evidence directory must differ from the target tree root")
        os.makedirs(evidence_dir, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="subpoena-cross-") as tmp:
        template = os.path.join(tmp, "snapshot")
        def ignore(directory, names):
            ignored = {name for name in names if _skipped(directory, name)}
            if evidence_dir:
                ignored.update(name for name in names if os.path.realpath(os.path.join(directory, name)) ==
                               os.path.realpath(evidence_dir))
            return ignored
        try:
            shutil.copytree(target, template, ignore=ignore)
        except OSError as exc:
            raise CrossError(f"cross: copy tree: {exc}") from None
        points, mutants = find_mutants(template)
        if not mutants:
            raise CrossError(f"cross: no {_POINT} with a {_STATEMENT} statement under {target}")
        groups = _groups(mutants)
        test_helpers = [os.path.normpath(f).replace(os.sep, "/") for f in test_helpers]
        for f in test_helpers:
            if not os.path.isfile(os.path.join(template, f)):
                raise CrossError(f"cross: --test-helper {f}: no such file under {target}")
            if any(m.file == f for m in mutants):
                raise CrossError(f"cross: --test-helper {f}: it holds enforcement markers, so it is code under test")
        markers, unplaced = marker_count(template, mutants)
        rep = Report(enforcement_points=points, markers=markers, unplaced=unplaced,
                     snapshot={m.file: m.digest for m in mutants})
        for file, digest in sorted(rep.snapshot.items()):
            log(f"snapshot {digest} {file}")

        def suite(copy, selected=None, coverage=None, members=(), label="run"):
            nonlocal counter
            with lock:
                counter += 1
                number = counter
            report = os.path.join(tmp, f"report-{number}.jsonl")
            nonce = secrets.token_hex(16)
            code, out = _run_suite(copy, args, timeout, members[0].file if members else "",
                                   report, nonce, selected=selected, coverage=coverage,
                                   cancel=cancel, mutated_files=sorted({m.file for m in members}),
                                   test_helpers=test_helpers)
            records = _read_report(report, nonce)
            evidence_file = ""
            if evidence_dir:
                prefix = os.path.join(evidence_dir, f"{run_id}-{number:05d}-{label}")
                evidence_file = prefix + ".txt"
                # Exclusive writes: concurrent runs never overwrite evidence.
                with open(evidence_file, "x", encoding="utf-8") as f:
                    f.write(out)
                with open(prefix + ".jsonl", "x", encoding="utf-8") as f:
                    with open(report, encoding="utf-8") as raw:
                        shutil.copyfileobj(raw, f)
                with open(prefix + ".json", "x", encoding="utf-8") as f:
                    json.dump({"label": label, "exit_code": code, "selected": selected,
                               "mutants": [{"file": m.file, "func": m.func, "line": m.line,
                                            "removed": m.removed, "group": m.group,
                                            "digest": m.digest} for m in members]}, f, indent=2)
            return code, out, records, evidence_file

        def fresh():
            directory = tempfile.mkdtemp(prefix="case-", dir=tmp)
            copy = os.path.join(directory, "project")
            try:
                shutil.copytree(template, copy)
            except OSError as exc:
                raise CrossError(f"cross: copy tree: {exc}") from None
            return directory, copy

        def baseline(selected=None, coverage=None, label="baseline"):
            directory, copy = fresh()
            try:
                return suite(copy, selected, coverage, label=label)
            finally:
                _remove_tree(directory)

        log(f"baseline: pytest {' '.join(args)}")
        code, out, records, _ = baseline()
        if not _clean(code, records):
            hint = ""
            if "--randomly" in out and "unrecognized arguments" in out:
                hint = ("cross turns pytest-randomly off, so a --randomly option in addopts is unknown; "
                        "pass -- -o addopts= with the options you still want\n")
            raise CrossError("cross: baseline suite is not green, cannot judge mutants: "
                             + _baseline_reason(code, records, timeout) + "\n" + hint + _tail(out, 40))
        selected_tests = {}
        if select:
            if any(r.get("kind") == "worker_finished" for r in records):
                raise CrossError("cross: select: per-test coverage needs one process; drop pytest-xdist's -n")
            collected = [r for r in records if r.get("kind") == "collected"]
            if len(collected) != 1 or not isinstance(collected[0].get("tests"), list):
                raise CrossError("cross: select: missing test collection report")
            nodes = collected[0]["tests"]
            hits = {i: [] for i in range(len(mutants))}
            for test in nodes:
                log(f"select: {test}")
                code, out, covered, _ = baseline([test], sorted(rep.snapshot), "coverage")
                if not _clean(code, covered):
                    raise CrossError(f"cross: select: {test} fails when run alone; fix the test or drop -select:\n" + _tail(out, 20))
                coverage = [r for r in covered if r.get("kind") == "coverage" and r.get("test") == test]
                # Missing coverage selects the full suite, never an empty subset.
                if len(coverage) != 1:
                    for i in hits:
                        hits[i] = []
                    selected_tests = {}
                    break
                lines = coverage[0].get("lines", {})
                for i, m in enumerate(mutants):
                    if m.line in lines.get(m.file, []):
                        hits[i].append(test)
            else:
                selected_tests = {i: sorted(tests) for i, tests in hits.items() if tests}
            for subset in sorted({tuple(tests) for tests in selected_tests.values()}):
                code, out, records, _ = baseline(list(subset), label="subset-baseline")
                if not _clean(code, records):
                    raise CrossError("cross: select: selected subset fails without the mutant:\n" + _tail(out, 20))

        def case(members, selected=None):
            if any(m.no_stand_in for m in members):
                return Result(members[0], INVALID, output=_NO_STAND_IN, with_mutants=list(members[1:]))
            directory, copy = fresh()
            try:
                if _before_mutate is not None:
                    _before_mutate(copy)
                by_file = {}
                for m in members:
                    by_file.setdefault(m.file, []).append(m)
                for file, changes in by_file.items():
                    path = os.path.join(copy, file)
                    data = _read_source(path, file)
                    if any(hashlib.sha256(data).hexdigest() != m.digest for m in changes):
                        raise CrossError(f"cross: {file}: snapshot drift: copy no longer matches discovery bytes")
                    # Descending offsets preserve all remaining mutation positions.
                    ordered = sorted(changes, key=lambda m: m.span, reverse=True)
                    if any(low.span[1] > high.span[0] for high, low in zip(ordered, ordered[1:])):
                        raise CrossError(f"cross: {file}: overlapping mutations in group")
                    for m in ordered:
                        data = apply(data, m)
                    with open(path, "wb") as f:
                        f.write(data)
                with lock:
                    log("mutant: " + ", ".join(m.name() for m in members))
                code, out, records, evidence_file = suite(copy, selected=selected, members=members, label="mutant")
                outcome, failing, evidence, first = classify(code, records, out)
                if require_witness and outcome == KILLED and evidence != "witness":
                    outcome = KILLED_BY_SELF_REPORT
                if outcome in {KILLED, KILLED_BY_SELF_REPORT}:
                    # The mutant run's own tests, whole, since a failure can
                    # need the tests beside it. Green with the mutant: the red
                    # was not the mutant's. Red without it: red for another
                    # reason, or it may have been.
                    for _ in range(_REPEATS):
                        code, out, records, _ = suite(copy, selected=selected, members=members, label="repeat")
                        if _clean(code, records):
                            outcome = UNCONFIRMED
                            out = "the suite passed when run again with the mutant\n" + out
                            break
                    else:
                        for _ in range(_RERUNS):
                            code, out, records, _ = baseline(selected, label="confirm")
                            if not _clean(code, records):
                                outcome = UNCONFIRMED
                                break
                return Result(members[0], outcome, failing, evidence, first,
                              "" if outcome == KILLED else _tail(out, 20),
                              with_mutants=list(members[1:]), selected=list(selected or []),
                              evidence_file=evidence_file)
            finally:
                _remove_tree(directory)

        def single(item):
            i, m = item
            tests = selected_tests.get(i)
            result = case([m], tests)
            # An unconfirmed is a red run that did not hold, and no later run
            # takes that back: a retry would give a flake a second way
            # to a kill.
            if tests and result.outcome not in {KILLED, UNCONFIRMED}:
                result = case([m])
            return result

        pool = ThreadPoolExecutor(max_workers=min(jobs, len(mutants)))
        futures = []
        try:
            for item in enumerate(mutants):
                futures.append(pool.submit(single, item))
            rep.results = [future.result() for future in futures]
        except BaseException:
            cancel.set()
            for future in futures:
                future.cancel()
            raise
        finally:
            pool.shutdown(wait=True)
        singles = list(rep.results)
        for group, members in sorted(groups.items()):
            group_result = case(members)
            group_result.group = group
            rep.results.append(group_result)
            survivors = [(i, m) for i, m in enumerate(mutants)
                         if m.group == group and singles[i].outcome == SURVIVED]
            if len(survivors) < 2:
                continue
            if len(survivors) < len(members):
                group_result = case([m for _, m in survivors])
                group_result.group = group
                rep.results.append(group_result)
            if group_result.outcome != KILLED:
                continue
            pairs = {}
            for i, m in survivors:
                masked_by = []
                for j, other in survivors:
                    if i == j:
                        continue
                    key = tuple(sorted((i, j)))
                    if key not in pairs:
                        pair = case([m, other])
                        pairs[key] = pair.outcome
                        if pair.outcome not in {KILLED, SURVIVED}:
                            pair.group = group
                            rep.results.append(pair)
                    if pairs[key] == KILLED:
                        masked_by.append(other.name())
                singles[i].outcome = MASKED
                singles[i].masked_by = masked_by
        _accept_masked(rep, os.path.join(template, "cross-masked.txt"))
        return rep


def _remove_tree(path: str) -> None:
    """Remove a case's directory. A test can leave a read-only directory there,
    as a Go module cache is, which rmtree cannot empty. No verdict hangs on this."""
    for parent, dirs, _ in os.walk(path):
        for name in dirs:
            child = os.path.join(parent, name)
            if not os.path.islink(child):
                try:
                    os.chmod(child, 0o700)
                except OSError:
                    pass
    shutil.rmtree(path, ignore_errors=True)


def _tail(s: str, n: int) -> str:
    return "\n".join(s.rstrip("\n").splitlines()[-n:])


# --- command line -----------------------------------------------------------

_NO_STAND_IN = ("the function ends with this return and gives None on no other path, so None cannot stand in "
                "for it: it may carry the allow decision. Mark the if that reaches it with # subpoena:enforcement_guard "
                "true or false, or move the decision into an if that can carry the marker")

_EXPLAIN = {
    KILLED_BY_SELF_REPORT: "require-witness: first failure was not independent witness evidence",
    MASKED: "layer is masked by other surviving layers; requires a reviewed cross-masked.txt entry",
    SURVIVED: "suite stayed green with enforcement removed: the tests cannot tell enforced from unenforced",
    UNCONFIRMED: "suite went red, but it did not hold (green again with the mutant, or red without it): leftover state outside "
                 "the copy, or a flake. The red run proves nothing; fix the test:",
    CRASHED: "suite went red only by a crash (an exception other than an assertion, or the process died); "
             "a crash is not a kill:",
    INVALID: "mutant has no stand-in, did not import, or the suite never imported it from the copy (an installed copy of "
             "the package shadows it); it proves nothing:",
    TIMED_OUT: "suite did not finish within the timeout (or pytest-timeout stopped a test); a hang is not a "
               "kill. Make the test fail fast instead:",
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="subpoena-cross",
                                 description="Remove each marked enforcement statement and require pytest to fail.")
    ap.add_argument("--require-witness", action="store_true",
                    help="accept a kill only when its first failure is independent witness evidence")
    ap.add_argument("--test-helper", action="append", default=[], metavar="FILE",
                    help="a file relative to the target that holds test code but no tests, "
                         "so an assertion there counts as a test's; repeatable")
    ap.add_argument("target", help="project directory; pytest runs there")
    ap.add_argument("-j", "--jobs", type=int, default=1, help="isolated parallel single-mutant workers")
    ap.add_argument("-select", "--select", action="store_true", help="select tests by per-test line coverage")
    ap.add_argument("-evidence-dir", "--evidence-dir", help="keep full pytest output and plugin records")
    ap.add_argument("--timeout", type=float, default=300.0, help="seconds per suite run (default 300)")
    ap.add_argument("pytest_args", nargs="*", help="arguments for pytest, after --")
    a = ap.parse_args(argv)
    try:
        rep = run(a.target, a.pytest_args, a.timeout, log=lambda s: print(s, file=sys.stderr),
                  jobs=a.jobs, select=a.select, evidence_dir=a.evidence_dir,
                  require_witness=a.require_witness, test_helpers=a.test_helper)
    except (CrossError, OSError) as e:
        # Exit 1 means a mutant was not killed; a setup fault must never read as that.
        print(f"subpoena-cross: {e}", file=sys.stderr)
        return 2
    print(f"{rep.enforcement_points} enforcement point(s), {rep.markers} marker(s), {len(rep.results)} mutant(s)")
    for at in rep.unplaced:
        print(f"marker made no mutant: {at}")
    for r in rep.results:
        m = r.mutant
        print(f"{r.outcome} {m.func}" + (f" group={r.group}" if r.group else ""))
        if r.evidence_file:
            print(f"  evidence file: {r.evidence_file}")
        if r.with_mutants:
            print("  with: " + ", ".join(x.name() for x in r.with_mutants))
        if r.masked_by:
            print("  masked by: " + ", ".join(r.masked_by))
        if r.accepted:
            print("  accepted: " + r.accepted)
        if m.bypass:
            print(f"  at {_where(m)}, forced to {m.bypass}: {' '.join(m.removed.split())}")
        else:
            print(f"  at {_where(m)}, removed: {' '.join(m.removed.split())}")
        if r.outcome in {KILLED, KILLED_BY_SELF_REPORT}:
            print(f"  suite went red; failing: {', '.join(r.failing)}")
            print(f"  first evidence ({r.evidence}): {r.first_failure}")
            if r.outcome == KILLED_BY_SELF_REPORT:
                print("  " + _EXPLAIN[r.outcome])
        else:
            print("  " + _EXPLAIN[r.outcome])
            if r.output and r.outcome != SURVIVED:
                print("  " + r.output.replace("\n", "\n  "))
    for entry in rep.stale_accepted:
        print(f"stale masked acceptance: {entry}")
    return 1 if rep.failed() else 0


if __name__ == "__main__":
    sys.exit(main())
