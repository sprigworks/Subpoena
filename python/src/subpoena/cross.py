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
condition with True or False. Verdicts:

- killed: a test failed on an assertion raised from test code: an
  AssertionError, pytest.fail or a failed pytest.raises whose innermost frame
  (past pytest's and subpoena's own helpers) is in a test module (pytest's
  python_files, conftest.py, or the failing test's own file), or a subpoena
  teardown check such as watch_spawns. An assert in the code under test is a
  crash, as a panic is in Go.
- survived: the suite stayed green. The run fails.
- crashed: the suite went red only by another exception, or the test process
  died. A crash is not evidence that the enforcement is tested; the run fails.
- invalid: the mutant does not import (a SyntaxError, or any collection
  error), or the suite never imported the mutated module from the copy (an
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
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import tokenize
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

KILLED = "enforcement-mutant-killed"
SURVIVED = "enforcement-mutant-survived"
CRASHED = "enforcement-mutant-crashed"
INVALID = "enforcement-mutant-invalid"
TIMED_OUT = "enforcement-mutant-timeout"

_ANY_MARKER = re.compile(r"#\s*subpoena\s*:\s*enforc")  # cross's markers, misspelt ones too
_POINT = "subpoena:enforcement_point"
_STATEMENT = "subpoena:enforcement"
_GUARD = re.compile(r"^subpoena:enforcement_guard (true|false)$")
_SIMPLE = (ast.Return, ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Raise, ast.Pass,
           ast.Break, ast.Continue, ast.Delete, ast.Assert)
_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".tox", ".pytest_cache", "node_modules", ".mypy_cache"}


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


@dataclass
class Report:
    enforcement_points: int = 0
    results: List[Result] = field(default_factory=list)

    def failed(self) -> bool:
        return not self.results or any(r.outcome != KILLED for r in self.results)


# --- discovery -------------------------------------------------------------

def _comments(text: str) -> Dict[int, Tuple[str, bool]]:
    """Line number -> (the comment text on it without the leading #, whether
    the comment is the whole line). Lines are counted as ast counts them:
    universal newlines, and nothing else (not U+2028 or form feed)."""
    out = {}
    for tok in tokenize.generate_tokens(io.StringIO(text, newline=None).readline):
        if tok.type == tokenize.COMMENT:
            out[tok.start[0]] = (tok.string[1:].strip(), not tok.line[:tok.start[1]].strip())
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
                          node.end_lineno - node.lineno, digest)

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
                if c == _STATEMENT:
                    if not isinstance(st, _SIMPLE):
                        continue  # an if or a loop starting here: not this marker's line
                    m = mutant(node.name, st.lineno, st, "")
                elif _GUARD.match(c):
                    if not isinstance(st, ast.If):
                        continue
                    m = mutant(node.name, st.lineno, st.test,
                               "True" if _GUARD.match(c).group(1) == "true" else "False")
                else:
                    continue
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
        dirs[:] = [x for x in dirs if x not in _SKIP_DIRS and not x.endswith(".egg-info")]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(d, f)


def apply(data: bytes, m: Mutant) -> bytes:
    """The file bytes with m's span replaced, line numbers kept. data must be
    the discovery snapshot (run checks m.digest first)."""
    a, b = m.span
    repl = (m.bypass or "pass").encode()
    # Keep every later line where it was, so tracebacks and markers line up.
    return data[:a] + repl + b"\n" * m.breaks + data[b:]


# --- running ----------------------------------------------------------------

_PLUGIN = "subpoena._cross_plugin"


def _run_suite(copy: str, args: List[str], timeout: float, mutated: str, report: str,
               nonce: str = "") -> Tuple[Optional[int], str]:
    # The report is created fresh, by cross, before every run: nothing left
    # from an earlier run (or planted) is read as this one's.
    if os.path.lexists(report):
        os.remove(report)
    os.close(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    env = dict(os.environ)
    env["SUBPOENA_CROSS_REPORT"] = report
    env["SUBPOENA_CROSS_NONCE"] = nonce
    env["SUBPOENA_CROSS_MUTATED"] = os.path.join(copy, mutated) if mutated else ""
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = copy + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cmd = [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "-p", _PLUGIN] + args
    p = subprocess.Popen(cmd, cwd=copy, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        # The whole session: pytest and anything the tests started.
        _kill_group(p)
        out, _ = p.communicate()
        return None, out
    except BaseException:
        # Ctrl-C (or any other way out): the suite is in its own session, so
        # it did not get the SIGINT; never leave it running.
        _kill_group(p)
        p.wait()
        raise


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
    if any(r.get("kind") == "collect_error" for r in records) or code in (2, 4, 5) and not finished:
        return INVALID, [], "", ""
    if any(r.get("verdict") == "invalid" for r in fails):
        return INVALID, [r["test"] for r in fails], "", ""
    if finished and not finished[-1].get("mutated_loaded", True):
        return INVALID, [], "", ""
    if code == 0 and finished:
        return SURVIVED, [], "", ""
    if code != 1 or not finished:
        return CRASHED, [], "", ""  # the process died, or pytest stopped abnormally
    assertion = [r for r in fails if r.get("verdict") == "assertion"]
    crashed = [r for r in fails if r.get("verdict") != "assertion"]
    if crashed or not assertion:
        return CRASHED, [r["test"] for r in fails], "", ""
    msg = assertion[0].get("message", "")
    first = msg.strip().splitlines()[0] if msg.strip() else ""
    for prefix, ev in (("witness:", "witness"), ("testimony:", "testimony")):
        if prefix in msg:
            line = next((l for l in msg.splitlines() if prefix in l), first)
            return KILLED, [r["test"] for r in fails], ev, line.strip()
    return KILLED, [r["test"] for r in fails], "other", first


def run(target: str, pytest_args: Optional[List[str]] = None, timeout: float = 300.0, log=None,
        _before_mutate: Optional[Callable[[str], None]] = None) -> Report:
    """Cross-examine the project at target. Raises CrossError on setup errors.
    _before_mutate (tests only) is called with the copy's root before each
    mutant is applied."""
    log = log or (lambda s: None)
    target = os.path.abspath(target)
    points, mutants = find_mutants(target)
    if not mutants:
        raise CrossError(f"cross: no {_POINT} with a {_STATEMENT} statement under {target}")
    rep = Report(enforcement_points=points)
    args = list(pytest_args or [])
    with tempfile.TemporaryDirectory(prefix="subpoena-cross-") as tmp:
        copy = os.path.join(tmp, os.path.basename(target))
        try:
            shutil.copytree(target, copy, ignore=shutil.ignore_patterns(*_SKIP_DIRS, "*.egg-info"))
        except OSError as e:  # shutil.Error too: a dangling symlink, an unreadable file
            raise CrossError(f"cross: copy tree: {e}") from None
        report = os.path.join(tmp, "report.jsonl")
        nonce = secrets.token_hex(16)
        log(f"baseline: pytest {' '.join(args)}")
        code, out = _run_suite(copy, args, timeout, "", report, nonce)
        if code != 0:
            raise CrossError("cross: baseline suite is not green, cannot judge mutants:\n" + _tail(out, 40))
        for m in mutants:
            if _before_mutate is not None:
                _before_mutate(copy)
            path = os.path.join(copy, m.file)
            snapshot = _read_source(path, m.file)
            if hashlib.sha256(snapshot).hexdigest() != m.digest:
                raise CrossError(f"cross: {m.file}: snapshot drift: copy no longer matches discovery bytes")
            log(f"mutant: {m.name()} " + (f"forced {m.removed!r} to {m.bypass}" if m.bypass
                                          else f"removed {m.removed!r}"))
            try:
                with open(path, "wb") as f:
                    f.write(apply(snapshot, m))
                code, out = _run_suite(copy, args, timeout, m.file, report, nonce)
            finally:
                with open(path, "wb") as f:
                    f.write(snapshot)
            outcome, failing, ev, first = classify(code, _read_report(report, nonce), out)
            rep.results.append(Result(m, outcome, failing, ev, first,
                                      "" if outcome == KILLED else _tail(out, 20)))
    return rep


def _tail(s: str, n: int) -> str:
    return "\n".join(s.rstrip("\n").splitlines()[-n:])


# --- command line -----------------------------------------------------------

_EXPLAIN = {
    SURVIVED: "suite stayed green with enforcement removed: the tests cannot tell enforced from unenforced",
    CRASHED: "suite went red only by a crash (an exception other than an assertion, or the process died); "
             "a crash is not a kill:",
    INVALID: "mutant did not import, or the suite never imported it from the copy (an installed copy of "
             "the package shadows it); it proves nothing:",
    TIMED_OUT: "suite did not finish within the timeout (or pytest-timeout stopped a test); a hang is not a "
               "kill. Make the test fail fast instead:",
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="subpoena-cross",
                                 description="Remove each marked enforcement statement and require pytest to fail.")
    ap.add_argument("target", help="project directory; pytest runs there")
    ap.add_argument("--timeout", type=float, default=300.0, help="seconds per suite run (default 300)")
    ap.add_argument("pytest_args", nargs="*", help="arguments for pytest, after --")
    a = ap.parse_args(argv)
    try:
        rep = run(a.target, a.pytest_args, a.timeout, log=lambda s: print(s, file=sys.stderr))
    except (CrossError, OSError) as e:
        # Exit 1 means a mutant was not killed; a setup fault must never read as that.
        print(f"subpoena-cross: {e}", file=sys.stderr)
        return 2
    print(f"{rep.enforcement_points} enforcement point(s), {len(rep.results)} mutant(s)")
    for r in rep.results:
        m = r.mutant
        print(f"{r.outcome} {m.func}")
        if m.bypass:
            print(f"  at {m.file}:{m.line}, forced to {m.bypass}: {' '.join(m.removed.split())}")
        else:
            print(f"  at {m.file}:{m.line}, removed: {' '.join(m.removed.split())}")
        if r.outcome == KILLED:
            print(f"  suite went red; failing: {', '.join(r.failing)}")
            print(f"  first evidence ({r.evidence}): {r.first_failure}")
        else:
            print("  " + _EXPLAIN[r.outcome])
            if r.output and r.outcome != SURVIVED:
                print("  " + r.output.replace("\n", "\n  "))
    return 1 if rep.failed() else 0


if __name__ == "__main__":
    sys.exit(main())
