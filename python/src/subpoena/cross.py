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

- killed: a test failed on an assertion (AssertionError or pytest.fail),
  including a teardown check such as watch_spawns.
- survived: the suite stayed green. The run fails.
- crashed: the suite went red only by another exception, or the test process
  died. A crash is not evidence that the enforcement is tested; the run fails.
- invalid: the mutant does not import, or the suite never imported the
  mutated module from the copy (an installed copy of the package shadowed
  it). It proves nothing; the run fails.
- timeout: the suite ran past the timeout. The run fails.

A marker that takes no effect is an error, never skipped: a statement or
guard marker outside an enforcement point, on the wrong kind of line, with
trailing text, or misspelt; and an enforcement point with no statement or
guard marker.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import tokenize
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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
    start: Tuple[int, int] = (0, 0)  # (line, col) of the replaced text, 1-based line
    end: Tuple[int, int] = (0, 0)

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

def _comments(src: str) -> Dict[int, str]:
    """Line number -> the comment text on it, without the leading #."""
    out = {}
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            out[tok.start[0]] = tok.string[1:].strip()
    return out


def find_mutants(root: str) -> Tuple[int, List[Mutant]]:
    """Every marked mutant under root, and the number of enforcement points.
    Raises CrossError for any marker that would take no effect."""
    points, mutants = 0, []
    for path in sorted(_python_files(root)):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if "subpoena" not in src:
            continue
        try:
            tree = ast.parse(src, filename=rel)
        except SyntaxError as e:
            raise CrossError(f"cross: {rel}: {e}") from None
        comments = _comments(src)
        placed = set()
        missing = []  # points with nothing to mutate; reported after stray markers, which explain them
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            first = min([node.lineno] + [d.lineno for d in node.decorator_list])
            if comments.get(first - 1) != _POINT:
                continue
            placed.add(first - 1)
            points += 1
            found = 0
            for st in _statements(node):
                c = comments.get(st.lineno)
                if c is None or not _ANY_MARKER.match("#" + c) or st.lineno in placed:
                    continue
                if c == _STATEMENT:
                    if not isinstance(st, _SIMPLE):
                        continue  # an if or a loop starting here: not this marker's line
                    seg = ast.get_source_segment(src, st)
                    m = Mutant(rel, node.name, st.lineno, seg, "",
                               (st.lineno, st.col_offset), (st.end_lineno, st.end_col_offset))
                elif _GUARD.match(c):
                    if not isinstance(st, ast.If):
                        continue
                    t = st.test
                    m = Mutant(rel, node.name, st.lineno, ast.get_source_segment(src, t),
                               "True" if _GUARD.match(c).group(1) == "true" else "False",
                               (t.lineno, t.col_offset), (t.end_lineno, t.end_col_offset))
                else:
                    continue
                placed.add(st.lineno)
                mutants.append(m)
                found += 1
            if found == 0:
                missing.append(f"cross: {rel}: {node.name} is marked {_POINT} but has no "
                               f"{_STATEMENT} statement, so it cannot be cross-examined")
        for line, c in sorted(comments.items()):
            if _ANY_MARKER.match("#" + c) and line not in placed:
                raise CrossError(
                    f"cross: {rel}:{line}: {'#' + c!r} is not a marker cross applies: statement and guard "
                    f"markers go on a simple statement or an if inside a function marked {_POINT}, the "
                    f"point marker directly above the def, and markers take no other text")
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


def apply(src: str, m: Mutant) -> str:
    """src with m's text replaced, line numbers kept."""
    lines = src.splitlines(keepends=True)
    (l1, c1), (l2, c2) = m.start, m.end
    head = lines[l1 - 1][:c1]
    tail = lines[l2 - 1][c2:]
    repl = m.bypass or "pass"
    # Keep every later line where it was, so tracebacks and markers line up.
    return "".join(lines[:l1 - 1]) + head + repl + "\n" * (l2 - l1) + tail + "".join(lines[l2:])


# --- running ----------------------------------------------------------------

_PLUGIN = "subpoena._cross_plugin"


def _run_suite(copy: str, args: List[str], timeout: float, mutated: str, report: str) -> Tuple[Optional[int], str]:
    env = dict(os.environ)
    env["SUBPOENA_CROSS_REPORT"] = report
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
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return None, out


def _read_report(path: str) -> List[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return []


def classify(code: Optional[int], records: List[dict], out: str) -> Tuple[str, List[str], str, str]:
    """(outcome, failing tests, evidence, first failure) for one mutant run."""
    if code is None:
        return TIMED_OUT, [], "", ""
    finished = [r for r in records if r.get("kind") == "finished"]
    if any(r.get("kind") == "collect_error" for r in records) or code in (2, 4, 5) and not finished:
        return INVALID, [], "", ""
    if finished and not finished[-1].get("mutated_loaded", True):
        return INVALID, [], "", ""
    if code == 0 and finished:
        return SURVIVED, [], "", ""
    if code != 1 or not finished:
        return CRASHED, [], "", ""  # the process died, or pytest stopped abnormally
    fails = [r for r in records if r.get("kind") == "failure"]
    assertion = [r for r in fails if r.get("assertion")]
    crashed = [r for r in fails if not r.get("assertion")]
    if crashed or not assertion:
        return CRASHED, [r["test"] for r in fails], "", ""
    msg = assertion[0].get("message", "")
    first = msg.strip().splitlines()[0] if msg.strip() else ""
    for prefix, ev in (("witness:", "witness"), ("testimony:", "testimony")):
        if prefix in msg:
            line = next((l for l in msg.splitlines() if prefix in l), first)
            return KILLED, [r["test"] for r in fails], ev, line.strip()
    return KILLED, [r["test"] for r in fails], "other", first


def run(target: str, pytest_args: Optional[List[str]] = None, timeout: float = 300.0, log=None) -> Report:
    """Cross-examine the project at target. Raises CrossError on setup errors."""
    log = log or (lambda s: None)
    target = os.path.abspath(target)
    points, mutants = find_mutants(target)
    if not mutants:
        raise CrossError(f"cross: no {_POINT} with a {_STATEMENT} statement under {target}")
    rep = Report(enforcement_points=points)
    args = list(pytest_args or [])
    with tempfile.TemporaryDirectory(prefix="subpoena-cross-") as tmp:
        copy = os.path.join(tmp, os.path.basename(target))
        shutil.copytree(target, copy, ignore=shutil.ignore_patterns(*_SKIP_DIRS, "*.egg-info"))
        report = os.path.join(tmp, "report.jsonl")
        log(f"baseline: pytest {' '.join(args)}")
        code, out = _run_suite(copy, args, timeout, "", report)
        if code != 0:
            raise CrossError("cross: baseline suite is not green, cannot judge mutants:\n" + _tail(out, 40))
        for m in mutants:
            path = os.path.join(copy, m.file)
            with open(path, encoding="utf-8") as f:
                src = f.read()
            log(f"mutant: {m.name()} " + (f"forced {m.removed!r} to {m.bypass}" if m.bypass
                                          else f"removed {m.removed!r}"))
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(apply(src, m))
                if os.path.exists(report):
                    os.remove(report)
                code, out = _run_suite(copy, args, timeout, m.file, report)
            finally:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(src)
            outcome, failing, ev, first = classify(code, _read_report(report), out)
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
    TIMED_OUT: "suite did not finish within the timeout; a hang is not a kill. Make the test fail fast instead:",
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
    except CrossError as e:
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
