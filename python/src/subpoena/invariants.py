"""Invariants by name: the TraceQL in invariants/<name>.traceql, so a test
asserts the exact string that OATS and the alert rules use. Every match of an
invariant is a violation. A port of the invariants package's Load.

    from subpoena import invariants
    require_absent(tr, invariants.load("no_exec_after_deny"))

With no directory, the nearest invariants/ directory above the calling file
is used, as subpoena-lint finds it for orphan-invariant.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Optional, Union

_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


class InvariantError(LookupError):
    """No such invariant, or no invariants directory."""


def find(start: Union[str, Path]) -> Path:
    """The nearest invariants/ directory at or above start."""
    p = Path(start).resolve()
    if p.is_file():
        p = p.parent
    for d in (p, *p.parents):
        if (d / "invariants").is_dir():
            return d / "invariants"
    raise InvariantError(f"invariants: no invariants/ directory at or above {start}")


def _directory(directory: Optional[Union[str, Path]], depth: int) -> Path:
    if directory is not None:
        d = Path(directory)
        if not d.is_dir():
            raise InvariantError(f"invariants: {d} is not a directory")
        return d
    caller = sys._getframe(depth).f_globals.get("__file__")
    if not caller:
        raise InvariantError("invariants: the caller has no file; pass directory")
    return find(caller)


def load(name: str, directory: Optional[Union[str, Path]] = None) -> str:
    """The query text of <directory>/<name>.traceql, trimmed. Raises
    InvariantError if there is no such file. name is a file stem, never a
    path."""
    if not isinstance(name, str) or not _NAME.match(name) or ".." in name:
        raise InvariantError(f"invariants: {name!r} is not an invariant name")
    p = _directory(directory, 2) / f"{name}.traceql"
    try:
        return p.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        raise InvariantError(f"invariants: no invariant {name!r} ({p})") from None
    except (OSError, UnicodeError) as e:
        raise InvariantError(f"invariants: {p}: {e}") from None


def names(directory: Optional[Union[str, Path]] = None) -> List[str]:
    """Every invariant in the directory, sorted."""
    return sorted(p.stem for p in _directory(directory, 2).glob("*.traceql"))
