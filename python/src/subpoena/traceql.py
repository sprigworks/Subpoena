"""The TraceQL subset (docs/traceql-subset.md), evaluated in-process.

A port of pkg/traceql. Checked against the same corpus as the Go evaluator
with subpoena-conform (docs/ports.md, Q):

    go run ./cmd/subpoena-conform -- python/.venv/bin/python -m subpoena.traceql
"""

from __future__ import annotations

import ast as _ast
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union


@dataclass(frozen=True)
class Unsupported:
    """An attribute value outside the subset: an array or a map. A query that
    reads an attribute holding one is refused (UnsupportedValueError)."""

    kind: str


@dataclass
class Span:
    id: str
    name: str
    parent_id: str = ""
    attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Trace:
    id: str
    spans: List[Span] = field(default_factory=list)


@dataclass
class Match:
    trace_id: str
    spans: List[Span]


class ParseError(ValueError):
    """A syntax error, or syntax outside the subset."""

    def __init__(self, query: str, pos: int, msg: str):
        super().__init__(f"traceql: {msg} at offset {pos} in {query!r}")
        self.query, self.pos, self.msg = query, pos, msg


class UnsupportedValueError(ValueError):
    """The query reads an attribute that holds an Unsupported value."""

    def __init__(self, trace_id: str, span_id: str, attr: str, kind: str):
        super().__init__(
            f"traceql: span.{attr} holds a {kind} value (trace {trace_id}, span {span_id}); "
            "array and map values are outside the subset"
        )
        self.trace_id, self.span_id, self.attr, self.kind = trace_id, span_id, attr, kind


# ---- lexer ----

EOF, LBRACE, RBRACE, LPAREN, RPAREN, AND, OR, EQ, NEQ, DESC, CHILD, IDENT, STRING, INT = range(14)


@dataclass
class _Tok:
    kind: int
    text: Any
    pos: int


def _is_letter(c: str) -> bool:
    return c.isalpha()


def _lex(src: str) -> List[_Tok]:
    toks: List[_Tok] = []
    n = len(src)
    i = 0

    def bad(at: int, msg: str) -> ParseError:
        return ParseError(src, at, msg)

    def nxt(k: int) -> str:
        return src[k] if k < n else ""

    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
        elif c in "{}()":
            toks.append(_Tok({"{": LBRACE, "}": RBRACE, "(": LPAREN, ")": RPAREN}[c], c, i))
            i += 1
        elif c == "&" and nxt(i + 1) == "&":
            toks.append(_Tok(AND, "&&", i))
            i += 2
        elif c == "|" and nxt(i + 1) == "|":
            toks.append(_Tok(OR, "||", i))
            i += 2
        elif c == "|":
            raise bad(i, "pipeline operator '|' is not in the supported subset")
        elif c == "!" and nxt(i + 1) == "=":
            toks.append(_Tok(NEQ, "!=", i))
            i += 2
        elif c == "=" and nxt(i + 1) in ("~", "="):
            raise bad(i, "regex and '==' operators are not in the supported subset")
        elif c == "=":
            toks.append(_Tok(EQ, "=", i))
            i += 1
        elif c == ">" and nxt(i + 1) == ">":
            toks.append(_Tok(DESC, ">>", i))
            i += 2
        elif c == ">" and nxt(i + 1) in ("=", "~"):
            raise bad(i, "comparison and sibling operators are not in the supported subset")
        elif c == ">":
            toks.append(_Tok(CHILD, ">", i))
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                if src[j] == "\\":
                    j += 1
                j += 1
            if j >= n:
                raise bad(i, "unterminated string literal")
            toks.append(_Tok(STRING, _unquote(src[i : j + 1], src, i), i))
            i = j + 1
        elif c.isdigit() or (c == "-" and nxt(i + 1).isdigit()):
            j = i + 1
            while j < n and src[j].isdigit():
                j += 1
            if j < n and (src[j] in ".e" or _is_letter(src[j])):
                raise bad(i, "only integer literals are in the supported subset")
            toks.append(_Tok(INT, src[i:j], i))
            i = j
        elif _is_letter(c) or c in "_.":
            j = i
            while j < n and (_is_letter(src[j]) or src[j].isdigit() or src[j] in "_."):
                j += 1
            toks.append(_Tok(IDENT, src[i:j], i))
            i = j
        else:
            raise bad(i, f"unexpected character {c!r}")
    toks.append(_Tok(EOF, "<end>", n))
    return toks


# Go-style double-quoted escapes, the ones strconv.Unquote accepts.
_SIMPLE = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"'}


def _unquote(lit: str, src: str, at: int) -> str:
    body, out, k = lit[1:-1], [], 0
    try:
        while k < len(body):
            ch = body[k]
            if ch == "\n":
                raise ValueError
            if ch != "\\":
                out.append(ch)
                k += 1
                continue
            e = body[k + 1]
            if e in _SIMPLE:
                out.append(_SIMPLE[e])
                k += 2
            elif e in "01234567":
                out.append(chr(int(body[k + 1 : k + 4], 8)))
                if len(body[k + 1 : k + 4]) != 3:
                    raise ValueError
                k += 4
            elif e in "xuU":
                width = {"x": 2, "u": 4, "U": 8}[e]
                digits = body[k + 2 : k + 2 + width]
                if len(digits) != width:
                    raise ValueError
                out.append(chr(int(digits, 16)))
                k += 2 + width
            else:
                raise ValueError
    except (ValueError, IndexError):
        raise ParseError(src, at, "invalid string literal") from None
    return "".join(out)


# ---- AST ----

@dataclass
class _Cmp:
    is_name: bool
    attr: str
    neg: bool
    val: Union[str, bool, int]


@dataclass
class _And:
    l: Any
    r: Any


@dataclass
class _Or:
    l: Any
    r: Any


@dataclass
class _Lit:
    v: bool


def _equal(got: Any, want: Any):
    """(eq, comparable), as in pkg/traceql: types are compared strictly."""
    if isinstance(want, bool):
        return (isinstance(got, bool) and got == want), isinstance(got, bool)
    if isinstance(want, str):
        return (isinstance(got, str) and got == want), isinstance(got, str)
    if isinstance(want, int):
        if isinstance(got, bool) or not isinstance(got, (int, float)):
            return False, False
        return got == want, True
    return False, False


def _eval(e: Any, s: Span) -> bool:
    if isinstance(e, _And):
        return _eval(e.l, s) and _eval(e.r, s)
    if isinstance(e, _Or):
        return _eval(e.l, s) or _eval(e.r, s)
    if isinstance(e, _Lit):
        return e.v
    if e.is_name:
        got = s.name
    else:
        if e.attr not in s.attrs:
            return False  # a missing attribute is false, for = and != alike
        got = s.attrs[e.attr]
    eq, comparable = _equal(got, e.val)
    if not comparable:
        return False  # a type mismatch never matches
    return (not eq) if e.neg else eq


class Query:
    """A parsed query. Use parse()."""

    def __init__(self, src: str, first: Optional[Any], rest: List[tuple]):
        self.src, self._first, self._rest = src, first, rest

    def __str__(self) -> str:
        return self.src

    def attributes(self) -> List[str]:
        """The span attribute keys the query reads, sorted, without duplicates."""
        seen = set()

        def walk(e: Any) -> None:
            if isinstance(e, (_And, _Or)):
                walk(e.l)
                walk(e.r)
            elif isinstance(e, _Cmp) and not e.is_name:
                seen.add(e.attr)

        for ss in [self._first] + [r for _, r in self._rest]:
            if ss is not None:
                walk(ss)
        return sorted(seen)

    def _refuse(self, tr: Trace) -> None:
        attrs = self.attributes()
        for s in tr.spans:
            for a in attrs:
                v = s.attrs.get(a)
                if isinstance(v, Unsupported):
                    raise UnsupportedValueError(tr.id, s.id, a, v.kind)

    def eval(self, traces: Sequence[Trace]) -> List[Match]:
        """The traces with a non-empty final spanset, in input order. Raises
        UnsupportedValueError if any span holds an array or map value under an
        attribute the query reads, whether or not evaluation would reach it."""
        for tr in traces:
            self._refuse(tr)
        out = []
        for tr in traces:
            sel = self._eval_trace(tr)
            if sel:
                out.append(Match(tr.id, [tr.spans[i] for i in sel]))
        return out

    def matches_trace(self, tr: Trace) -> bool:
        self._refuse(tr)
        return bool(self._eval_trace(tr))

    def _select(self, ss: Optional[Any], spans: List[Span]) -> List[int]:
        return [i for i, s in enumerate(spans) if ss is None or _eval(ss, s)]

    def _eval_trace(self, tr: Trace) -> List[int]:
        cur = self._select(self._first, tr.spans)
        if not self._rest:
            return cur
        by_id = {s.id: i for i, s in enumerate(tr.spans) if s.id}
        for op, rhs in self._rest:
            lhs = set(cur)
            cur = [j for j in self._select(rhs, tr.spans) if _related(op, j, tr.spans, by_id, lhs)]
            if not cur:
                return []
        return cur


def _related(op: int, j: int, spans: List[Span], by_id: Dict[str, int], lhs: set) -> bool:
    """Whether span j is a child (CHILD) or descendant (DESC) of a span in lhs."""
    seen, cur = {j}, j
    while True:
        pid = spans[cur].parent_id
        if not pid:
            return False
        p = by_id.get(pid)
        if p is None or p in seen:
            return False  # orphan or cycle
        seen.add(p)
        if p in lhs:
            return True
        if op == CHILD:
            return False
        cur = p


# ---- parser ----

class _Parser:
    def __init__(self, src: str):
        self.src, self.toks, self.i = src, _lex(src), 0

    def peek(self) -> _Tok:
        return self.toks[self.i]

    def next(self) -> _Tok:
        t = self.toks[self.i]
        if t.kind != EOF:
            self.i += 1
        return t

    def err(self, t: _Tok, msg: str) -> ParseError:
        return ParseError(self.src, t.pos, msg)

    def spanset(self) -> Optional[Any]:
        t = self.next()
        if t.kind != LBRACE:
            raise self.err(t, f"expected '{{', got {t.text!r}")
        if self.peek().kind == RBRACE:
            self.next()
            return None
        e = self.or_()
        t = self.next()
        if t.kind != RBRACE:
            raise self.err(t, f"expected '}}', got {t.text!r}")
        return e

    def or_(self) -> Any:
        l, and_at = self.and_()
        while self.peek().kind == OR:
            or_tok = self.next()
            r, r_and_at = self.and_()
            if and_at is None:
                and_at = r_and_at
            if and_at is not None:
                at = and_at if and_at.pos > or_tok.pos else or_tok
                raise self.err(at, "'&&' and '||' mixed without parentheses (Tempo groups them left to right with equal precedence); add parentheses")
            l = _Or(l, r)
        return l

    def and_(self):
        l = self.primary()
        first = None
        while self.peek().kind == AND:
            t = self.next()
            if first is None:
                first = t
            l = _And(l, self.primary())
        return l, first

    def primary(self) -> Any:
        t = self.next()
        if t.kind == LPAREN:
            e = self.or_()
            c = self.next()
            if c.kind != RPAREN:
                raise self.err(c, f"expected ')', got {c.text!r}")
            return e
        if t.kind == IDENT:
            if t.text == "true":
                return _Lit(True)
            if t.text == "false":
                return _Lit(False)
            return self.comparison(t)
        raise self.err(t, f"expected a condition, got {t.text!r}")

    def comparison(self, f: _Tok) -> _Cmp:
        if f.text == "name":
            is_name, attr = True, ""
        elif f.text.startswith("span.") and len(f.text) > len("span."):
            is_name, attr = False, f.text[len("span."):]
        else:
            raise self.err(f, f"field {f.text!r} is not in the supported subset (use name or span.<attr>)")
        op = self.next()
        if op.kind not in (EQ, NEQ):
            raise self.err(op, f"operator {op.text!r} is not in the supported subset (use = or !=)")
        v = self.next()
        if v.kind == STRING:
            val: Union[str, bool, int] = v.text
        elif v.kind == INT:
            val = int(v.text)
            if not -(2**63) <= val < 2**63:
                raise self.err(v, "integer out of range")
        elif v.kind == IDENT and v.text in ("true", "false"):
            val = v.text == "true"
        elif v.kind == IDENT:
            raise self.err(v, f"value {v.text!r} is not a string, integer or bool literal")
        else:
            raise self.err(v, f"expected a literal, got {v.text!r}")
        if is_name and not isinstance(val, str):
            raise self.err(v, "name must be compared with a string")
        return _Cmp(is_name, attr, op.kind == NEQ, val)


def parse(src: str) -> Query:
    """Parse a query in the subset; raises ParseError otherwise."""
    p = _Parser(src)
    first = p.spanset()
    rest = []
    while p.peek().kind in (DESC, CHILD):
        op = p.next().kind
        rest.append((op, p.spanset()))
    t = p.peek()
    if t.kind != EOF:
        raise p.err(t, f"unexpected {t.text!r} (not in the supported subset)")
    return Query(src, first, rest)


# ---- OTLP/JSON, for the subpoena-traceql protocol ----

def _scalar(v: Dict[str, Any]) -> Any:
    found = []
    if "stringValue" in v:
        found.append(v["stringValue"])
    if "boolValue" in v:
        found.append(bool(v["boolValue"]))
    if "intValue" in v:
        found.append(int(v["intValue"]))
    if "doubleValue" in v:
        found.append(float(v["doubleValue"]))
    if v.get("arrayValue") is not None:
        found.append(Unsupported("array"))
    if v.get("kvlistValue") is not None:
        found.append(Unsupported("kvlist"))
    if len(found) != 1:
        raise ValueError(f"expected exactly one value, found {len(found)}")
    return found[0]


def _norm_id(i: str) -> str:
    i = i.lower()
    return i.rjust(32, "0") if len(i) < 32 else i


def traces_from_otlp(doc: Dict[str, Any]) -> List[Trace]:
    """An OTLP/JSON ExportTraceServiceRequest as traces, in first-seen order."""
    out: List[Trace] = []
    idx: Dict[str, int] = {}
    for rs in doc.get("resourceSpans") or []:
        for ss in rs.get("scopeSpans") or []:
            for sp in ss.get("spans") or []:
                tid = _norm_id(sp["traceId"])
                if tid not in idx:
                    idx[tid] = len(out)
                    out.append(Trace(tid))
                attrs = {kv["key"]: _scalar(kv["value"]) for kv in sp.get("attributes") or []}
                out[idx[tid]].spans.append(
                    Span(sp["spanId"].lower(), sp["name"], (sp.get("parentSpanId") or "").lower(), attrs)
                )
    return out


def main(argv: Sequence[str]) -> int:
    """QUERY_FILE TRACES_FILE -> matching trace IDs, sorted (docs/ports.md, Q).
    Exit 2: outside the subset; 3: reads an array or map value; 1: other errors."""
    if len(argv) != 2:
        print("usage: python -m subpoena.traceql QUERY_FILE TRACES_FILE", file=sys.stderr)
        return 1
    try:
        with open(argv[0], encoding="utf-8") as f:
            src = f.read().strip()
        with open(argv[1], encoding="utf-8") as f:
            traces = traces_from_otlp(json.load(f))
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"subpoena.traceql: {e}", file=sys.stderr)
        return 1
    try:
        q = parse(src)
    except ParseError as e:
        print(f"subpoena.traceql: {e}", file=sys.stderr)
        return 2
    try:
        ms = q.eval(traces)
    except UnsupportedValueError as e:
        print(f"subpoena.traceql: {e}", file=sys.stderr)
        return 3
    for tid in sorted(m.trace_id for m in ms):
        print(tid)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
