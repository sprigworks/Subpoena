"""Python L1 lint. Static AST checks; target modules and registries are never imported.

See lint/README.md for the rules and python/README.md for Python resolution limits.
Exit codes: 0 clean, 1 findings, 2 usage or load error.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass


class LintError(Exception):
    """Source or configuration could not be loaded; never a clean verdict."""


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    column: int
    rule: str
    message: str

    def __str__(self):
        return f'{self.path}:{self.line}:{self.column}: {self.rule}: {self.message}'


_SKIP = {'testdata', 'vendor', 'node_modules', '__pycache__', 'venv'}
_FUNCTION = (ast.FunctionDef, ast.AsyncFunctionDef)
_WITNESS = {'no_spawn', 'require_no_spawn', 'check_no_spawn', 'watch_spawns',
            'no_dial', 'require_no_dial', 'check_no_dial', 'watch_dials', 'check_spawns'}
_QUERIES = {'require_absent': 1, 'require_exists': 1, 'absent': 0, 'exists': 0, 'query': 0}


def _parse(path):
    try:
        # tokenize.open honours Python's source encoding cookie and BOM.
        with tokenize.open(path) as stream:
            text = stream.read()
        return text, ast.parse(text, filename=str(path))
    except (OSError, SyntaxError, UnicodeError, LookupError, RecursionError, ValueError) as exc:
        raise LintError(f'{path}: {exc}') from exc


def _files(root):
    if not root.exists():
        raise LintError(f'target does not exist: {root}')
    if root.is_file():
        if root.suffix != '.py':
            raise LintError(f'expected a Python file: {root}')
        return [root]
    found = []
    def fail(exc):
        raise LintError(str(exc)) from exc
    for directory, dirs, files in os.walk(root, onerror=fail):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.') and d not in _SKIP)
        found.extend(Path(directory) / f for f in sorted(files) if f.endswith('.py'))
    return found


def _find(start, relative):
    directory = start if start.is_dir() else start.parent
    for parent in (directory, *directory.parents):
        candidate = parent / relative
        if candidate.exists():
            return candidate
    return None


def _registry(path):
    if path is None:
        raise LintError('no generated/python/semconv.py found; pass --registry')
    if path.is_dir():
        path = path / 'semconv.py'
    _, tree = _parse(path)
    names, positions = {}, {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        else:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            for target in targets:
                if isinstance(target, ast.Name):
                    names[target.id] = value.value
                    positions[target.id] = (path, target)
    values = {v for k, v in names.items() if k.startswith(('SPAN_', 'ATTR_'))}
    if not values:
        raise LintError(f'{path}: no SPAN_ or ATTR_ string constants found')
    return names, values, positions


def _invariants(path):
    if path is None:
        return set()
    if not path.is_dir():
        raise LintError(f'invariants directory does not exist: {path}')
    try:
        return {p.read_text(encoding='utf-8').strip() for p in sorted(path.glob('*.traceql'))}
    except (OSError, UnicodeError) as exc:
        raise LintError(f'{path}: {exc}') from exc


def _comments(text):
    return {t.start[0]: (t.string, not t.line[:t.start[1]].strip())
            for t in tokenize.generate_tokens(io.StringIO(text).readline)
            if t.type == tokenize.COMMENT}


def _semconv(symbol):
    return 'semconv' in symbol.split('.')


def _harness(symbol):
    return any(part.startswith('subpoena.harness.') for part in symbol.split('|'))


def _telemetry(symbol):
    return symbol.startswith('opentelemetry.') or _semconv(symbol) or any(
        symbol == p or symbol.startswith(p + '.') for p in
        ('subpoena.harness', 'subpoena.witness', 'subpoena.invariants'))


class _File:
    def __init__(self, path, names, values, invariants, star_ok=False):
        self.path, self.names, self.values, self.invariants = path, names, values, invariants
        self.star_ok = star_ok
        self.text, self.tree = _parse(path)
        self.comments = _comments(self.text)
        self.test = path.name.startswith('test_') or path.name.endswith('_test.py') or path.name == 'conftest.py'
        self.findings, self.emitted, self.points = [], set(), []
        self.collected = self.witnessed = self.tests = False
        first = min((min([n.lineno] + [d.lineno for d in getattr(n, 'decorator_list', [])])
                     for n in self.tree.body), default=len(self.text.splitlines()) + 1)
        self.header = '\n'.join(c for line, (c, full) in self.comments.items() if full and line < first)
        self.imports = []
        self.module_imports = self.import_bindings(self.tree.body)
        self.function_depth = 0

    def add(self, rule, node, message):
        self.findings.append(Finding(self.path, node.lineno, node.col_offset + 1, rule, message))

    def import_bindings(self, statements):
        bindings = {}
        for node in statements:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name == '*':
                        if self.star_ok:
                            continue
                        raise LintError(f'{self.path}:{node.lineno}: star imports cannot be resolved by lint')
                    if isinstance(node, ast.Import):
                        name = alias.asname or alias.name.split('.')[0]
                        symbol = alias.name if alias.asname else alias.name.split('.')[0]
                    else:
                        module = node.module or ''
                        if node.level:
                            # Recognise the bundled port's sibling modules; other relative
                            # modules retain their names without guessing a service package.
                            if module in {'harness', 'witness', 'invariants'}:
                                module = 'subpoena.' + module
                            if not module and alias.name in {'harness', 'witness', 'invariants'}:
                                module = 'subpoena'
                        name = alias.asname or alias.name
                        symbol = (module + '.' if module else '') + alias.name
                    bindings[name] = symbol
                    imported = alias.name if isinstance(node, ast.Import) else symbol
                    if imported not in self.imports:
                        self.imports.append(imported)
            elif not isinstance(node, (*_FUNCTION, ast.ClassDef)):
                for field in ('body', 'orelse', 'finalbody'):
                    bindings.update(self.import_bindings(getattr(node, field, [])))
                for handler in getattr(node, 'handlers', []):
                    bindings.update(self.import_bindings(handler.body))
        return bindings

    def resolve(self, node, scope):
        if isinstance(node, ast.Name):
            return scope.get(node.id, '')
        if isinstance(node, ast.Attribute):
            return '|'.join(sorted({base + '.' + node.attr if base else ''
                                    for base in self.resolve(node.value, scope).split('|')}))
        if isinstance(node, ast.Call):
            result = set()
            for symbol in self.resolve(node.func, scope).split('|'):
                if symbol in {'subpoena.harness.Harness.tracer', 'subpoena.harness.Harness.tracer_provider.get_tracer',
                              'opentelemetry.trace.get_tracer', 'opentelemetry.trace.TracerProvider.get_tracer'}:
                    result.add('opentelemetry.trace.Tracer')
                elif symbol == 'subpoena.witness.read_log':
                    result.add('subpoena.witness.Log')
                elif symbol == 'subpoena.harness.Harness.collect':
                    result.add('subpoena.harness.Trace')
                elif symbol.endswith(('.start_span', '.start_as_current_span')):
                    result.add('opentelemetry.trace.Span')
                elif symbol and symbol.rsplit('.', 1)[-1][:1].isupper():
                    result.add(symbol)
                else:
                    result.add('')
            return '|'.join(sorted(result))
        return ''

    def local_names(self, node):
        # Comprehension targets, nested definitions and lambda parameters have
        # their own scope. Their stores must not shadow the enclosing imports.
        names = set()
        def visit(child):
            if isinstance(child, (*_FUNCTION, ast.ClassDef)):
                names.add(child.name)
                return
            if isinstance(child, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                names.add(child.id)
            for value in ast.iter_child_nodes(child):
                visit(value)
        for statement in node.body:
            visit(statement)
        return names

    def marker(self, fn):
        line = min([fn.lineno] + [d.lineno for d in fn.decorator_list]) - 1
        while line in self.comments and self.comments[line][1]:
            if re.match(r'#\s*subpoena:enforcement_point\b', self.comments[line][0]):
                return True
            line -= 1
        return False

    def call(self, node, scope, fn, direct, guarded, main):
        symbol = self.resolve(node.func, scope)
        written_name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', '')
        candidates = [part for part in symbol.split('|') if part]
        name = candidates[0].rsplit('.', 1)[-1] if candidates else written_name
        collect = symbol == 'subpoena.harness.Harness.collect'
        if collect and fn is not None and self.function_depth == 1:
            self.collected = True
        if self.test and fn is not None and self.function_depth == 1:
            if (_harness(symbol) and name in _WITNESS) or (
                    symbol.startswith('subpoena.witness.') and name in {'spawned', 'dialed'}):
                self.witnessed = True
        query_call = _harness(symbol) or not symbol
        if self.test and query_call and name in {'require_absent', 'absent'} and not guarded:
            self.add('unguarded-absence', node, 'collect() must run earlier in this function before absence')
        if self.test and query_call and name in _QUERIES:
            index = _QUERIES[name]
            query = next((k.value for k in node.keywords if k.arg == 'q'),
                         node.args[index] if index < len(node.args) else None)
            if isinstance(query, ast.Constant) and isinstance(query.value, str) and query.value.strip() not in self.invariants:
                self.add('orphan-invariant', query, 'TraceQL literal does not match an invariants/*.traceql file')
        provider = any(candidate in {'opentelemetry.trace.set_tracer_provider',
                              'opentelemetry.sdk.trace.TracerProvider', 'opentelemetry.trace.NoOpTracerProvider'}
                       for candidate in candidates)
        if provider and not main:
            exempt = any(re.match(r'#\s*subpoena:own_provider\s+\S', self.comments.get(line, ('', False))[0])
                         for line in (node.lineno, node.lineno - 1))
            if not exempt:
                self.add('provider-override', node, 'use the harness provider or declare # subpoena:own_provider <reason>')
        # Like Go's name check, telemetry syntax is recognised by method name.
        # This intentionally favours finding invented names over accepting dynamic types.
        keyargs = []
        def arg(index, keyword):
            return next((k.value for k in node.keywords if k.arg == keyword),
                        node.args[index] if index < len(node.args) else None)
        if name in {'start_span', 'start_as_current_span', 'update_name'}:
            keyargs.append(arg(0, 'name'))
        if name == 'set_attribute':
            keyargs.append(arg(0, 'key'))
        attrs = arg(0, 'attributes') if name == 'set_attributes' else next(
            (k.value for k in node.keywords if k.arg == 'attributes'), None)
        if name in {'start_span', 'start_as_current_span'} and attrs is None and len(node.args) > 3:
            attrs = node.args[3]
        if isinstance(attrs, ast.Dict):
            keyargs.extend(attrs.keys)
        for value in keyargs:
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value not in self.values:
                self.add('unknown-telemetry', value, f'{value.value!r} is not in the generated registry')
            ref = self.resolve(value, scope)
            if _semconv(ref) and ref.rsplit('.', 1)[-1] not in self.names:
                self.add('unknown-telemetry', value, f'{ref} does not exist in the generated registry')
        return collect and direct

    def expr(self, node, scope, fn, direct, guarded, main):
        if node is None or isinstance(node, (*_FUNCTION, ast.ClassDef)):
            return False
        if isinstance(node, ast.Lambda):
            local = dict(scope)
            for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                local[arg.arg] = ''
            for value in node.args.defaults + node.args.kw_defaults:
                self.expr(value, scope, fn, False, guarded, main)
            self.function_depth += 1
            self.expr(node.body, local, fn, False, False, main)
            self.function_depth -= 1
            return False
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            local = dict(scope)
            for generator in node.generators:
                self.expr(generator.iter, local, fn, False, guarded, main)
                for target in ast.walk(generator.target):
                    if isinstance(target, ast.Name):
                        local[target.id] = ''
                for condition in generator.ifs:
                    self.expr(condition, local, fn, False, guarded, main)
            values = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            for value in values:
                self.expr(value, local, fn, False, guarded, main)
            return False
        collected = False
        # Conditional expressions cannot establish collect-before-absence order.
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.BoolOp, ast.IfExp)):
            direct = False
        for child in ast.iter_child_nodes(node):
            collected |= self.expr(child, scope, fn, direct, guarded, main)
        if isinstance(node, ast.Call):
            collected |= self.call(node, scope, fn, direct, guarded, main)
        if not self.test:
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in self.values:
                self.emitted.add(node.value)
            symbol = self.resolve(node, scope)
            if _semconv(symbol):
                value = self.names.get(symbol.rsplit('.', 1)[-1])
                if value in self.values:
                    self.emitted.add(value)
        return collected

    def body(self, statements, scope, fn=None, guarded=False, direct=True, main=False):
        for node in statements:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                scope.update(self.import_bindings([node]))
                continue
            if isinstance(node, _FUNCTION):
                if self.marker(node):
                    self.points.append(node)
                self.tests |= node.name.startswith('test')
                local = dict(scope)
                # Imports are visible throughout their lexical function scope.
                for name in self.local_names(node):
                    local[name] = ''
                local.update(self.import_bindings(node.body))
                for value in node.decorator_list + node.args.defaults + node.args.kw_defaults:
                    self.expr(value, scope, fn, False, guarded, main)
                args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                for a in args:
                    local[a.arg] = self.resolve(a.annotation, scope) if a.annotation else ''
                self.function_depth += 1
                self.body(node.body, local, node, False, True, main)
                self.function_depth -= 1
                scope[node.name] = ''
                continue
            if isinstance(node, ast.ClassDef):
                for value in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                    self.expr(value, scope, fn, False, guarded, main)
                self.body(node.body, dict(scope), None, False, True, main)
                scope[node.name] = ''
                continue
            collected = False
            for field, value in ast.iter_fields(node):
                if field in {'body', 'orelse', 'finalbody', 'handlers', 'cases'}:
                    continue
                if isinstance(value, ast.AST):
                    collected |= self.expr(value, scope, fn, direct, guarded, main)
                elif isinstance(value, list):
                    for child in value:
                        if isinstance(child, ast.AST):
                            collected |= self.expr(child, scope, fn, direct, guarded, main)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                symbol = self.resolve(node.value, scope)
                for target in targets:
                    if isinstance(target, ast.Name):
                        scope[target.id] = symbol
            ismain = (isinstance(node, ast.If) and ast.dump(node.test, include_attributes=False) ==
                      ast.dump(ast.parse('__name__ == "__main__"', mode='eval').body, include_attributes=False))
            branches = []
            for field in ('body', 'orelse', 'finalbody'):
                children = getattr(node, field, [])
                if children:
                    branch = dict(scope)
                    self.body(children, branch, fn, guarded, False, main or (ismain and field == 'body' and not self.test))
                    branches.append(branch)
            for handler in getattr(node, 'handlers', []):
                branch = dict(scope)
                self.body(handler.body, branch, fn, guarded, False, main)
                branches.append(branch)
            for case in getattr(node, 'cases', []):
                branch = dict(scope)
                self.body(case.body, branch, fn, guarded, False, main)
                branches.append(branch)
            if branches:
                for name in set().union(*(branch.keys() for branch in branches)):
                    symbols = set()
                    # Preserve uncertainty: a conditional Harness binding cannot
                    # establish an unconditional collect, but possible provider
                    # construction must still be reported.
                    for branch in [scope] + branches:
                        symbols.update(branch.get(name, '').split('|'))
                    scope[name] = '|'.join(sorted(symbols))
            guarded |= collected

    def check(self):
        self.body(self.tree.body, dict(self.module_imports))
        if self.test:
            first = self.tree.body[0] if self.tree.body else ast.Constant(value=None, lineno=1, col_offset=0)
            if not re.search(r'#\s*subpoena:(spec_derived|impl_derived)\b', self.header):
                self.add('missing-provenance', first, 'add # subpoena:spec_derived or # subpoena:impl_derived in the file header')
            if re.search(r'#\s*subpoena:pure_logic\b', self.header):
                if any(_telemetry(p) for p in self.imports):
                    self.add('no-trace-assertion', first, 'pure_logic file imports telemetry')
            elif self.tests and not self.collected:
                self.add('no-trace-assertion', first, 'test file never calls the harness collect()')
        return self.findings


def run(roots, *, registry=None, invariants=None, dead_telemetry=False):
    """Lint target trees and return position-sorted findings. Raise LintError on load errors."""
    roots = [Path(p).resolve() for p in roots]
    if not roots:
        raise LintError('at least one target is required')
    regpath = Path(registry).resolve() if registry is not None else _find(roots[0], 'generated/python/semconv.py')
    names, values, positions = _registry(regpath)
    findings, emitted = [], set()
    for root in roots:
        invpath = Path(invariants).resolve() if invariants is not None else _find(root, 'invariants')
        queries = _invariants(invpath)
        files = []
        for path in _files(root):
            # Generated constants are data, never application emissions.
            if path == (regpath / 'semconv.py' if regpath.is_dir() else regpath):
                continue
            source = _File(path, names, values, queries)
            findings.extend(source.check())
            emitted.update(source.emitted)
            files.append(source)
        if not any(f.witnessed for f in files):
            for source in files:
                for point in source.points:
                    source.add('unwitnessed-enforcement', point, 'no test in the target tree asks a witness')
                    findings.append(source.findings[-1])
    if dead_telemetry:
        for name, value in names.items():
            if name.startswith(('SPAN_', 'ATTR_')) and value not in emitted:
                path, node = positions[name]
                findings.append(Finding(path, node.lineno, node.col_offset + 1, 'dead-telemetry',
                                        f'{name} is not referenced by non-test target code'))
    return sorted(set(findings), key=lambda f: (str(f.path), f.line, f.column, f.rule))


# ---- registry-drift ---------------------------------------------------------
#
# The registry is the contract; a test must not move together with it. The
# rule is Go's (internal/lint/drift.go): parse registry/**/*.yaml at the base
# revision and in the working tree, take the spans and attributes that are new
# or semantically changed (brief, note and examples are ignored), map them to
# the generated Python constants, and report Python test files changed since
# the base that reference one. A flag for a deliberate human look, not a
# verdict. Not handled, as in Go: removals, string literals, identifiers
# reached through variables, and non-span, non-attribute groups. Unlike Go, a
# bare constant name counts when Python cannot resolve where it came from (a
# star import, a module loaded with importlib); generated names are distinctive.

def _git(top, *args):
    try:
        done = subprocess.run(['git', '-C', str(top), *args], capture_output=True, check=False)
    except OSError as exc:
        raise LintError(f'git: {exc}') from exc
    if done.returncode != 0:
        raise LintError(f'git {" ".join(args)}: {done.stderr.decode(errors="replace").strip()}')
    return done.stdout


def _split_z(data):
    return [p for p in data.decode('utf-8', errors='surrogateescape').split('\0') if p]


def _pick(mapping, *keys):
    return {k: mapping[k] for k in keys if k in mapping}


def _parse_registry_yaml(model, name, data):
    try:
        import yaml
    except ImportError as exc:
        raise LintError("registry-drift needs PyYAML: pip install 'subpoena[drift]'") from exc
    try:
        document = yaml.safe_load(data)
    except (yaml.YAMLError, ValueError) as exc:  # PyYAML raises ValueError for some bad scalars
        raise LintError(f'parse {name}: {exc}') from exc
    # Fail on a shape Go's typed decode would reject: a skipped group could hide a change.
    def shape(ok, what):
        if not ok:
            raise LintError(f'parse {name}: {what}')
    shape(document is None or isinstance(document, dict), 'top level is not a mapping')
    groups = (document or {}).get('groups') or []
    shape(isinstance(groups, list), '`groups` is not a list')
    for group in groups:
        shape(isinstance(group, dict), 'a group is not a mapping')
        attributes = group.get('attributes') or []
        shape(isinstance(attributes, list) and all(isinstance(a, dict) for a in attributes),
              f'group {group.get("id")!r}: `attributes` is not a list of mappings')
        if group.get('type') == 'attribute_group':
            for a in attributes:
                if isinstance(a.get('id'), str) and a['id']:
                    model['attribute'][a['id']] = _canonical(_pick(a, 'type', 'stability', 'deprecated', 'annotations'))
        elif group.get('type') == 'span' and group.get('name'):
            model['span'][group['name']] = _canonical({
                'span_kind': group.get('span_kind', ''), 'stability': group.get('stability', ''),
                'attributes': [_pick(a, 'ref', 'id', 'requirement_level', 'type', 'annotations') for a in attributes]})


def _canonical(value):
    # Keys are stringified first: YAML 1.1 reads `on`, `no` and dates as non-string keys.
    def norm(v):
        if isinstance(v, dict):
            return sorted([str(k), norm(x)] for k, x in v.items())
        if isinstance(v, list):
            return [norm(x) for x in v]
        return v
    return json.dumps(norm(value), default=str)


def _is_yaml(path):
    return str(path).endswith(('.yaml', '.yml'))


def _python_test(path):
    name = Path(path).name
    return name.endswith('.py') and (name.startswith('test_') or name.endswith('_test.py') or name == 'conftest.py')


def diff_registry(base, head):
    """(kind, id, new) for each span or attribute new or changed in head, sorted by kind and id."""
    out = []
    for kind in ('attribute', 'span'):
        for ident, value in head[kind].items():
            if base[kind].get(ident) != value:
                out.append((kind, ident, ident not in base[kind]))
    return sorted(out)


def registry_drift(repo='.', base=''):
    """Run the registry-drift rule over a git repository. Raise LintError on load errors."""
    try:
        top = Path(_git(repo, 'rev-parse', '--show-toplevel').decode().strip())
    except LintError as exc:
        raise LintError(f'registry-drift needs a git repository: {exc}') from exc
    rev = 'HEAD'
    if base and base != 'HEAD':
        rev = base
        try:
            rev = _git(top, 'merge-base', base, 'HEAD').decode().strip()
        except LintError:
            try:
                _git(top, 'rev-parse', '--verify', base + '^{commit}')
            except LintError:
                raise LintError(f'unknown base revision {base!r}') from None
    try:
        _git(top, 'rev-parse', '--verify', rev + '^{commit}')
        has_base = True
    except LintError:
        has_base = False  # a repository with no commits yet: the base registry is empty

    base_model = {'attribute': {}, 'span': {}}
    if has_base:
        for p in _split_z(_git(top, 'ls-tree', '-r', '--name-only', '-z', rev, '--', 'registry')):
            if _is_yaml(p):
                _parse_registry_yaml(base_model, f'{rev}:{p}', _git(top, 'show', f'{rev}:{p}'))
    head_model = {'attribute': {}, 'span': {}}
    registry_dir = top / 'registry'
    if registry_dir.is_dir():
        for directory, dirs, files in os.walk(registry_dir):
            dirs.sort()
            for f in sorted(files):
                path = Path(directory) / f
                if _is_yaml(path):
                    try:
                        data = path.read_bytes()
                    except OSError as exc:
                        raise LintError(f'{path}: {exc}') from exc
                    _parse_registry_yaml(head_model, str(path), data)
    changes = diff_registry(base_model, head_model)
    if not changes:
        return []

    regpath = top / 'generated/python/semconv.py'
    if not regpath.exists():
        raise LintError(f'registry-drift: {regpath} not found (run `make generate`)')
    names, _, _ = _registry(regpath)
    by_value = {(kind, ident): (kind, ident, new) for kind, ident, new in changes}
    by_const = {}
    for name, value in names.items():
        kind = 'span' if name.startswith('SPAN_') else 'attribute' if name.startswith('ATTR_') else None
        if kind and (kind, value) in by_value:
            by_const[name] = by_value[(kind, value)]

    tests = []
    if has_base:
        tests += _split_z(_git(top, 'diff', '--name-only', '-z', '--diff-filter=ACMR', rev, '--', '*.py'))
    tests += _split_z(_git(top, 'ls-files', '--others', '--exclude-standard', '-z', '--', '*.py'))
    label = base or 'HEAD'
    findings = []
    for rel in sorted(set(t for t in tests if _python_test(t))):
        path = top / rel
        try:
            source = _File(path, names, set(), set(), star_ok=True)
        except LintError:
            continue  # a test that does not parse is the interpreter's problem
        scope = dict(source.module_imports)
        for node in ast.walk(source.tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                scope.update(source.import_bindings([node]))
        for node in ast.walk(source.tree):
            if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(node.ctx, ast.Load):
                continue
            # Through an import of the generated module, or by the constant's own
            # name where Python cannot say where it came from (a star import, a
            # module loaded with importlib). A binding to some other module rules it out.
            symbols = [p for p in source.resolve(node, scope).split('|') if p]
            if symbols:
                consts = sorted({p.rsplit('.', 1)[-1] for p in symbols if _semconv(p)} & by_const.keys())
            else:
                written = node.attr if isinstance(node, ast.Attribute) else node.id
                consts = [written] if written in by_const else []
            if not consts:
                continue
            kind, ident, new = by_const[consts[0]]
            findings.append(Finding(path, node.lineno, node.col_offset + 1, 'registry-drift',
                f'{ast.unparse(node)} references {kind} "{ident}", which is {"new" if new else "changed"} in the registry/ '
                f'diff against {label}; the registry is the contract, so confirm the code or test is not being '
                'bent to fit (needs registry owner review)'))
    return sorted(set(findings), key=lambda f: (str(f.path), f.line, f.column))


def _registry_drift_main(argv):
    parser = argparse.ArgumentParser(prog='subpoena-lint registry-drift',
                                     description='Flag Python test files that move together with registry/.')
    parser.add_argument('-base', '--base', default='',
                        help='revision to compare against (default HEAD: working tree vs HEAD); '
                             'a branch ref is resolved to its merge-base with HEAD')
    parser.add_argument('repo', nargs='?', default='.')
    args = parser.parse_args(argv)
    try:
        findings = registry_drift(args.repo, args.base)
    except Exception as exc:  # any failure is a load error (2), never findings (1) that a label could waive
        print(f'subpoena-lint: registry-drift: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print(f'subpoena-lint registry-drift: {len(findings)} finding(s)', file=sys.stderr)
        return 1
    print('subpoena-lint registry-drift: clean')
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ['registry-drift']:
        return _registry_drift_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-registry', '--registry', type=Path, help='generated semconv.py or its directory')
    parser.add_argument('-invariants', '--invariants', type=Path, help='directory containing *.traceql')
    parser.add_argument('-dead-telemetry', '--dead-telemetry', action='store_true')
    parser.add_argument('targets', nargs='+', type=Path)
    args = parser.parse_args(argv)
    try:
        findings = run(args.targets, registry=args.registry, invariants=args.invariants,
                       dead_telemetry=args.dead_telemetry)
    except (LintError, OSError, tokenize.TokenError, RecursionError, ValueError) as exc:
        print(f'subpoena-lint: {exc}', file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    return int(bool(findings))


if __name__ == '__main__':
    raise SystemExit(main())
