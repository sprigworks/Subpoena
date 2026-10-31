# subpoena:spec_derived
# subpoena:pure_logic
"""L1 contract fixtures, written from lint/README.md before the Python implementation."""
import subprocess
import sys
from pathlib import Path

import pytest

from subpoena.lint import LintError, run

REGISTRY = '''SPAN_ACTION: Final = "action"
ATTR_ALLOWED: Final = "allowed"
VAL_MODE: Final = "mode"
TIER_ALL: Final = "all"
'''


@pytest.fixture
def project(tmp_path):
    registry = tmp_path / 'generated/python/semconv.py'
    registry.parent.mkdir(parents=True)
    registry.write_text(REGISTRY)
    (tmp_path / 'invariants').mkdir()
    (tmp_path / 'invariants/action.traceql').write_text('{ name = "action" }')
    return tmp_path


def check(root, source, filename='test_service.py', **kwargs):
    (root / filename).write_text(source)
    return run([root], **kwargs)


def rules(findings):
    return {f.rule for f in findings}


def test_all_core_findings(project):
    found = check(project, '''from subpoena.harness import Harness, require_absent
from opentelemetry.sdk.trace import TracerProvider
# subpoena:enforcement_point
def authorize():
    return False

def test_denied():
    h = Harness()
    require_absent(None, '{ name = "other" }')
    h.tracer('svc').start_span('invented')
    TracerProvider()
''')
    assert rules(found) == {'unknown-telemetry', 'no-trace-assertion',
                           'unwitnessed-enforcement', 'unguarded-absence',
                           'missing-provenance', 'orphan-invariant', 'provider-override'}
    assert all(f.line > 0 and f.column > 0 for f in found)
    assert found == sorted(found, key=lambda f: (str(f.path), f.line, f.column, f.rule))


def test_clean_aliases_and_registered_literals(project):
    found = check(project, '''# subpoena:spec_derived
from subpoena import harness as tel
from generated.python import semconv as sc
from opentelemetry.sdk.trace import TracerProvider as Provider
# subpoena:enforcement_point
def authorize():
    return False

def test_denied():
    h = tel.Harness()
    tracer = h.tracer('svc')
    tracer.start_as_current_span(sc.SPAN_ACTION, attributes={sc.ATTR_ALLOWED: False})
    tr = h.collect()
    tel.require_absent(tr, '{ name = "action" }')
    tel.require_no_spawn(witness, session)
    Provider()  # subpoena:own_provider exercise the provider's own behavior
''')
    assert found == []


@pytest.mark.parametrize('call', ["s.set_attribute('invented', 1)",
                                  "s.set_attributes({'invented': 1})",
                                  "t.start_span(name='invented')",
                                  "t.start_as_current_span('mode')",
                                  "s.update_name(sc.SPAN_MISSING)"])
def test_unknown_telemetry_shapes(project, call):
    assert 'unknown-telemetry' in rules(check(project,
        'from generated.python import semconv as sc\n' + call, 'service.py'))


def test_enum_values_are_not_names_and_tests_do_not_emit(project):
    found = check(project, '# subpoena:spec_derived\n# subpoena:pure_logic\n'
                  'def test_value():\n    assert "action"\n', dead_telemetry=True)
    assert rules(found) == {'dead-telemetry'}
    assert len(found) == 2


def test_dead_telemetry_refs_and_literals(project):
    (project / 'service.py').write_text('from generated.python.semconv import SPAN_ACTION as S\nx = S\ny = "allowed"\n')
    assert run([project], dead_telemetry=True) == []


@pytest.mark.parametrize('source', [
    'from metrics import Collector\nc = Collector()\ndef test_x():\n    c.collect()\n',
    'from subpoena.harness import Harness\nclass Metrics:\n    def collect(self): pass\nm = Metrics()\ndef test_x():\n    m.collect()\n',
    'from subpoena.harness import Harness\ndef test_x():\n    h = Harness()\n    def later(): h.collect()\n',
])
def test_unrelated_or_deferred_collect_does_not_count(project, source):
    assert 'no-trace-assertion' in rules(check(project, '# subpoena:impl_derived\n' + source))


def test_scope_and_order_for_absence(project):
    source = '''# subpoena:spec_derived
from subpoena.harness import Harness, require_absent
h = Harness()
def helper():
    h.collect()
def test_x():
    require_absent(None, query)
    h.collect()
'''
    assert 'unguarded-absence' in rules(check(project, source))


def test_conditional_and_nested_collect_not_guard(project):
    for statement in ['if flag: h.collect()', 'def nested(): h.collect()']:
        source = ('# subpoena:spec_derived\nfrom subpoena.harness import Harness, require_absent\n'
                  'def test_x():\n    h = Harness()\n    ' + statement + '\n    require_absent(None, query)\n')
        assert 'unguarded-absence' in rules(check(project, source))


def test_collected_trace_methods_and_keyword_queries(project):
    source = '''# subpoena:spec_derived
from subpoena.harness import Harness, require_exists
h = Harness()
def test_x():
    tr = h.collect()
    tr.absent(q='{ name = "action" }')
    require_exists(t=tr, q='orphan')
'''
    assert rules(check(project, source)) == {'orphan-invariant'}


@pytest.mark.parametrize('module', ['subpoena.harness', 'subpoena.witness',
                                    'opentelemetry.trace', 'generated.python.semconv', 'subpoena.invariants'])
def test_pure_logic_cannot_import_telemetry(project, module):
    assert 'no-trace-assertion' in rules(check(project,
        '# subpoena:spec_derived\n# subpoena:pure_logic\nimport ' + module + '\ndef test_x(): pass\n'))


def test_late_markers_and_helpers(project):
    assert 'missing-provenance' in rules(check(project, 'x = 1\n# subpoena:spec_derived\ndef helper(): pass\n'))
    assert check(project, '# subpoena:impl_derived\ndef helper(): pass\n') == []


def test_provider_aliases_main_and_reason(project):
    source = '''from opentelemetry import trace as api
from opentelemetry.sdk.trace import TracerProvider as TP
TP()  # subpoena:own_provider
api.set_tracer_provider(None)
if __name__ == '__main__':
    TP()
'''
    assert len([f for f in check(project, source, 'service.py') if f.rule == 'provider-override']) == 2


def test_unrelated_witness_does_not_count(project):
    (project / 'service.py').write_text('# subpoena:enforcement_point\ndef enforce(): return False\n')
    found = check(project, '''# subpoena:spec_derived
# subpoena:pure_logic
class Fake:
    def spawned(self): pass
def test_x():
    Fake().spawned()
''')
    assert 'unwitnessed-enforcement' in rules(found)


def test_syntax_errors_bad_paths_and_registry_fail_closed(project):
    with pytest.raises(LintError):
        check(project, 'def broken(')
    (project / 'test_service.py').unlink()
    with pytest.raises(LintError):
        run([project / 'missing'])
    with pytest.raises(LintError):
        run([project], registry=project / 'missing.py')
    with pytest.raises(LintError):
        run([project], invariants=project / 'missing-invariants')


def test_never_execute_generated_registry(project):
    registry = project / 'generated/python/semconv.py'
    registry.write_text(REGISTRY + '\nraise RuntimeError("executed registry")\n')
    assert check(project, 'x = 1', 'service.py') == []


def test_cli_exit_codes(project):
    (project / 'service.py').write_text('span.update_name("invented")\n')
    command = [sys.executable, '-m', 'subpoena.lint']
    r = subprocess.run(command + [str(project)], capture_output=True, text=True)
    assert r.returncode == 1
    assert 'unknown-telemetry' in r.stdout
    assert subprocess.run(command + [str(project / 'missing')], capture_output=True).returncode == 2
    (project / 'service.py').write_text('x = 1\n')
    assert subprocess.run(command + [str(project)], capture_output=True).returncode == 0


def test_skipped_trees(project):
    for name in ['.hidden', 'vendor', 'testdata', 'node_modules', '__pycache__']:
        (project / name).mkdir()
        (project / name / 'broken.py').write_text('def broken(')
    assert run([project]) == []
