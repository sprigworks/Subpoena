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


def test_explicit_level_zero_exemptions_keep_other_rules(project):
    found = check(project, 'def test_example():\n    t.start_span("invented")\n',
                  exemptions={'unknown-telemetry': 'Level 0 has no registry'})
    assert rules(found) == {'missing-provenance', 'no-trace-assertion'}


@pytest.mark.parametrize('exemptions', [
    {'unknown-telemetry': ' '},
    {'missing-provenance': 'not a Level 0 exception'},
    {'typo': 'invalid rule'},
])
def test_invalid_exemptions_fail(project, exemptions):
    with pytest.raises(LintError):
        run([project], exemptions=exemptions)


def test_exemption_cli_requires_and_reports_reason(project):
    (project / "service.py").write_text('t.start_span("invented")\n')
    result = subprocess.run([sys.executable, '-m', 'subpoena.lint', '--exempt',
                             'unknown-telemetry=Level 0 has no registry', str(project)],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert 'exempt unknown-telemetry: Level 0 has no registry' in result.stderr
    result = subprocess.run([sys.executable, '-m', 'subpoena.lint', '--exempt',
                             'unknown-telemetry=', str(project)], text=True, capture_output=True)
    assert result.returncode == 2
    assert 'needs a reason' in result.stderr


@pytest.mark.parametrize('rule', ['unknown-telemetry', 'orphan-invariant'])
def test_stale_global_exemption_fails(project, rule):
    with pytest.raises(LintError, match='stale exemption'):
        run([project], exemptions={rule: 'obsolete waiver'})
    result = subprocess.run([sys.executable, '-m', 'subpoena.lint', '--exempt',
                             f'{rule}=obsolete waiver', str(project)], text=True, capture_output=True)
    assert result.returncode == 2


def test_unwitnessed_cannot_be_globally_exempted(project):
    with pytest.raises(LintError, match='cannot be exempted'):
        run([project], exemptions={'unwitnessed-enforcement': 'too broad'})


def test_unwitnessed_site_exemption_does_not_waive_second_point(project):
    found = check(project, """# subpoena:enforcement_point
# subpoena:unwitnessed Educational dictionary observation
@decorator
def first():
    pass

# subpoena:enforcement_point
def second():
    pass
""", 'service.py')
    assert len(found) == 1
    assert found[0].rule == 'unwitnessed-enforcement'
    assert found[0].line == 8


@pytest.mark.parametrize('source,reason', [
    ('# subpoena:enforcement_point\n# subpoena:unwitnessed\ndef f(): pass', 'needs a reason'),
    ('# subpoena:unwitnessed reason\nx = 1', 'misplaced'),
    ('# subpoena:unwitnessed reason\ndef f(): pass', 'stale'),
    ('# subpoena:enforcement_point\n# subpoena:unwitnessed reason\ndef f(): pass\n'
     'from subpoena.harness import require_no_spawn\n'
     'def test_check(): require_no_spawn(w, "t")', 'stale'),
])
def test_invalid_site_exemptions_fail(project, source, reason):
    with pytest.raises(LintError, match=reason):
        check(project, source, 'test_service.py' if 'test_check' in source else 'service.py')


def test_site_marker_becomes_stale_when_witness_added(project):
    (project / 'service.py').write_text(
        '# subpoena:enforcement_point\n'
        '# subpoena:unwitnessed Educational direct state observation\n'
        'def authorize(): pass\n')
    (project / 'test_service.py').write_text(
        '# subpoena:spec_derived\n'
        'from subpoena.harness import require_no_spawn\n'
        'def test_denied(): require_no_spawn(w, "t")\n')
    with pytest.raises(LintError, match='stale unwitnessed marker'):
        run([project])


@pytest.mark.parametrize('call', ['no_delivery', 'require_no_delivery', 'check_no_delivery'])
def test_delivery_checks_count_as_asking_a_witness(project, call):
    (project / 'service.py').write_text('# subpoena:enforcement_point\ndef authorize(): pass\n')
    (project / 'test_service.py').write_text(
        '# subpoena:spec_derived\n'
        f'from subpoena.harness import {call}\n'
        f'def test_denied(): {call}(w, "t")\n')
    assert 'unwitnessed-enforcement' not in rules(run([project]))


def test_asking_the_log_what_was_written_counts_as_asking_a_witness(project):
    (project / 'service.py').write_text('# subpoena:enforcement_point\ndef authorize(): pass\n')
    (project / 'test_service.py').write_text(
        '# subpoena:spec_derived\n'
        'from subpoena import witness\n'
        'def test_denied():\n'
        '    log = witness.read_log(open("w"))\n'
        '    assert not log.wrote("t")\n')
    assert 'unwitnessed-enforcement' not in rules(run([project]))
