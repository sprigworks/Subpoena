# subpoena:impl_derived
# subpoena:pure_logic
"""Resolution regressions from a second review of the AST walk."""
import pytest

from subpoena.lint import LintError, run


@pytest.fixture
def project(tmp_path):
    generated = tmp_path / 'generated/python'
    generated.mkdir(parents=True)
    (generated / 'semconv.py').write_text('SPAN_ACTION = "action"\nATTR_KEY = "key"\n')
    return tmp_path


def write(root, source, filename='test_example.py'):
    target = root / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)


def test_read_log_result_is_a_witness(project):
    write(project, '# subpoena:enforcement_point\ndef enforce(): return False\n', 'service.py')
    write(project, '''# subpoena:impl_derived
from subpoena.witness import read_log as read
from subpoena.harness import Harness as H
log = read(file)
def test_x():
    h = H()
    h.collect()
    log.spawned(trace_id)
''')
    assert run([project]) == []


def test_committed_on_a_witness_log_asks_a_witness(project):
    (project / 'service.py').write_text('# subpoena:enforcement_point\ndef enforce(): return False\n')
    write(project, '''# subpoena:impl_derived
from subpoena.witness import read_log
from subpoena.harness import Harness
log = read_log(file)
def test_x():
    Harness().collect()
    log.committed(trace_id)
''')
    assert 'unwitnessed-enforcement' not in {f.rule for f in run([project])}


def test_conditional_expressions_cannot_guard_absence(project):
    for expression in ('flag and h.collect()', 'h.collect() if flag else None',
                       '[h.collect() for _ in items]'):
        write(project, '# subpoena:impl_derived\nfrom subpoena.harness import Harness, require_absent\n'
              'def test_x():\n    h = Harness()\n    ' + expression + '\n    require_absent(None, query)\n')
        assert 'unguarded-absence' in {f.rule for f in run([project])}


def test_parameters_resolve_but_unrelated_collect_does_not(project):
    write(project, '''# subpoena:impl_derived
from subpoena.harness import Harness, require_absent
from metrics import Collector
def test_x(h: Harness, metrics: Collector):
    metrics.collect()
    require_absent(None, query)
    h.collect()
''')
    assert {f.rule for f in run([project])} == {'unguarded-absence'}


def test_overlapping_roots_keep_tree_witness_and_deduplicate(project):
    write(project, '# subpoena:enforcement_point\ndef enforce(): return False\n', 'service.py')
    write(project, '''# subpoena:impl_derived
from subpoena.harness import require_no_spawn
def test_x():
    require_no_spawn(witness, trace_id)
''', 'tests/test_example.py')
    findings = run([project / 'tests', project])
    assert {f.rule for f in findings} == {'no-trace-assertion'}
    assert len(findings) == 1


def test_unknown_absence_receiver_is_checked(project):
    write(project, '# subpoena:impl_derived\ndef test_x(tr):\n    tr.absent(query)\n')
    assert 'unguarded-absence' in {f.rule for f in run([project])}


def test_star_import_refused(project):
    write(project, 'from subpoena.harness import *\n')
    with pytest.raises(LintError, match='star imports'):
        run([project])


def test_test_main_guard_does_not_exempt_provider(project):
    write(project, '''# subpoena:impl_derived
from opentelemetry.sdk.trace import TracerProvider
if __name__ == '__main__':
    TracerProvider()
''')
    assert 'provider-override' in {f.rule for f in run([project])}


@pytest.mark.parametrize('setup,call', [
    ('from subpoena.harness import require_absent as ra', 'ra(None, "orphan")'),
    ('from subpoena import harness\nra = harness.require_absent', 'ra(None, "orphan")'),
])
def test_renamed_assertions_are_checked(project, setup, call):
    write(project, '# subpoena:impl_derived\n' + setup + '\ndef test_x():\n    ' + call + '\n')
    assert {'unguarded-absence', 'orphan-invariant'} <= {f.rule for f in run([project])}


def test_imports_in_blocks_and_later_in_file(project):
    write(project, '''def setup():
    trace.set_tracer_provider(Provider())
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider as Provider
except ImportError:
    trace = None
''', 'service.py')
    assert len([f for f in run([project]) if f.rule == 'provider-override']) == 2


@pytest.mark.parametrize('source', [
    'f = lambda: tracer.start_span("invented")',
    '@tracer.start_span("invented")\ndef f(): pass',
    'def f(default=tracer.start_span("invented")): pass',
    'class C(tracer.start_span("invented")): pass',
])
def test_all_expression_contexts_checked(project, source):
    write(project, source, 'service.py')
    assert 'unknown-telemetry' in {f.rule for f in run([project])}


def test_test_prefix_and_decorator_header_boundary(project):
    write(project, '''@staticmethod
# subpoena:impl_derived
# subpoena:pure_logic
def testfoo(): pass
''')
    assert {f.rule for f in run([project])} == {'missing-provenance', 'no-trace-assertion'}


def test_comprehension_does_not_shadow_enclosing_import(project):
    write(project, '''from opentelemetry.sdk.trace import TracerProvider
def setup():
    provider = TracerProvider()
    return [provider for TracerProvider in range(1)]
''', 'service.py')
    assert 'provider-override' in {f.rule for f in run([project])}


def test_relative_harness_import_marks_telemetry(project):
    write(project, '# subpoena:impl_derived\n# subpoena:pure_logic\nfrom . import harness\ndef test_x(): pass\n')
    assert 'no-trace-assertion' in {f.rule for f in run([project])}


def test_parse_resource_and_null_errors_are_load_errors(project, monkeypatch):
    from subpoena import lint
    write(project, 'x = 1', 'service.py')
    for error in (RecursionError('too deep'), ValueError('null bytes')):
        def fail(*args, **kwargs):
            raise error
        with monkeypatch.context() as patch:
            patch.setattr(lint.ast, 'parse', fail)
            with pytest.raises(LintError):
                run([project])


def test_comprehension_shadow_is_local_inside_expression(project):
    write(project, '''from opentelemetry.sdk.trace import TracerProvider
def setup():
    return [TracerProvider() for TracerProvider in constructors]
''', 'service.py')
    assert run([project]) == []


def test_conditional_harness_binding_is_not_a_guaranteed_collect(project):
    write(project, '''# subpoena:impl_derived
from subpoena.harness import Harness, require_absent
def test_x():
    if condition:
        h = Harness()
    h.collect()
    require_absent(None, query)
''')
    assert 'unguarded-absence' in {f.rule for f in run([project])}
