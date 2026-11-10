# subpoena:impl_derived
# subpoena:pure_logic
"""Cross parity against Go's documented group, selection and evidence semantics."""
import json
from pathlib import Path
import textwrap

import pytest

from subpoena import cross

AUTH = '''
# subpoena:enforcement_point
def allowed(admin):
    if not admin:
        return False  # subpoena:enforcement
    return True
'''
LAYERED = '''
# subpoena:enforcement_point
def allowed(admin):
    if not admin:
        return False  # subpoena:enforcement group=access
    if not admin:
        return False  # subpoena:enforcement group=access
    return True
'''
TEST = '''
from auth import allowed
from subpoena.harness import witness_fail
def test_denied():
    if allowed(False):
        witness_fail("denied action ran")
def test_admin():
    assert allowed(True)
'''


def project(root, auth=AUTH, test=TEST):
    (root / 'auth.py').write_text(textwrap.dedent(auth).lstrip())
    (root / 'test_auth.py').write_text(textwrap.dedent(test).lstrip())
    return str(root)


@pytest.mark.parametrize('marker', ['group=', 'group=x group=y', 'oops=x', 'group=a/b'])
def test_bad_group_marker_refused(tmp_path, marker):
    project(tmp_path, AUTH.replace('subpoena:enforcement\n', 'subpoena:enforcement ' + marker + '\n'))
    with pytest.raises(cross.CrossError):
        cross.find_mutants(str(tmp_path))


def test_group_bounds(tmp_path):
    project(tmp_path, AUTH.replace('subpoena:enforcement\n', 'subpoena:enforcement group=only\n'))
    with pytest.raises(cross.CrossError, match='one layer'):
        cross.run(str(tmp_path))


def test_parallel_copies_restore_and_keep_order(tmp_path):
    auth = AUTH + AUTH.replace('allowed', 'also_allowed')
    project(tmp_path, auth, TEST + '\nfrom auth import also_allowed\ndef test_also(): assert not also_allowed(False)\n')
    before = (tmp_path / 'auth.py').read_bytes()
    sequential = cross.run(str(tmp_path))
    parallel = cross.run(str(tmp_path), jobs=2)
    assert [r.outcome for r in parallel.results] == [cross.KILLED, cross.KILLED]
    assert [(r.mutant.func, r.outcome) for r in parallel.results] == [
        (r.mutant.func, r.outcome) for r in sequential.results]
    assert before == (tmp_path / 'auth.py').read_bytes()


def test_raw_evidence_includes_kills_and_reports(tmp_path, capsys):
    root = tmp_path / 'project'
    root.mkdir()
    evidence = tmp_path / 'evidence'
    rep = cross.run(project(root), evidence_dir=str(evidence))
    assert not rep.failed()
    result = rep.results[0]
    assert Path(result.evidence_file).is_file()
    assert 'witness: denied action ran' in Path(result.evidence_file).read_text()
    assert cross.main(['-evidence-dir', str(evidence), str(root)]) == 0
    output = capsys.readouterr().out
    assert '  evidence file: ' in output
    printed = output.split('  evidence file: ', 1)[1].splitlines()[0]
    assert Path(printed).is_file()
    assert printed != result.evidence_file
    records = [json.loads(line) for p in evidence.glob('*.jsonl') for line in p.read_text().splitlines()]
    assert any(r.get('kind') == 'failure' and r.get('verdict') == 'assertion' for r in records)
    assert any(r.get('kind') == 'finished' for r in records)
    assert any('witness: denied action ran' in p.read_text() for p in evidence.glob('*.txt'))


def test_masked_layers_fail_without_acceptance(tmp_path):
    rep = cross.run(project(tmp_path, LAYERED))
    assert [r.outcome for r in rep.results[:2]] == [cross.MASKED, cross.MASKED]
    assert rep.results[2].outcome == cross.KILLED and rep.failed()
    assert all(r.masked_by for r in rep.results[:2])


def test_masked_acceptance_unique_layers_and_stale_entries(tmp_path):
    # Different text makes the reviewed entries unambiguous.
    auth = LAYERED.replace('return False  # subpoena:enforcement group=access',
                           'return bool(0)  # subpoena:enforcement group=access', 1)
    project(tmp_path, auth)
    accepted = tmp_path / 'cross-masked.txt'
    accepted.write_text('auth.py | allowed | group=access | return bool(0) | early layer\n'
                        'auth.py | allowed | group=access | return False | late layer\n')
    rep = cross.run(str(tmp_path))
    assert not rep.failed()
    assert all(r.accepted for r in rep.results[:2])
    accepted.write_text(accepted.read_text() + 'auth.py | missing | group=access | return False | stale\n')
    assert cross.run(str(tmp_path)).failed()


def test_ambiguous_and_duplicate_acceptance_refused(tmp_path):
    project(tmp_path, LAYERED)
    entry = 'auth.py | allowed | group=access | return False | layered\n'
    (tmp_path / 'cross-masked.txt').write_text(entry)
    with pytest.raises(cross.CrossError, match='matches 2 masked layers'):
        cross.run(str(tmp_path))
    (tmp_path / 'cross-masked.txt').write_text(entry * 2)
    with pytest.raises(cross.CrossError, match='each layer listed once'):
        cross.run(str(tmp_path))


def test_selection_matches_whole_suite_and_keeps_full_fallback(tmp_path):
    project(tmp_path)
    evidence = tmp_path.parent / (tmp_path.name + '-evidence')
    rep = cross.run(str(tmp_path), select=True, evidence_dir=str(evidence))
    assert not rep.failed() and rep.results[0].outcome == cross.KILLED
    assert rep.results[0].selected == ['test_auth.py::test_denied']


def test_selection_refuses_order_dependent_test(tmp_path):
    project(tmp_path, test='''
        from auth import allowed
        state = []
        def test_first():
            state.append(1)
            assert not allowed(False)
        def test_second():
            assert state
    ''')
    with pytest.raises(cross.CrossError, match='fails when run alone'):
        cross.run(str(tmp_path), select=True)


def test_selection_falls_back_when_coverage_misses_subprocess(tmp_path):
    guarded = AUTH.replace('if not admin:', 'if not admin:  # subpoena:enforcement_guard false').replace('  # subpoena:enforcement\n', '\n')
    project(tmp_path, auth=guarded, test='''
        import subprocess, sys
        from auth import allowed
        def test_visible():
            assert allowed(True)
        def test_child():
            output = subprocess.check_output([sys.executable, '-c',
                'from auth import allowed; print(allowed(False))'], text=True)
            assert output.strip() == 'False'
    ''')
    rep = cross.run(str(tmp_path), select=True)
    assert rep.results[0].outcome == cross.KILLED
    assert rep.results[0].failing == ['test_auth.py::test_child']


def test_guard_groups_across_files_require_all_imports(tmp_path):
    # Discovery checks guard group syntax without running a suite.
    (tmp_path / 'auth.py').write_text('''# subpoena:enforcement_point
def allow(admin):
    if not admin:  # subpoena:enforcement_guard false group=g
        return False
    return True
''')
    (tmp_path / 'other.py').write_text((tmp_path / 'auth.py').read_text())
    _, mutants = cross.find_mutants(str(tmp_path))
    assert len(mutants) == 2 and all(m.group == 'g' for m in mutants)


@pytest.mark.parametrize('kwargs', [{'jobs': 0}, {'timeout': 0}, {'timeout': float('nan')}])
def test_bad_options_refused(tmp_path, kwargs):
    with pytest.raises(cross.CrossError):
        cross.run(project(tmp_path), **kwargs)


def test_surviving_layer_cannot_hide_behind_an_independent_kill(tmp_path):
    auth = '''
# subpoena:enforcement_point
def first(admin):
    if not admin:
        return False  # subpoena:enforcement group=controls
    return True
# subpoena:enforcement_point
def second(admin):
    if not admin:
        return False  # subpoena:enforcement group=controls
    return True
'''
    project(tmp_path, auth, '''
from auth import first, second
def test_first(): assert not first(False)
def test_second(): assert second(True)
''')
    rep = cross.run(str(tmp_path))
    assert [r.outcome for r in rep.results] == [cross.KILLED, cross.SURVIVED, cross.KILLED]
    assert rep.failed()


def test_group_mutants_all_have_to_be_loaded(tmp_path):
    project(tmp_path, AUTH.replace('subpoena:enforcement\n', 'subpoena:enforcement group=all\n'))
    (tmp_path / 'other.py').write_text(AUTH.replace('subpoena:enforcement\n', 'subpoena:enforcement group=all\n'))
    rep = cross.run(str(tmp_path))
    assert rep.results[1].outcome == cross.INVALID
    assert rep.results[-1].outcome == cross.INVALID
    assert rep.failed()


def test_evidence_inside_target_is_excluded(tmp_path):
    project(tmp_path)
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    # A previous evidence artifact must not be discovered as enforcement source.
    (evidence / 'broken.py').write_text('# subpoena:enforcement_point\ndef broken(')
    assert not cross.run(str(tmp_path), evidence_dir=str(evidence)).failed()


def test_group_limit_and_unreadable_evidence_fail_closed(tmp_path):
    project(tmp_path, '\n'.join(AUTH.replace('allowed', f'allow_{i}').replace(
        'subpoena:enforcement\n', 'subpoena:enforcement group=too_big\n') for i in range(9)))
    with pytest.raises(cross.CrossError, match='at most 8'):
        cross.run(str(tmp_path))


def test_selection_subset_baseline_detects_interaction(tmp_path):
    # Each test is green alone, and the full suite is green, but the selected
    # pair fails together because the unselected reset normally separates them.
    project(tmp_path, test='''
from auth import allowed
state = []
def test_a():
    state.append(1)
    assert not allowed(False)
def test_b_reset():
    state.clear()
def test_c():
    assert not state
    assert not allowed(False)
''')
    with pytest.raises(cross.CrossError, match='selected subset fails without the mutant'):
        cross.run(str(tmp_path), select=True)


def test_selection_resolves_symlinked_temporary_root(tmp_path, monkeypatch):
    actual = tmp_path / 'actual'
    actual.mkdir()
    linked = tmp_path / 'linked'
    linked.symlink_to(actual, target_is_directory=True)
    root = tmp_path / 'project'
    root.mkdir()
    monkeypatch.setattr(cross.tempfile, 'tempdir', str(linked))
    rep = cross.run(project(root), select=True)
    assert rep.results[0].outcome == cross.KILLED
    assert rep.results[0].selected == ['test_auth.py::test_denied']


def test_evidence_path_empty_without_evidence_directory(tmp_path):
    rep = cross.run(project(tmp_path))
    assert rep.results[0].evidence_file == ''


def test_require_witness_group_cannot_mask_self_report(tmp_path):
    root = project(tmp_path, LAYERED, TEST.replace('witness_fail("denied action ran")', 'raise AssertionError("testimony: denied action ran")'))
    rep = cross.run(root, require_witness=True, select=True, jobs=2)
    assert rep.failed()
    assert [r.outcome for r in rep.results[:2]] == [cross.SURVIVED, cross.SURVIVED]
    assert rep.results[2].outcome == cross.KILLED_BY_SELF_REPORT
    assert all(not r.accepted for r in rep.results)
