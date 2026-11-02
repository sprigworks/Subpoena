# subpoena:impl_derived
# subpoena:pure_logic
"""registry-drift over Python tests: the cases of internal/lint/drift_test.go,
written after reading internal/lint/drift.go."""
import subprocess
import sys

import pytest

from subpoena.lint import LintError, diff_registry, main, registry_drift

ATTRS_V1 = '''groups:
  - id: registry.x
    type: attribute_group
    brief: x
    attributes:
      - id: x.alpha
        type: string
        stability: stable
        brief: first
        annotations:
          tier: all
      - id: x.beta
        type: int
        stability: stable
        brief: second
'''

SPANS_V1 = '''groups:
  - id: span.x.work
    type: span
    name: x.work
    span_kind: internal
    stability: stable
    brief: work
    attributes:
      - ref: x.alpha
        requirement_level: required
  - id: span.x.rest
    type: span
    name: x.rest
    span_kind: internal
    stability: stable
    brief: rest
'''

SEMCONV_V1 = '''from typing import Final
SPAN_X_REST: Final = "x.rest"
SPAN_X_WORK: Final = "x.work"
ATTR_X_ALPHA: Final = "x.alpha"
ATTR_X_BETA: Final = "x.beta"
'''

# V2: x.gamma is new.
ATTRS_V2 = ATTRS_V1 + '''      - id: x.gamma
        type: boolean
        stability: stable
        brief: third
'''
SEMCONV_V2 = SEMCONV_V1 + 'ATTR_X_GAMMA: Final = "x.gamma"\n'


def source(body, imports='from generated.python import semconv'):
    return f'# subpoena:impl_derived\n{imports}\n\n\ndef test_a():\n' + ''.join(
        f'    {line}\n' for line in body.splitlines())


class Repo:
    def __init__(self, path):
        self.dir = path
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'drift@example.invalid')
        self.git('config', 'user.name', 'drift')
        self.git('config', 'commit.gpgsign', 'false')
        self.write({
            'registry/model/attributes.yaml': ATTRS_V1,
            'registry/model/spans.yaml': SPANS_V1,
            'generated/python/semconv.py': SEMCONV_V1,
            'test_a.py': source('_ = semconv.SPAN_X_WORK\n_ = semconv.ATTR_X_ALPHA'),
        })
        self.commit('base')

    def git(self, *args):
        subprocess.run(['git', '-C', str(self.dir), *args], check=True, capture_output=True)

    def write(self, files):
        for rel, text in files.items():
            path = self.dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '-m', message)

    def drift(self, base=''):
        return registry_drift(self.dir, base)


@pytest.fixture
def repo(tmp_path):
    return Repo(tmp_path)


def test_clean_tree(repo):
    assert repo.drift() == []


def test_new_attribute_referenced_by_changed_test(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_a.py': source('_ = semconv.SPAN_X_WORK\n_ = semconv.ATTR_X_GAMMA')})
    [f] = repo.drift()
    assert (f.path.name, f.line, f.rule) == ('test_a.py', 7, 'registry-drift')
    for want in ('semconv.ATTR_X_GAMMA', '"x.gamma"', 'new', 'HEAD'):
        assert want in f.message


def test_registry_change_without_test_change_is_quiet(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2})
    assert repo.drift() == []


def test_test_change_without_registry_change_is_quiet(repo):
    repo.write({'test_a.py': source('_ = semconv.SPAN_X_WORK\n_ = semconv.ATTR_X_ALPHA\n_ = 1')})
    assert repo.drift() == []


def test_changed_test_referencing_only_unchanged_identifiers_is_quiet(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_a.py': source('_ = semconv.SPAN_X_REST\n_ = semconv.ATTR_X_ALPHA')})
    assert repo.drift() == []


def test_changed_attribute_and_changed_span(repo):
    attrs = ATTRS_V1.replace('type: int', 'type: string', 1)  # x.beta changes type
    spans = SPANS_V1.replace('      - ref: x.alpha\n        requirement_level: required\n',
                             '      - ref: x.alpha\n        requirement_level: required\n'
                             '      - ref: x.beta\n        requirement_level: recommended\n', 1)
    repo.write({'registry/model/attributes.yaml': attrs, 'registry/model/spans.yaml': spans,
                'test_a.py': source('_ = semconv.SPAN_X_WORK\n_ = semconv.ATTR_X_BETA\n_ = semconv.SPAN_X_REST')})
    found = repo.drift()
    assert len(found) == 2 and found[0].line < found[1].line
    text = '\n'.join(f.message for f in found)
    assert 'span "x.work"' in text and 'attribute "x.beta"' in text and 'changed' in text
    assert 'x.rest' not in text


def test_ignores_prose_only_changes(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V1.replace('brief: first', 'brief: much better', 1),
                'test_a.py': source('_ = semconv.ATTR_X_ALPHA\n_ = 1')})
    assert repo.drift() == []


def test_tier_annotation_change_counts(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V1.replace('tier: all', 'tier: test', 1),
                'test_a.py': source('_ = semconv.ATTR_X_ALPHA\n_ = 1')})
    [f] = repo.drift()
    assert 'attribute "x.alpha"' in f.message and 'changed' in f.message


def test_untracked_files(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'tests/test_new.py': source('_ = semconv.ATTR_X_GAMMA')})
    [f] = repo.drift()
    assert f.path.name == 'test_new.py' and '"x.gamma"' in f.message


def test_ignores_string_literals(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_a.py': source('_ = "x.gamma"')})
    assert repo.drift() == []


def test_import_forms(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_alias.py': source('_ = sc.ATTR_X_GAMMA', 'from generated.python import semconv as sc'),
                'test_name.py': source('_ = GAMMA', 'from generated.python.semconv import ATTR_X_GAMMA as GAMMA'),
                'test_local.py': '# subpoena:impl_derived\n\ndef test_a():\n    import semconv\n    _ = semconv.ATTR_X_GAMMA\n'})
    found = repo.drift()
    assert sorted(f.path.name for f in found) == ['test_alias.py', 'test_local.py', 'test_name.py']


def test_unresolvable_origins_count_by_constant_name(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_star.py': source('_ = ATTR_X_GAMMA', 'from generated.python.semconv import *'),
                'test_spec.py': source('_ = semconv.ATTR_X_GAMMA',
                                       'import importlib.util\nspec = importlib.util.spec_from_file_location("s", "s.py")\n'
                                       'semconv = importlib.util.module_from_spec(spec)'),
                'test_other.py': source('_ = ATTR_X_GAMMA', 'from elsewhere import ATTR_X_GAMMA')})
    found = repo.drift()
    assert sorted(f.path.name for f in found) == ['test_spec.py', 'test_star.py']


def test_yaml_1_1_keys_do_not_crash(repo):
    attrs = ATTRS_V1.replace('          tier: all\n', '          tier: all\n          on: yes\n', 1)
    repo.write({'registry/model/attributes.yaml': attrs, 'test_a.py': source('_ = semconv.ATTR_X_ALPHA\n_ = 1')})
    [f] = repo.drift()
    assert 'attribute "x.alpha"' in f.message


@pytest.mark.parametrize('text', [
    'groups: [\n',                                   # does not parse
    'groups:\n  - id: a\n    type: attribute_group\n    attributes:\n      - id: x\n        since: 2024-13-45\n',
    'groups: {id: a}\n',                             # groups is not a list
    'groups:\n  - just a string\n',                  # a group is not a mapping
    'groups:\n  - id: a\n    type: attribute_group\n    attributes: x.alpha\n',
    '- not a mapping\n',
])
def test_malformed_registry_is_an_error_never_clean(repo, text):
    repo.write({'registry/model/attributes.yaml': text})
    with pytest.raises(LintError):
        repo.drift()


def test_only_python_test_files(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'service.py': 'from generated.python import semconv\n_ = semconv.ATTR_X_GAMMA\n'})
    assert repo.drift() == []


def test_base_ref_uses_merge_base(repo):
    repo.git('checkout', '-q', '-b', 'feature')
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_a.py': source('_ = semconv.ATTR_X_GAMMA')})
    repo.commit('feature')
    assert repo.drift() == []  # committed: nothing against HEAD
    [f] = repo.drift('main')
    assert 'against main' in f.message
    repo.git('checkout', '-q', 'main')
    repo.write({'registry/model/other.yaml': 'groups:\n  - id: registry.z\n    type: attribute_group\n    brief: z\n'
                '    attributes:\n      - id: x.zeta\n        type: string\n        stability: stable\n        brief: z\n'})
    repo.commit('main moves')
    repo.git('checkout', '-q', 'feature')
    assert len(repo.drift('main')) == 1


def test_errors(tmp_path_factory, repo):
    with pytest.raises(LintError):
        registry_drift(tmp_path_factory.mktemp('outside'))  # not a repository: an error, never clean
    with pytest.raises(LintError, match='unknown base'):
        repo.drift('no-such-ref')
    repo.write({'registry/model/attributes.yaml': 'groups: [\n'})
    with pytest.raises(LintError):
        repo.drift()


def test_missing_generated_module_is_an_error(repo):
    repo.write({'registry/model/attributes.yaml': ATTRS_V2})
    (repo.dir / 'generated/python/semconv.py').unlink()
    with pytest.raises(LintError, match='make generate'):
        repo.drift()


def test_diff_registry_only_reports_new_and_changed():
    base = {'attribute': {'a': '1', 'b': '1', 'gone': '1'}, 'span': {'s': '1'}}
    head = {'attribute': {'a': '1', 'b': '2', 'c': '1'}, 'span': {'s': '1', 't': '1'}}
    assert diff_registry(base, head) == [('attribute', 'b', False), ('attribute', 'c', True), ('span', 't', True)]


def test_cli_exit_codes(repo, capsys):
    assert main(['registry-drift', str(repo.dir)]) == 0
    assert 'clean' in capsys.readouterr().out
    repo.write({'registry/model/attributes.yaml': ATTRS_V2, 'generated/python/semconv.py': SEMCONV_V2,
                'test_a.py': source('_ = semconv.ATTR_X_GAMMA')})
    assert main(['registry-drift', str(repo.dir)]) == 1
    assert main(['registry-drift', '--base', 'no-such-ref', str(repo.dir)]) == 2
    done = subprocess.run([sys.executable, '-m', 'subpoena.lint', 'registry-drift', str(repo.dir)],
                          capture_output=True, text=True)
    assert done.returncode == 1 and 'registry-drift:' in done.stdout


def test_cli_unexpected_failure_is_a_load_error(repo, monkeypatch, capsys):
    # Exit 1 is findings, which CI lets a label waive; a crash must be 2.
    import subpoena.lint as lint
    monkeypatch.setattr(lint, 'registry_drift', lambda *a: 1 / 0)
    assert main(['registry-drift', str(repo.dir)]) == 2
    assert 'ZeroDivisionError' in capsys.readouterr().err
