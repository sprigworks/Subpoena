# subpoena:spec_derived (from docs/ports.md G1 and internal/cross's verdict rules)
"""subpoena.cross: each verdict and each refusal, on small projects in a
temp dir, through the real pytest runs."""

import os
import textwrap

import pytest

from subpoena import cross
from subpoena.cross import CRASHED, INVALID, KILLED, SURVIVED, TIMED_OUT, CrossError

AUTH = '''
DENIED = "denied"


# subpoena:enforcement_point
def allow(admin):
    if not admin:
        return DENIED  # subpoena:enforcement
    return None
'''

GUARDED = '''
DENIED = "denied"


# subpoena:enforcement_point
def allow(admin):
    if not admin:  # subpoena:enforcement_guard false
        return DENIED
    return None
'''


def project(tmp_path, files):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body).lstrip())
    return str(tmp_path)


def outcome(tmp_path, files, **kw):
    rep = cross.run(project(tmp_path, files), **kw)
    assert len(rep.results) == 1, rep.results
    return rep, rep.results[0]


def test_assertion_kills(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    assert r.outcome == KILLED and not rep.failed()
    assert r.evidence == "other" and r.failing == ["test_auth.py::test_denied"]


def test_weak_suite_survives_and_fails_the_run(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import allow
        def test_admin():
            assert allow(True) is None
    """})
    assert r.outcome == SURVIVED and rep.failed()


def test_tagged_assertion_is_witness_evidence(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            if allow(False) != DENIED:
                raise AssertionError("witness: refused command ran for t: pid 7 'rm -rf /'")
    """})
    assert r.outcome == KILLED and r.evidence == "witness"
    assert r.first_failure.startswith("witness: refused command ran")


def test_teardown_assertion_kills(tmp_path):
    # watch_spawns reports at teardown; that is a kill like any assertion.
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        import pytest
        from auth import DENIED, allow
        seen = []
        @pytest.fixture
        def watch(request):
            def check():
                if seen and seen[0] != DENIED:
                    raise AssertionError("witness: refused command ran for t")
            request.addfinalizer(check)
        def test_denied(watch):
            seen.append(allow(False))
    """})
    assert r.outcome == KILLED and r.evidence == "witness"


def test_other_exception_is_a_crash_not_a_kill(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import allow
        def test_denied():
            assert allow(False).upper() == "DENIED"
    """})
    assert r.outcome == CRASHED and rep.failed()


def test_assertion_after_a_crash_elsewhere_is_still_a_crash(tmp_path):
    # -x stops at the first failure, so arrange a crash first: one crash in
    # the run means the red suite is not clean evidence.
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_a_crashes():
            allow(False).upper()
        def test_b_asserts():
            assert allow(False) == DENIED
    """})
    assert r.outcome == CRASHED


def test_process_that_dies_is_a_crash(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        import os
        from auth import DENIED, allow
        def test_denied():
            if allow(False) != DENIED:
                os._exit(1)
    """})
    assert r.outcome == CRASHED


def test_hang_is_a_timeout(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import allow
        def test_denied():
            while allow(False) is None:
                pass
    """}, timeout=5)
    assert r.outcome == TIMED_OUT and rep.failed()


def test_shadowed_module_is_invalid(tmp_path):
    # The suite imports auth from elsewhere (an installed copy): the mutant in
    # the copy was never run, so it proves nothing.
    elsewhere = tmp_path.parent / (tmp_path.name + "-installed")
    elsewhere.mkdir()
    (elsewhere / "auth.py").write_text(textwrap.dedent(AUTH).lstrip())
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": f"""
        import sys
        sys.path.insert(0, {str(elsewhere)!r})
        sys.modules.pop("auth", None)
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    assert r.outcome == INVALID and rep.failed()


def test_forced_guard_kills(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": GUARDED, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    assert r.outcome == KILLED and r.mutant.bypass == "False" and r.mutant.removed == "not admin"


def test_red_baseline_is_an_error(tmp_path):
    with pytest.raises(CrossError, match="baseline suite is not green"):
        cross.run(project(tmp_path, {"auth.py": AUTH, "test_auth.py": """
            def test_red():
                assert False
        """}))


@pytest.mark.parametrize("src,want", [
    (AUTH.replace("    return None", "    return None  # subpoena:enforcement").replace(
        "# subpoena:enforcement_point\n", ""), "not a marker cross applies"),
    (AUTH.replace("# subpoena:enforcement\n", "# subpoena:enforcement because\n"), "not a marker cross applies"),
    (AUTH.replace("# subpoena:enforcement\n", "# subpoena:enforcment\n"), "not a marker cross applies"),
    (AUTH.replace("    if not admin:", "    if not admin:  # subpoena:enforcement"), "not a marker cross applies"),
    (GUARDED.replace("guard false", "guard maybe"), "not a marker cross applies"),
    (GUARDED.replace("    if not admin:  # subpoena:enforcement_guard false\n        return DENIED",
                     "    if not admin:\n        return DENIED  # subpoena:enforcement_guard false"),
     "not a marker cross applies"),
    (AUTH.replace("  # subpoena:enforcement\n", "\n"), "no subpoena:enforcement statement"),
    (AUTH.replace("# subpoena:enforcement_point\n", "# subpoena:enforcement_point\n\n"), "not a marker cross applies"),
], ids=["outside a point", "trailing text", "misspelt", "on an if", "bad guard value", "guard off an if",
        "no statement marker", "point not above the def"])
def test_markers_that_take_no_effect_are_errors(tmp_path, src, want):
    project(tmp_path, {"auth.py": src})
    with pytest.raises(CrossError, match=want):
        cross.find_mutants(str(tmp_path))


def test_apply_keeps_line_numbers():
    src = "def f():\n    return g(\n        1,\n    )  # x\n    y = 2\n"
    m = cross.Mutant("f.py", "f", 2, "", "", (2, 4), (4, 5))
    out = cross.apply(src, m)
    assert out.splitlines()[1] == "    pass" and out.count("\n") == src.count("\n")
    assert out.splitlines()[4] == "    y = 2"


def test_command_line_exit_codes(tmp_path, capsys):
    root = project(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    assert cross.main([root]) == 0
    out = capsys.readouterr().out
    assert "1 enforcement point(s), 1 mutant(s)" in out and "enforcement-mutant-killed allow" in out
    os.remove(os.path.join(root, "test_auth.py"))
    with open(os.path.join(root, "test_auth.py"), "w") as f:
        f.write("from auth import allow\ndef test_admin():\n    assert allow(True) is None\n")
    assert cross.main([root]) == 1
