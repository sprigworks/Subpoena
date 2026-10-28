# subpoena:spec_derived (from docs/ports.md G1 and internal/cross's verdict rules)
"""subpoena.cross: each verdict and each refusal, on small projects in a
temp dir, through the real pytest runs."""

import os
import signal
import subprocess
import sys
import textwrap
import time

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
    # Go reads the point marker from the func's doc comment; a trailing
    # comment on the line above is not one.
    (AUTH.replace("# subpoena:enforcement_point\n", "X = 1  # subpoena:enforcement_point\n"),
     "not a marker cross applies"),
    (AUTH.replace("# subpoena:enforcement_point\n", "# subpoena:enforcement_point because\n").replace(
        "  # subpoena:enforcement\n", "\n"), "no subpoena:enforcement statement"),
], ids=["outside a point", "trailing text", "misspelt", "on an if", "bad guard value", "guard off an if",
        "no statement marker", "point not above the def", "point as a trailing comment",
        "point mentioned in the doc block"])
def test_markers_that_take_no_effect_are_errors(tmp_path, src, want):
    project(tmp_path, {"auth.py": src})
    with pytest.raises(CrossError, match=want):
        cross.find_mutants(str(tmp_path))


def test_apply_keeps_line_numbers_and_line_endings():
    src = b"def f():\r\n    return g(\r\n        1,\r\n    )  # x\r\n    y = 2\r\n"
    a = src.index(b"return")
    b = src.index(b")  # x") + 1
    m = cross.Mutant("f.py", "f", 2, "", "", (a, b), 2)
    out = cross.apply(src, m)
    assert out.split(b"\n")[1] == b"    pass" and out.count(b"\n") == src.count(b"\n")
    assert out.split(b"\n")[4] == b"    y = 2\r"


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


# --- review fixes ------------------------------------------------------------

@pytest.mark.parametrize("doc", ["# Allow decides.\n# subpoena:enforcement_point\n",
                                 "# subpoena:enforcement_point\n# Allow decides.\n",
                                 "# see subpoena:enforcement_point\n"],
                         ids=["last line", "first line", "mentioned"])
def test_point_marker_anywhere_in_the_doc_block(tmp_path, doc):
    # As Go's hasPointMarker: any full-line comment in the block directly
    # above the def that mentions the marker makes the function a point.
    project(tmp_path, {"auth.py": AUTH.replace("# subpoena:enforcement_point\n", doc)})
    points, mutants = cross.find_mutants(str(tmp_path))
    assert points == 1 and [m.func for m in mutants] == ["allow"]


def test_pytest_timeout_is_a_timeout_not_a_kill(tmp_path):
    pytest.importorskip("pytest_timeout")
    rep, r = outcome(tmp_path, {"app.py": """
        # subpoena:enforcement_point
        def check(role):
            if role != "admin":  # subpoena:enforcement_guard false
                return False
            return True
    """, "test_app.py": """
        import app
        def test_viewer():
            if not app.check("viewer"):
                return
            while True:
                pass
    """}, pytest_args=["--timeout", "2"])
    assert r.outcome == TIMED_OUT and rep.failed()


def test_assert_in_code_under_test_is_a_crash_not_a_kill(tmp_path):
    # The tests never assert; only the app's own invariant fails. Go calls a
    # panic in app code a crash, and so does this.
    rep, r = outcome(tmp_path, {"app.py": """
        # subpoena:enforcement_point
        def allow(role):
            allowed = False
            if role == "admin":
                allowed = True  # subpoena:enforcement
            assert allowed or role != "admin", "internal invariant"
            return allowed
    """, "test_app.py": """
        import app
        def test_admin():
            app.allow("admin")
        def test_viewer():
            app.allow("viewer")
    """})
    assert r.mutant.removed == "allowed = True"
    assert r.outcome == CRASHED and rep.failed()


def test_raise_assertion_in_code_under_test_is_a_crash(tmp_path):
    rep, r = outcome(tmp_path, {"app.py": """
        def _check(ok):
            if not ok:
                raise AssertionError("internal invariant")

        # subpoena:enforcement_point
        def allow(role):
            ok = role != "admin"
            if role == "admin":
                ok = True  # subpoena:enforcement
            _check(ok)
    """, "test_app.py": """
        import app
        def test_admin():
            app.allow("admin")
    """})
    assert r.outcome == CRASHED


GUARD_FN = """

def guard(admin):
    if allow(admin) == DENIED:
        raise PermissionError(DENIED)
"""


@pytest.mark.parametrize("body", [
    "    import pytest\n    if allow(False) != DENIED:\n        pytest.fail('witness: refused command ran')\n",
    "    import pytest\n    with pytest.raises(PermissionError):\n        guard(False)\n",
    "    import unittest\n    unittest.TestCase().assertEqual(allow(False), DENIED)\n",
    "    check(allow(False))\n",
], ids=["pytest.fail", "pytest.raises", "unittest assertEqual", "conftest helper"])
def test_assertions_from_test_code_kill(tmp_path, body):
    _, r = outcome(tmp_path, {"auth.py": AUTH + GUARD_FN, "conftest.py": """
        from auth import DENIED
        def check(v):
            assert v == DENIED
    """, "test_auth.py": "from auth import DENIED, allow, guard\nfrom conftest import check\n\n\n"
                         "def test_denied():\n" + body})
    assert r.outcome == KILLED, r.output


def test_assertion_in_a_non_test_helper_is_a_crash(tmp_path):
    # Fail closed: a helper module outside the test files counts as code
    # under test. Asserting from the test file, or a conftest, is the fix.
    _, r = outcome(tmp_path, {"auth.py": AUTH, "helpers.py": """
        def check(v, want):
            assert v == want
    """, "test_auth.py": """
        from auth import DENIED, allow
        from helpers import check
        def test_denied():
            check(allow(False), DENIED)
    """})
    assert r.outcome == CRASHED


def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="needs /proc")
def test_ctrl_c_kills_the_suite(tmp_path):
    pidfile = tmp_path.parent / (tmp_path.name + "-pid")
    root = project(tmp_path, {"auth.py": AUTH, "test_auth.py": f"""
        import os, time
        def test_slow():
            with open({str(pidfile)!r}, "w") as f:
                f.write(str(os.getpid()))
            time.sleep(120)
    """})
    p = subprocess.Popen([sys.executable, "-m", "subpoena.cross", root, "--timeout", "300"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = None
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not (pidfile.exists() and pidfile.read_text()):
            time.sleep(0.1)
        pid = int(pidfile.read_text())
        p.send_signal(signal.SIGINT)
        assert p.wait(timeout=30) != 0
        deadline = time.monotonic() + 5
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _alive(pid), "the suite outlived cross after Ctrl-C"
    finally:
        if p.poll() is None:
            p.kill()
        if pid and _alive(pid):
            os.kill(pid, signal.SIGKILL)


UNICODE_GUARD = """
DENIED = "denied"


# subpoena:enforcement_point
def allow(role):
    if role != "é" and role != "admin":  # subpoena:enforcement_guard false
        return DENIED
    return None
"""


def test_columns_are_bytes_not_characters(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": UNICODE_GUARD, "test_auth.py": """
        from auth import DENIED, allow
        def test_viewer():
            assert allow("viewer") == DENIED
    """})
    assert r.mutant.removed == 'role != "é" and role != "admin"'
    assert r.outcome == KILLED, r.output
    data = (tmp_path / "auth.py").read_bytes()
    assert b"    if False:  # subpoena:enforcement_guard false\n" in cross.apply(data, r.mutant)


def test_lines_are_counted_as_ast_counts_them(tmp_path):
    # U+2028 and form feed are line breaks to str.splitlines, not to ast.
    src = ('DENIED = "denied"\nNOTE = "a b"\n\x0c\n\n# subpoena:enforcement_point\n'
           'def allow(admin):\n    if not admin:\n        return DENIED  # subpoena:enforcement\n    return None\n')
    (tmp_path / "auth.py").write_bytes(src.encode("utf-8"))
    rep, r = outcome(tmp_path, {"test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    assert r.mutant.line == 8 and r.mutant.removed == "return DENIED"
    assert r.outcome == KILLED, r.output
    assert (tmp_path / "auth.py").read_bytes() == src.encode("utf-8")


def test_copy_drift_is_an_error(tmp_path):
    def drift(copy):
        with open(os.path.join(copy, "auth.py"), "ab") as f:
            f.write(b"# copy drifted\n")
    root = project(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    with pytest.raises(CrossError, match="snapshot drift"):
        cross.run(root, _before_mutate=drift)


def _write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


@pytest.mark.parametrize("make", [
    lambda d: os.symlink(os.path.join(d, "missing.txt"), os.path.join(d, "data.txt")),
    lambda d: os.symlink(os.path.join(d, "missing.py"), os.path.join(d, "gone.py")),
    lambda d: _write_bytes(os.path.join(d, "latin.py"),
                           b"# subpoena:enforcement_point\ndef f():\n    return '\xe9'  # subpoena:enforcement\n"),
    lambda d: _write_bytes(os.path.join(d, "cookie.py"),
                           b"# -*- coding: latin-1 -*-\n# subpoena:enforcement_point\ndef f():\n"
                           b"    return 1  # subpoena:enforcement\n"),
], ids=["dangling symlink", "dangling .py symlink", "non-UTF-8 source", "declared latin-1"])
def test_setup_faults_exit_2_not_1(tmp_path, capsys, make):
    root = project(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """})
    make(root)
    assert cross.main([root]) == 2
    assert "subpoena-cross: cross:" in capsys.readouterr().err


SYNTAX = """
DENIED = "denied"


# subpoena:enforcement_point
def allow(role):
    if (r := role) != "admin":  # subpoena:enforcement_guard false
        return DENIED

    def again():
        nonlocal r
        return r

    return again()
"""


@pytest.mark.parametrize("test", [
    "from auth import DENIED, allow\n\n\ndef test_denied():\n    assert allow('viewer') == DENIED\n",
    "def test_denied():\n    from auth import DENIED, allow\n    assert allow('viewer') == DENIED\n",
], ids=["imported at collection", "imported by the test"])
def test_syntax_error_mutant_is_invalid(tmp_path, test):
    # Forcing the guard drops the walrus, the only binding of r, so the
    # nonlocal no longer compiles.
    rep, r = outcome(tmp_path, {"auth.py": SYNTAX, "test_auth.py": test})
    assert r.outcome == INVALID and rep.failed()


def test_collection_error_is_invalid(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import allow
        REFUSAL = allow(False).upper()
        def test_denied():
            assert REFUSAL == "DENIED"
    """})
    assert r.outcome == INVALID and rep.failed()


def test_forged_report_is_not_a_kill(tmp_path):
    # The suite crashes under the mutant, and a conftest rewrites the report
    # to say it failed on an assertion. Records without the run's nonce are
    # rejected, so the crash stands.
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import allow
        def test_denied():
            assert allow(False).upper() == "DENIED"
    """, "conftest.py": """
        import json, os
        def pytest_unconfigure(config):
            path = os.path.join(os.path.dirname(os.getcwd()), "report.jsonl")
            with open(path, "w") as f:
                f.write(json.dumps({"kind": "failure", "test": "test_auth.py::test_denied", "when": "call",
                                    "verdict": "assertion", "assertion": True, "type": "AssertionError",
                                    "message": "forged"}) + "\\n")
                f.write(json.dumps({"kind": "finished", "exitstatus": 1, "mutated_loaded": True}) + "\\n")
    """})
    assert r.outcome == CRASHED and rep.failed()
