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
                f.write(json.dumps({"kind": "finished", "exitstatus": 1, "missing": []}) + "\\n")
    """})
    assert r.outcome == CRASHED and rep.failed()


@pytest.mark.parametrize("message,evidence", [
    ("wrong return value", "other"),
    ("testimony: deny span missing", "testimony"),
    ("witness: denied side effect occurred", "witness"),
])
def test_require_witness_gate(tmp_path, message, evidence):
    files = {"auth.py": AUTH, "test_auth.py": f'''
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED, {message!r}
    '''}
    rep, r = outcome(tmp_path, files, require_witness=True)
    expected = KILLED if evidence == "witness" else cross.KILLED_BY_SELF_REPORT
    assert r.outcome == expected and r.evidence == evidence
    assert rep.failed() == (evidence != "witness")
    assert r.first_failure and r.failing


def test_require_witness_cli(tmp_path, capsys):
    target = project(tmp_path, {"auth.py": AUTH, "test_auth.py": '''
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    '''})
    assert cross.main(["--require-witness", target]) == 1
    assert cross.KILLED_BY_SELF_REPORT in capsys.readouterr().out
    assert cross.main([target]) == 0


def test_require_witness_rejects_testimony_before_teardown_witness(tmp_path):
    rep, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": '''
        import pytest
        from auth import DENIED, allow
        seen = []
        @pytest.fixture
        def observer(request):
            def check():
                if seen and seen[0] != DENIED:
                    pytest.fail("witness: denied side effect occurred")
            request.addfinalizer(check)
        def test_denied(observer):
            result = allow(False)
            seen.append(result)
            assert result == DENIED, "testimony: wrong return value"
    '''}, require_witness=True)
    assert r.outcome == cross.KILLED_BY_SELF_REPORT and rep.failed()
    assert r.evidence == "testimony"


def test_tooling_directories_are_not_source(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    for name in ("env", ".venv", "pkg.egg-info", ".nox"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "m.py").write_text("x = 1\n")
    (tmp_path / "env" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    # A package that only shares a name with a common venv is still source.
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "m.py").write_text("x = 1\n")
    found = sorted(os.path.relpath(p, tmp_path) for p in cross._python_files(str(tmp_path)))
    assert found == ["app.py", os.path.join("build", "m.py")]


WSGI = '''
# subpoena:enforcement_point
def app(environ, start_response):
    status = "200 OK"
    if environ["PATH_INFO"] == "/secret":
        status = "403 Forbidden"  # subpoena:enforcement
    start_response(status, [("Content-Type", "text/plain")])
    return [b"ok"]
'''


def test_webtest_status_check_is_an_assertion(tmp_path):
    _, r = outcome(tmp_path, {"wsgisite.py": WSGI, "test_wsgisite.py": """
        from webtest import TestApp
        from wsgisite import app
        def test_secret():
            TestApp(app).get("/secret", status=403)
    """})
    assert r.outcome == KILLED and r.evidence == "other"
    assert r.first_failure.startswith("Bad response: 200 OK (not 403)")


def test_webtest_default_status_check_is_no_assertion(tmp_path):
    # With no status= the test stated no expectation: webtest's own default
    # raised, so nothing the test asked for failed.
    _, r = outcome(tmp_path, {"wsgisite.py": WSGI.replace(
        '"200 OK"', '"404 Not Found"').replace('"403 Forbidden"', '"200 OK"'), "test_wsgisite.py": """
        from webtest import TestApp
        from wsgisite import app
        def test_secret():
            TestApp(app).get("/secret")
    """})
    assert r.outcome == CRASHED


# The mutant makes a handler raise, and a catch-all answers 500, as web
# frameworks do. Nothing here is a refusal the test saw: the app fell over.
CATCH_ALL = '''
TOKENS = {"ann": "tok"}


# subpoena:enforcement_point
def token_for(user):
    token = None
    if user:
        token = TOKENS.get(user, "anon")  # subpoena:enforcement
    return token


def app(environ, start_response):
    try:
        body = token_for("ann").upper().encode()
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [body]
    except Exception:
        start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
        return [b"x"]
'''


@pytest.mark.parametrize("call", ['get("/")', 'get("/", status=200)', 'get("/", status=[200, 204])'],
                         ids=["no status", "explicit status", "status list"])
def test_webtest_500_from_an_app_that_fell_over_is_a_crash(tmp_path, call):
    _, r = outcome(tmp_path, {"wsgisite.py": CATCH_ALL, "test_wsgisite.py": f"""
        from webtest import TestApp
        from wsgisite import app
        def test_home():
            TestApp(app).{call}
    """})
    assert r.outcome == CRASHED


def test_webtest_a_propagated_exception_stays_a_crash(tmp_path):
    _, r = outcome(tmp_path, {"wsgisite.py": CATCH_ALL.replace("except Exception:", "except KeyError:"),
                              "test_wsgisite.py": """
        from webtest import TestApp
        from wsgisite import app
        def test_home():
            TestApp(app).get("/")
    """})
    assert r.outcome == CRASHED


def test_webtest_a_stated_5xx_the_app_did_not_give_is_an_assertion(tmp_path):
    _, r = outcome(tmp_path, {"wsgisite.py": WSGI.replace("403 Forbidden", "503 Busy"), "test_wsgisite.py": """
        from webtest import TestApp
        from wsgisite import app
        def test_secret():
            TestApp(app).get("/secret", status=503)
    """})
    assert r.outcome == KILLED and r.first_failure.startswith("Bad response: 200 OK (not 503)")


def test_webtest_logged_app_error_stays_a_crash(tmp_path):
    # The status is what the test expected: only the app's own log line fails it.
    _, r = outcome(tmp_path, {"wsgisite.py": '''
        # subpoena:enforcement_point
        def app(environ, start_response):
            quiet = False
            if environ["PATH_INFO"] == "/secret":
                quiet = True  # subpoena:enforcement
            if not quiet:
                environ["wsgi.errors"].write("broken")
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]
    ''', "test_wsgisite.py": """
        from webtest import TestApp
        from wsgisite import app
        def test_secret():
            TestApp(app).get("/secret", status=200)
    """})
    assert r.outcome == CRASHED


def test_webtest_status_check_inside_the_code_under_test_is_a_crash(tmp_path):
    _, r = outcome(tmp_path, {"wsgisite.py": WSGI + '''

def probe():
    from webtest import TestApp
    TestApp(app).get("/secret", status=403)
''', "test_wsgisite.py": """
        from wsgisite import probe
        def test_secret():
            probe()
    """})
    assert r.outcome == CRASHED


def test_another_exception_named_apperror_is_a_crash(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        class AppError(Exception):
            pass
        def test_denied():
            if allow(False) != DENIED:
                raise AppError("Bad response: 200 OK (not 403)")
    """})
    assert r.outcome == CRASHED


# Removing a return that ends the function leaves None in its place, a value
# nobody reviewed. Where the function never gives None, None is not "enforcement
# gone": the return can carry the allow decision, and a test of the allowed path
# would "kill" the mutant with no test ever asking about a denied user.
ALLOWED_PATH_TEST = """
    from gate import allowed
    def test_admin():
        assert allowed("ann")
"""


@pytest.mark.parametrize("gate", [
    '''
        ADMINS = {"ann"}

        # subpoena:enforcement_point
        def allowed(user):
            return user in ADMINS  # subpoena:enforcement
    ''',
    '''
        ADMINS = {"ann"}

        # subpoena:enforcement_point
        def allowed(user):
            if user == "root":
                return True
            else:
                return user in ADMINS  # subpoena:enforcement
    ''',
    '''
        ADMINS = {"ann"}

        # subpoena:enforcement_point
        def allowed(user):
            try:
                return user in ADMINS  # subpoena:enforcement
            except TypeError:
                return False
    ''',
], ids=["last statement", "else branch", "try body"])
def test_a_return_that_carries_the_decision_is_invalid(tmp_path, gate):
    rep, r = outcome(tmp_path, {"gate.py": gate, "test_gate.py": ALLOWED_PATH_TEST})
    assert r.outcome == INVALID and rep.failed()
    assert "enforcement_guard" in r.output


def test_a_group_with_such_a_return_is_invalid(tmp_path):
    rep = cross.run(project(tmp_path, {"gate.py": '''
        ADMINS = {"ann"}

        # subpoena:enforcement_point
        def allowed(user):
            if user == "":
                return False  # subpoena:enforcement group=a
            return user in ADMINS  # subpoena:enforcement group=a
    ''', "test_gate.py": ALLOWED_PATH_TEST}))
    assert rep.results[-1].group == "a" and rep.results[-1].outcome == INVALID


@pytest.mark.parametrize("gate", [
    '''
        # subpoena:enforcement_point
        def denied(user):
            if user == "ann":
                return None
            return "denied"  # subpoena:enforcement
    ''',
    '''
        # subpoena:enforcement_point
        def denied(user):
            if user == "ann":
                return
            else:
                return "denied"  # subpoena:enforcement
    ''',
    '''
        # subpoena:enforcement_point
        def denied(user):
            if user != "ann":
                return "denied"  # subpoena:enforcement
    ''',
], ids=["None elsewhere", "bare return elsewhere", "the if falls off the end anyway"])
def test_a_return_where_none_means_allowed_can_be_removed(tmp_path, gate):
    _, r = outcome(tmp_path, {"gate.py": gate, "test_gate.py": """
        from gate import denied
        def test_denied():
            assert denied("bob") == "denied"
    """})
    assert r.outcome == KILLED


# A condition with no parentheses of its own can still span lines inside a
# call's brackets. Its line breaks must stay in brackets once it is forced.
MULTILINE_GUARDS = {
    "call": '''
        def denied(admin, role):
            return not admin

        # subpoena:enforcement_point
        def allow(admin):
            if denied(  # subpoena:enforcement_guard false
                admin,
                "role",
            ):
                return "denied"
            return None
    ''',
    "parenthesised": '''
        # subpoena:enforcement_point
        def allow(admin):
            if (not admin  # subpoena:enforcement_guard false
                    and admin is not None):
                return "denied"
            return None
    ''',
    "elif": '''
        def denied(admin, role):
            return not admin

        # subpoena:enforcement_point
        def allow(admin):
            if admin is None:
                return "none"
            elif denied(  # subpoena:enforcement_guard false
                admin,
                "role",
            ):
                return "denied"
            return None
    ''',
}


@pytest.mark.parametrize("shape", sorted(MULTILINE_GUARDS))
def test_multi_line_guard_is_forced(tmp_path, shape):
    _, r = outcome(tmp_path, {"auth.py": MULTILINE_GUARDS[shape], "test_auth.py": """
        from auth import allow
        def test_denied():
            assert allow(False) == "denied"
    """})
    assert r.outcome == KILLED, r.output


def test_forcing_a_multi_line_guard_keeps_every_line_where_it_was():
    data = b"if f(\n    a,\n    b,\n):\n    pass\n"
    m = cross.Mutant("x.py", "f", 1, "f(\n    a,\n    b,\n)", "False", (3, data.index(b":")), 3)
    mutated = cross.apply(data, m)
    compile(mutated, "x.py", "exec")
    assert mutated.count(b"\n") == data.count(b"\n")


# pytest-xdist runs the tests in workers: another process, started after the
# plugin took its settings out of the environment.
XDIST = ["-n", "2"]


def test_xdist_assertion_is_a_kill(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
        def test_allowed():
            assert allow(True) is None
    """}, pytest_args=XDIST)
    assert r.outcome == KILLED and r.evidence == "other", r.output
    assert r.first_failure.startswith("assert None ==")


def test_xdist_keeps_the_witness_tag(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED, "witness: it ran"
    """}, pytest_args=XDIST)
    assert r.outcome == KILLED and r.evidence == "witness", r.output


def test_xdist_survivor_stays_a_survivor(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import allow
        def test_allowed():
            assert allow(True) is None
    """}, pytest_args=XDIST)
    assert r.outcome == SURVIVED, r.output


def test_xdist_exception_in_a_worker_is_a_crash(tmp_path):
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            if allow(False) != DENIED:
                raise RuntimeError("boom")
    """}, pytest_args=XDIST)
    assert r.outcome == CRASHED, r.output


def test_xdist_dead_worker_is_a_crash_beside_a_kill(tmp_path):
    # One worker fails cleanly, the other dies: the process that died proves
    # nothing, and in a single process it would have been a crash.
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        import os, time
        from auth import DENIED, allow
        def test_dies():
            if allow(False) != DENIED:
                os._exit(3)
        def test_denied():
            time.sleep(1)
            assert allow(False) == DENIED
    """}, pytest_args=XDIST + ["--maxfail=2"])
    assert r.outcome == CRASHED, r.output


def test_xdist_never_imported_is_invalid(tmp_path):
    # No worker imports the mutated file, so the suite proved nothing about it.
    _, r = outcome(tmp_path, {"auth.py": AUTH, "test_auth.py": """
        def test_nothing():
            assert False is False
    """}, pytest_args=XDIST)
    assert r.outcome == INVALID, r.output


def test_xdist_files_loaded_in_different_workers_count(tmp_path):
    # A group across two files: neither worker need import both.
    rep = cross.run(project(tmp_path, {
        "a.py": AUTH.replace("subpoena:enforcement\n", "subpoena:enforcement group=g\n"),
        "b.py": AUTH.replace("subpoena:enforcement\n", "subpoena:enforcement group=g\n"),
        "test_a.py": """
            import time
            def test_a():
                from a import DENIED, allow
                time.sleep(0.5)
                assert allow(False) == DENIED
        """,
        "test_b.py": """
            import time
            def test_b():
                from b import DENIED, allow
                time.sleep(0.5)
                assert allow(False) == DENIED
        """}), pytest_args=XDIST + ["--dist=loadfile"])
    assert [r.outcome for r in rep.results] == [KILLED, KILLED, KILLED], [r.output for r in rep.results]


def test_xdist_report_is_kept_in_the_evidence(tmp_path):
    evidence = tmp_path / "ev"
    src = tmp_path / "src"
    src.mkdir()
    rep = cross.run(project(src, {"auth.py": AUTH, "test_auth.py": """
        from auth import DENIED, allow
        def test_denied():
            assert allow(False) == DENIED
    """}), pytest_args=XDIST, evidence_dir=str(evidence))
    assert rep.results[0].outcome == KILLED
    records = (evidence / os.path.basename(rep.results[0].evidence_file)).with_suffix(".jsonl").read_text()
    assert '"kind": "failure"' in records


def test_xdist_with_selection_says_why_it_stops(tmp_path):
    with pytest.raises(CrossError, match="drop pytest-xdist"):
        cross.run(project(tmp_path, {"auth.py": AUTH, "test_auth.py": """
            from auth import DENIED, allow
            def test_denied():
                assert allow(False) == DENIED
        """}), pytest_args=XDIST, select=True)


def test_interrupted_run_is_a_crash():
    # Cross stops no run early, so exit 2 means pytest was interrupted, xdist or not.
    records = [{"kind": "failure", "test": "t", "verdict": "assertion", "message": "m"},
               {"kind": "finished", "exitstatus": 2, "missing": []}]
    assert cross.classify(2, records, "")[0] == CRASHED
    assert cross.classify(2, records + [{"kind": "worker_finished", "missing": []}], "")[0] == CRASHED


def test_a_file_one_process_loaded_is_loaded():
    fail = {"kind": "failure", "test": "t", "verdict": "assertion", "message": "m"}
    done = {"kind": "finished", "exitstatus": 1, "missing": ["a.py", "b.py"]}
    w1 = {"kind": "worker_finished", "missing": ["b.py"]}
    w2 = {"kind": "worker_finished", "missing": ["a.py"]}
    w3 = {"kind": "worker_finished", "missing": ["a.py", "b.py"]}
    assert cross.classify(1, [fail, w1, w2, done], "")[0] == KILLED
    assert cross.classify(1, [fail, w1, w3, done], "")[0] == INVALID


def test_baseline_timeout_says_so(tmp_path):
    files = {"auth.py": AUTH, "test_auth.py": """
        import time
        def test_hang():
            time.sleep(60)
    """}
    with pytest.raises(CrossError, match=r"(?s)baseline suite is not green.*did not finish within.*--timeout"):
        cross.run(project(tmp_path, files), timeout=8)


def test_baseline_red_test_is_named(tmp_path):
    files = {"auth.py": AUTH, "test_auth.py": """
        def test_broken():
            assert 1 == 2, "the reason"
    """}
    with pytest.raises(CrossError, match=r"(?s)test_auth.py::test_broken.*the reason"):
        cross.run(project(tmp_path, files))


def test_baseline_with_no_tests_says_so(tmp_path):
    with pytest.raises(CrossError, match="collected no tests"):
        cross.run(project(tmp_path, {"auth.py": AUTH}))


def test_baseline_collection_error_is_named(tmp_path):
    files = {"auth.py": AUTH, "test_auth.py": "import no_such_module\n"}
    with pytest.raises(CrossError, match=r"could not collect.*test_auth.py"):
        cross.run(project(tmp_path, files))


@pytest.mark.parametrize("code,records,want", [
    (None, [], "did not finish within"),
    (1, [{"kind": "tampered"}], "not this run's"),
    (-9, [], "exited -9"),
    (0, [], "exited 0 without finishing"),
])
def test_baseline_reason(code, records, want):
    assert want in cross._baseline_reason(code, records, 300)
