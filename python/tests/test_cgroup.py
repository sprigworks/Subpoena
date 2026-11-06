# subpoena:impl_derived (ported from pkg/cgroup/cgroup_test.go, after reading it)
"""Session cgroups: create refuses bad trace IDs and roots that are not
cgroup v2, a stand-in directory works for the write path, placement failure
is reported without losing the process, and session_trace reads
/proc/<pid>/cgroup. The real-cgroup cases skip without a writable cgroup v2
hierarchy (fail instead with SUBPOENA_CGROUP_REQUIRE=1)."""

import os
import sys
import time

import pytest

from subpoena import cgroup
from subpoena.cgroup import CgroupError, Manager, root_base, session_trace

TID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def stand_in(tmp_path):
    root = tmp_path / "subpoena"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu memory pids\n")
    return Manager(str(root))


def test_from_env(monkeypatch):
    monkeypatch.delenv(cgroup.ENV_ROOT, raising=False)
    assert cgroup.from_env().root == cgroup.DEFAULT_ROOT
    monkeypatch.setenv(cgroup.ENV_ROOT, "/x/y/z")
    m = cgroup.from_env()
    assert m.root == "/x/y/z" and root_base(m.root) == "z"
    assert root_base("/a/b/") == "b"


def test_create_starts_processes_in_the_group(stand_in):
    g = stand_in.create(TID.upper())
    assert (g.trace_id, g.dir, g.path, g.real) == (TID, os.path.join(stand_in.root, TID), "subpoena/" + TID, False)
    p, place_err = g.start(["sleep", "0.1"])
    try:
        assert place_err is None
        assert g.procs() == [p.pid]
        with open(os.path.join(g.dir, "cgroup.procs")) as f:
            assert f.read() == f"{p.pid}\n"
    finally:
        p.wait()
    g.remove()
    assert not os.path.exists(g.dir)


def test_create_is_idempotent_for_the_same_trace(stand_in):
    stand_in.create(TID)
    stand_in.create(TID)


@pytest.mark.parametrize("tid", ["", "abc", "../../../tmp/pwn", TID[:31], TID + "0", "g" * 32, None])
def test_create_refuses_bad_trace_ids(stand_in, tid):
    with pytest.raises(CgroupError):
        stand_in.create(tid)
    assert os.listdir(stand_in.root) == ["cgroup.controllers"]


def test_create_refuses_a_plain_directory_root(tmp_path):
    root = tmp_path / "subpoena"
    root.mkdir()
    with pytest.raises(CgroupError, match="not a cgroup v2 directory"):
        Manager(str(root)).create(TID)
    assert not (root / TID).exists()


def test_create_does_not_leave_a_root_it_created_but_cannot_use(tmp_path):
    m = Manager(str(tmp_path / "subpoena"))
    with pytest.raises(CgroupError):
        m.create(TID)
    assert not os.path.exists(m.root)


def test_create_fails_when_the_parent_is_missing_or_root_empty(tmp_path):
    with pytest.raises(CgroupError):
        Manager(str(tmp_path / "no" / "such" / "parent")).create(TID)
    with pytest.raises(CgroupError):
        Manager("").create(TID)


def test_stand_in_gets_a_procs_file_and_no_id(stand_in):
    g = stand_in.create(TID)
    assert os.path.isfile(os.path.join(g.dir, "cgroup.procs"))
    assert not g.real
    with pytest.raises(CgroupError):
        g.id()


def test_start_reports_placement_failure_without_losing_the_process(stand_in):
    g = stand_in.create(TID)
    procs = os.path.join(g.dir, "cgroup.procs")
    os.remove(procs)
    os.mkdir(procs)  # unopenable for writing
    p, place_err = g.start(["true"])
    p.wait()
    assert place_err, "placement failure must be reported so the caller can fall back to lineage"


def test_start_reports_start_failure(stand_in):
    g = stand_in.create(TID)
    with pytest.raises(OSError):
        g.start(["/definitely/not/a/binary"])


def test_start_refuses_a_preexec_fn(stand_in):
    with pytest.raises(TypeError):
        stand_in.create(TID).start(["true"], preexec_fn=lambda: None)


HYBRID = "12:pids:/\n4:memory:/user\n1:name=systemd:/\n0::/subpoena/" + TID.upper() + "\n"


@pytest.mark.parametrize("text,base,want", [
    ("0::/subpoena/" + TID + "\n", "subpoena", TID),
    (HYBRID, "subpoena", TID),
    ("0::/subpoena/" + TID + "/inner/leaf\n", "subpoena", TID),
    ("0::/system.slice/subpoena/" + TID + "\n", "subpoena", TID),
    ("0::/other/" + TID + "\n", "subpoena", None),
    ("0::/subpoena/web\n", "subpoena", None),
    ("0::/" + TID + "\n", "subpoena", None),
    ("0::/subpoena\n", "subpoena", None),
    ("0::/lab/" + TID + "\n", "lab", TID),
    ("0::/subpoena/a/subpoena/" + TID + "\n", "subpoena", None),
    ("0::/subpoena/" + TID + "/a/subpoena/" + "b" * 32 + "\n", "subpoena", TID),
    ("not a cgroup file", "subpoena", None),
    ("", "subpoena", None),
], ids=["v2 line", "hybrid, any line", "nested under the session", "under a slice", "other base",
        "base but not a trace ID", "trace ID without the base", "base is last element", "custom base",
        "a session built under the root is not one", "the real session wins over one nested in it",
        "garbage", "empty"])
def test_session_trace(text, base, want):
    assert session_trace(text, base) == want


@pytest.fixture
def real_group():
    uniq = f"subpoena-pytest-{os.getpid()}"
    candidates = [os.environ[cgroup.ENV_ROOT]] if os.environ.get(cgroup.ENV_ROOT) else []
    candidates += [f"/sys/fs/cgroup/unified/{uniq}", f"/sys/fs/cgroup/{uniq}"]
    errs = []
    for root in candidates:
        try:
            g = Manager(root).create(TID)
            break
        except CgroupError as e:
            errs.append(str(e))
    else:
        msg = "no writable cgroup v2 hierarchy: " + "; ".join(errs)
        if os.environ.get("SUBPOENA_CGROUP_REQUIRE") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    assert g.real, f"{g.dir} is not on a cgroup2 filesystem"
    yield g, root
    try:
        g.remove()
    except OSError:
        pass
    if not os.environ.get(cgroup.ENV_ROOT):
        try:
            os.rmdir(root)
        except OSError:
            pass


def _in_group(pid, root):
    with open(f"/proc/{pid}/cgroup") as f:
        return session_trace(f.read(), root_base(root))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux cgroups")
def test_real_cgroup(real_group):
    g, root = real_group
    p, place_err = g.start(["sleep", "0.5"])
    late = None
    try:
        assert place_err is None
        assert _in_group(p.pid, root) == TID
        assert g.procs() == [p.pid], "the child placed itself; no PID was written for it"
        assert g.id() == os.stat(g.dir).st_ino != 0
        import subprocess
        late = subprocess.Popen(["sleep", "0.5"])
        g.add(late.pid)
        assert sorted(g.procs()) == sorted([p.pid, late.pid])
        with pytest.raises(OSError):
            g.remove()
    finally:
        for q in (p, late):
            if q is not None:
                q.kill()
                q.wait()
    deadline = time.time() + 2
    while time.time() < deadline:
        try:
            g.remove()
            return
        except OSError:
            time.sleep(0.01)
    pytest.fail("empty cgroup could not be removed")


@pytest.mark.skipif(not os.path.isfile("/sys/fs/cgroup/cgroup.controllers"), reason="no cgroup v2 mount")
def test_cgroupfs_detection_and_id_on_the_mount():
    # Read-only checks, so they run where a group cannot be created.
    assert cgroup._is_cgroupfs("/sys/fs/cgroup")
    assert cgroup._cgroup_id("/sys/fs/cgroup") == os.stat("/sys/fs/cgroup").st_ino
    assert not cgroup._is_cgroupfs(os.path.dirname(__file__))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux cgroups")
def test_child_places_itself_before_exec(stand_in):
    # The atomic path, on a stand-in posing as real: the child writes "0"
    # (itself) to cgroup.procs between fork and exec, and the parent writes
    # nothing.
    g = stand_in.create(TID)
    g.real = True
    p, place_err = g.start(["true"])
    assert p.wait() == 0 and place_err is None
    with open(os.path.join(g.dir, "cgroup.procs")) as f:
        assert f.read() == "0\n"
