"""One cgroup v2 per agent session, named with the session's trace ID, and a
way to start the session's child processes inside it (docs/ports.md, W2). A
port of pkg/cgroup.

The cgroup is the correlation key between a trace and the processes it
caused: unlike parent-process lineage it survives double forks and
reparenting, and the witness reads it on the kernel side, so the application
cannot misreport it.

    g = cgroup.from_env().create(trace_id)
    proc, place_err = g.start(["sh", "-c", cmd])
    if place_err:   # started, but not in the group: record lineage correlation
        ...

Creating a cgroup needs a writable cgroup v2 hierarchy (root, or a subtree
delegated by systemd). Errors are CgroupError; callers fall back to lineage
correlation and record that they did.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import re
import subprocess
import sys
from typing import Any, List, Optional, Sequence, Tuple, Union

ENV_ROOT = "SUBPOENA_CGROUP_ROOT"
DEFAULT_ROOT = "/sys/fs/cgroup/subpoena"

# cgroup.controllers exists in every cgroup v2 directory, root or not: it is
# how cgroupfs is told from a plain directory (the tmpfs /sys/fs/cgroup of a
# v1 or hybrid host, where mkdir would "work" and isolate nothing).
_CONTROLLERS = "cgroup.controllers"
_PROCS = "cgroup.procs"
_CGROUP2_SUPER_MAGIC = 0x63677270
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


class CgroupError(OSError):
    pass


def root_base(root: str) -> str:
    """The last element of root. A process belongs to a session cgroup when
    its /proc/<pid>/cgroup path has the form .../<root base>/<trace id>."""
    return os.path.basename(os.path.normpath(root))


class Manager:
    """Creates session cgroups under root. root must be a cgroup v2
    directory. For tests it may instead be a plain directory holding a
    cgroup.controllers file: a deliberate stand-in, in which create makes the
    cgroup.procs file cgroupfs would have made."""

    def __init__(self, root: str):
        self.root = root

    def create(self, trace_id: str) -> "Group":
        """Make <root>/<trace_id>, creating root if it is missing. Refuses
        unless root has a cgroup.controllers file, so a misconfigured root
        never yields a plain directory that looks like a cgroup."""
        tid = trace_id.lower() if isinstance(trace_id, str) else ""
        if not _TRACE_ID.match(tid):
            raise CgroupError(f"cgroup: {trace_id!r} is not a 32-digit hex trace ID")
        if not self.root:
            raise CgroupError("cgroup: no root configured")
        created_root = False
        try:
            os.mkdir(self.root, 0o755)
            created_root = True
        except FileExistsError:
            pass
        except OSError as e:
            raise CgroupError(f"cgroup: create root: {e}") from e
        if not os.path.exists(os.path.join(self.root, _CONTROLLERS)):
            if created_root:
                _quiet(os.rmdir, self.root)
            raise CgroupError(f"cgroup: {self.root} is not a cgroup v2 directory (no {_CONTROLLERS})")
        d = os.path.join(self.root, tid)
        try:
            os.mkdir(d, 0o755)
        except FileExistsError:
            pass
        except OSError as e:
            raise CgroupError(f"cgroup: create {d}: {e}") from e
        procs = os.path.join(d, _PROCS)
        if not os.path.exists(procs):
            if _is_cgroupfs(d):
                _quiet(os.rmdir, d)  # cgroupfs always provides cgroup.procs
                raise CgroupError(f"cgroup: {d} has no {_PROCS}")
            try:
                open(procs, "w").close()  # stand-in: the file cgroupfs would have made
            except OSError as e:
                _remove_tree(d)
                raise CgroupError(f"cgroup: stand-in {procs}: {e}") from e
        return Group(d, tid, root_base(self.root), _is_cgroupfs(d))


def from_env() -> Manager:
    """A Manager rooted at $SUBPOENA_CGROUP_ROOT, or DEFAULT_ROOT."""
    return Manager(os.environ.get(ENV_ROOT) or DEFAULT_ROOT)


class Group:
    """One session's cgroup."""

    def __init__(self, dir: str, trace_id: str, base: str, real: bool):
        self.dir, self.trace_id, self._base, self.real = dir, trace_id, base, real

    @property
    def path(self) -> str:
        """The tail by which /proc/<pid>/cgroup names the group:
        "<root base>/<trace id>"."""
        return f"{self._base}/{self.trace_id}"

    def id(self) -> int:
        """The kernel's 64-bit cgroup ID, what eBPF witnesses report, read
        with name_to_handle_at as bpftrace's cgroupid() does. A stand-in has
        none."""
        if not self.real:
            raise CgroupError(f"cgroup: {self.dir} is a stand-in directory, not a cgroup")
        return _cgroup_id(self.dir)

    def start(self, args: Union[str, Sequence[str]], **popen: Any) -> "Tuple[subprocess.Popen, Optional[str]]":
        """Start a process inside the group: subprocess.Popen(args, **popen).

        On a real cgroup the child moves itself into the group after fork and
        before exec, so no instruction of the program runs outside it. If that
        fails, or the group is a stand-in, the process is started normally and
        its PID written to cgroup.procs; a process it forks in the instant
        before the write would escape.

        Returns (process, place_err). A failure to start raises. place_err is
        set when the process started but could not be placed: the caller must
        then treat the session as lineage-correlated.
        """
        if "preexec_fn" in popen:
            raise TypeError("cgroup: start places the child itself; preexec_fn is not supported")
        if self.real and sys.platform.startswith("linux"):
            p = self._start_into(args, popen)
            if p is not None:
                return p, None
        p = subprocess.Popen(args, **popen)
        try:
            self.add(p.pid)
        except CgroupError as e:
            return p, str(e)
        return p, None

    def _start_into(self, args: Any, popen: dict) -> Optional[subprocess.Popen]:
        try:
            fd = os.open(os.path.join(self.dir, _PROCS), os.O_WRONLY)
        except OSError:
            return None
        try:
            # The child writes "0" (itself) before exec; nothing else runs
            # in it between fork and exec.
            kw = dict(popen)
            kw["pass_fds"] = tuple(kw.get("pass_fds", ())) + (fd,)
            try:
                return subprocess.Popen(args, preexec_fn=lambda: os.write(fd, b"0\n") and None, **kw)
            except subprocess.SubprocessError:
                return None  # the write failed in the child; it never ran
        finally:
            os.close(fd)

    def add(self, pid: int) -> None:
        """Move a process into the group by writing its PID to cgroup.procs."""
        try:
            with open(os.path.join(self.dir, _PROCS), "a") as f:
                f.write(f"{pid}\n")
        except OSError as e:
            raise CgroupError(f"cgroup: add pid {pid}: {e}") from e

    def procs(self) -> List[int]:
        """The PIDs in cgroup.procs. On a stand-in, every PID written,
        including ones that have exited."""
        with open(os.path.join(self.dir, _PROCS)) as f:
            return [int(w) for w in f.read().split() if w.isdigit()]

    def remove(self) -> None:
        """Delete the group. A real cgroup can be removed only once empty."""
        try:
            os.rmdir(self.dir)
        except OSError:
            if self.real:
                raise
            _remove_tree(self.dir)


def session_trace(proc_cgroup: str, base: str) -> Optional[str]:
    """The trace ID of the session cgroup named in a /proc/<pid>/cgroup file:
    a path element equal to base followed by a trace-ID element. Hybrid hosts
    list many hierarchies; any line matches. None if there is none."""
    for line in proc_cgroup.split("\n"):
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        segs = parts[2].split("/")
        for i in range(len(segs) - 1):
            if segs[i] == base:
                tid = segs[i + 1].lower()
                if _TRACE_ID.match(tid):
                    return tid
    return None


def _quiet(f, *a) -> None:
    try:
        f(*a)
    except OSError:
        pass


def _remove_tree(d: str) -> None:
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)


def _is_cgroupfs(d: str) -> bool:
    """Whether d is on a cgroup2 filesystem: statfs's f_type, the first field
    of struct statfs on every Linux architecture."""
    if not sys.platform.startswith("linux"):
        return False
    buf = ctypes.create_string_buffer(256)
    try:
        if _libc().statfs(os.fsencode(d), buf) != 0:
            return False
    except (OSError, AttributeError):
        return False
    f_type = ctypes.c_long.from_buffer(buf).value
    return (f_type & 0xFFFFFFFF) == _CGROUP2_SUPER_MAGIC


class _FileHandle(ctypes.Structure):
    _fields_ = [("handle_bytes", ctypes.c_uint), ("handle_type", ctypes.c_int),
                ("f_handle", ctypes.c_ubyte * 128)]


def _cgroup_id(d: str) -> int:
    """cgroupfs (kernfs) encodes the cgroup ID as the 8-byte, native-endian
    file handle."""
    if not sys.platform.startswith("linux"):
        raise CgroupError("cgroup: cgroup IDs are Linux-only")
    h = _FileHandle(handle_bytes=128)
    mount_id = ctypes.c_int()
    libc = _libc()
    if libc.name_to_handle_at(-100, os.fsencode(d), ctypes.byref(h), ctypes.byref(mount_id), 0) != 0:
        e = ctypes.get_errno()
        raise CgroupError(f"cgroup: id of {d}: {os.strerror(e) if e else 'name_to_handle_at failed'}")
    if h.handle_bytes != 8:
        raise CgroupError(f"cgroup: id of {d}: {h.handle_bytes}-byte handle, want 8")
    return int.from_bytes(bytes(h.f_handle[:8]), sys.byteorder)
