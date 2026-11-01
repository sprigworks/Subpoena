"""Subpoena's pytest plugin, loaded through the pytest11 entry point when the
package is installed. Its fixtures do the setup and teardown a test would
otherwise write by hand, so a test reads like its Go twin:

    def test_viewer_cannot_delete(subpoena_harness, subpoena_watch_spawns, subpoena_sinkhole):
        h = subpoena_harness
        subpoena_watch_spawns(witness_log, trace_id, SpawnRule(never=["rm"]))
        ... run the code under test with h.tracer_provider, pointed at subpoena_sinkhole.addr ...
        tr = h.collect()
        require_absent(tr, invariants.load("no_exec_after_deny"))
        subpoena_sinkhole.stop()
        require_no_dial(subpoena_sinkhole, trace_id)

Nothing here relaxes a check: collect() is still the test's own call, and
Inconclusive still fails.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator, Optional

import pytest

from . import harness
from .harness import Harness, SpawnRule
from .witness import Sinkhole


@pytest.fixture
def subpoena_harness() -> Iterator[Harness]:
    """A fresh Harness, shut down when the test ends. Call collect() before
    asserting, as always."""
    h = Harness()
    yield h
    h.shutdown()


@pytest.fixture
def subpoena_watch_spawns(request) -> Callable[..., None]:
    """watch_spawns bound to this test: call it with (witness, trace_id,
    rule) when the witness starts. The check runs at teardown, even after
    the test has failed, and fails the test with witness: messages."""
    def watch(w: Any, trace_id: str, rule: Optional[SpawnRule] = None) -> None:
        harness.watch_spawns(request.addfinalizer, w, trace_id, rule if rule is not None else SpawnRule())
    return watch


@pytest.fixture
def subpoena_sinkhole() -> Iterator[Sinkhole]:
    """A running Sinkhole, stopped at teardown if the test did not stop it.
    Stop it yourself before require_no_dial: a running sinkhole is unhealthy,
    so the check is Inconclusive and fails."""
    s = Sinkhole()
    yield s
    s.stop()
