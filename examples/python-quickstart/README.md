# Python quickstart (Level 0)

The smallest useful Subpoena setup for a Python project: one rule, one
enforcement point, two tests, no Go, no Docker.

The rule: only an admin may delete an account. `delete_account` in
`accounts.py` is the enforcement point. It opens a span, and either records
`delete_account.denied` or calls `Database.erase` under a `db.erase` span.

## What this proves

- A viewer's delete leaves a denial span and no `db.erase` span, checked
  with an inline TraceQL query after `Harness.collect()`.
- The row is still in the database. The test reads the database itself,
  not the spans, so the spans are not the only evidence.
- An admin's delete does erase the row and emits `db.erase`, so the absence
  above is not an empty trace.
- An incomplete capture (dropped or unended span) makes `collect()` raise,
  so the test fails instead of passing on missing spans.

## What it does not prove

- The database here is a plain Python object the test owns. It is not the
  kernel-side witness. For a process effect, run `subpoena-witness` and
  check its file with `subpoena.harness.require_no_spawn` or
  `watch_spawns`, which fail closed on bad capture health.
- Python has no lint yet. Cross-examination (`subpoena-cross .`) tries two
  mutants: the check `role != "admin"` forced to `False`, and the
  `return False` refusal removed. CI requires both killed. Nothing else in
  this code is mutated.
- Span names are plain strings, with no registry or generated names.
- Nothing here covers a second code path to the database.

## Run it

From a checkout of the Subpoena repo, with Python 3.9+ (on Debian or Ubuntu,
`python3 -m venv` needs the `python3-venv` package):

    cd examples/python-quickstart
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt   # installs ../../python in editable mode, plus pytest
    pytest -q
    subpoena-cross .

Outside the repo, `pip install subpoena pytest` (Python 3.9+, alpha).

## When to move up

When the effect is a process or network call rather than a database row,
use the Go harness with `ProcWitness` or the eBPF witness
(`examples/gateway`). When you want names from a registry and tests that
are checked for being toothless, see `examples/adopter`.
