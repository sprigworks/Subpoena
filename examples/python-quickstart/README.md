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
  kernel-side witness. The Python port has no live witness and no witness
  health check, only a reader for the log `subpoena-witness` writes
  (`subpoena.witness.read_log`).
- Only one mutant is checked. Python has no lint and no cross-examination
  yet. CI swaps the check `role != "admin"` for `False` and requires the
  suite to fail, and it does: the first test goes red. No other mutant of
  this code is tried.
- Span names are plain strings, with no registry or generated names.
- Nothing here covers a second code path to the database.

## Run it

From a checkout of the Subpoena repo:

    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    pytest -q

Outside the repo, `pip install subpoena pytest` (Python 3.9+, alpha).

## When to move up

When the effect is a process or network call rather than a database row,
use the Go harness with `ProcWitness` or the eBPF witness
(`examples/gateway`). When you want names from a registry and tests that
are checked for being toothless, see `examples/adopter`.
