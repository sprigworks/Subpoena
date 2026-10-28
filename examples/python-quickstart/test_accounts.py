# subpoena:spec_derived (written from the rule in README.md before accounts.py)
from subpoena.harness import Harness, require_absent, require_exists

from accounts import Database, delete_account

FORBIDDEN = '{ name = "db.erase" }'
DENIAL = '{ name = "delete_account.denied" && span.role = "viewer" }'


def test_viewer_cannot_delete_an_account():
    h = Harness()
    db = Database({"acct-1": "alice"})

    delete_account(db, h.tracer_provider, "viewer", "acct-1")

    tr = h.collect()  # before any assertion
    require_exists(tr, DENIAL)       # the denial is on the record
    require_absent(tr, FORBIDDEN)    # no erase span (testimony)
    assert db.rows == {"acct-1": "alice"}  # the row is still there (evidence)


def test_admin_can_delete_an_account_so_absence_is_not_vacuous():
    h = Harness()
    db = Database({"acct-1": "alice"})

    delete_account(db, h.tracer_provider, "admin", "acct-1")

    tr = h.collect()
    require_exists(tr, FORBIDDEN)
    require_absent(tr, DENIAL)
    assert db.rows == {}  # the same observer sees the effect when it happens
