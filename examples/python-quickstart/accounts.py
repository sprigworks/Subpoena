"""One rule: only an admin may delete an account."""

from opentelemetry.trace import TracerProvider


class Database:
    """The real effect lives here. The tests read rows from it directly,
    which is evidence that does not depend on what the spans claim."""

    def __init__(self, rows):
        self.rows = dict(rows)

    def erase(self, account_id):
        del self.rows[account_id]


# The rule: non-admins never reach erase. subpoena-cross forces the check
# off, then removes the refusal, and requires the tests to fail each time.
# subpoena:enforcement_point
def delete_account(db, tracer_provider: TracerProvider, role, account_id):
    tracer = tracer_provider.get_tracer("accounts")
    with tracer.start_as_current_span("delete_account") as request:
        request.set_attribute("account.id", account_id)
        if role != "admin":  # subpoena:enforcement_guard false
            with tracer.start_as_current_span("delete_account.denied") as denied:
                denied.set_attribute("role", role)
            return False  # subpoena:enforcement
        with tracer.start_as_current_span("db.erase"):
            db.erase(account_id)
        return True
