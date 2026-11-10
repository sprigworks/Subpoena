"""The exception that says a failure is witness evidence. It lives apart from
subpoena.harness so that subpoena-cross's plugin can test for it in a project
that has no OpenTelemetry to import."""


class WitnessFailure(AssertionError):
    """A witness saw the effect. subpoena.harness raises it, and a test that asks
    a witness itself raises it through harness.witness_fail. subpoena-cross reads
    witness evidence from this type, not from text: a test's message can be a
    value the code under test returned (assert r.ok, r.body), and unittest's
    message is the repr of one."""
