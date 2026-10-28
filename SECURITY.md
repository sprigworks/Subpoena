# Security

Please report vulnerabilities privately, either through GitHub's
**Report a vulnerability** button on the Security tab of this repository, or by
email to hello@sprig.works. Please do not open a public issue for a security
report.

## What counts

Subpoena's job is to stop tests from passing for the wrong reason, so a way to
get a false Pass is a security bug. For example:

- an absence check that passes on an incomplete or blind capture;
- a witness that misses an exec or a connection it claims to cover, without
  reporting degraded health;
- `subpoena-cross` reporting a mutant as killed when the suite did not catch
  it.

Ordinary vulnerabilities in the code (the witness runs privileged) count too.

## Supported versions

Subpoena is alpha. Fixes go to `main` and the next release. Older releases do
not get backports.
