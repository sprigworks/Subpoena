---
name: Bug report
about: Report a reproducible problem in Subpoena
title: ''
---

<!-- For security vulnerabilities, follow SECURITY.md instead of opening a
public issue. Remove credentials, private spans, arguments, and identifiers
from logs and examples before sharing them. -->

## What happened?

Describe the expected behavior and what actually happened. If an assertion
returned Pass, Fail, or Inconclusive, include the verdict and Collect error.

## Reproduction

Provide a minimal example, the query or invariant, and the commands needed to
reproduce it.

## Version and environment

- Subpoena version or commit:
- Go or Python version:
- Operating system and architecture:
- Witness (if used): ProcWitness / eBPF / other
- For kernel or integration problems: kernel version, Docker version,
  cgroup v2 availability, and whether the run was privileged:

## Checks and output

Include the exact command and output from `subpoena-lint` for your service,
or explain why it does not apply. For example, from this repository:

```sh
go run ./cmd/subpoena-lint -dead-telemetry ./examples/gateway
```

Include relevant `make check` failures and witness health/Collect errors.
Distinguish checks that failed from checks that skipped or were not run.
