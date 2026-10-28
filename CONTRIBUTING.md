# Contributing to Subpoena

Start with the [README](README.md), [architecture](docs/architecture.md), and
[repository rules](AGENTS.md). The engineering rules in AGENTS.md apply to
human and agent contributions alike.

## Making a change

1. Open an issue describing the problem and a minimal reproduction. For
   security vulnerabilities, contact the maintainers privately instead of
   opening a public issue.
2. Create a branch from current `main`. Keep the change focused and include
   tests for behavior changes. If the change alters behavior, flags, versions
   or make targets, update the matching docs (README, CONTRIBUTING, `docs/`,
   `examples/adopter/README.md`) in the same pull request.
3. Run the checks below and review your diff before opening a pull request.
   Explain what changed, why, and which checks ran. State any skipped checks
   and the environment limitation.

## Checks

Use Go 1.25 or newer. From the repository root:

```sh
make check
```

This builds, vets, runs the Go suite, lints the gateway, checks that its
suite catches removed enforcement, cross-examines Subpoena's own guards and
runs `examples/platform`. If you change the adopter or public APIs,
also run the separate module's checks:

```sh
cd examples/adopter
make check
```

For Python changes, run `make python` from the root (requires `uv`). For
registry or generation changes, use `make registry-check check-generated`
with Weaver installed. Generated files must come from the registry; see
AGENTS.md for the contract and review rules.

Changes involving kernel observation, cgroups, integration, or production
alerts also need the applicable `make test-ebpf`, `make test-cgroup`,
`make conformance`, `make oats`, or `make alerts` targets. Requirements are in
the README and Makefile. A skipped privileged test is not a passing test.

For the supported sandbox workaround, see AGENTS.md and `make SANDBOX=1 check`.
Do not weaken capture completeness, accept Inconclusive, or remove enforcement
markers to make checks pass.

## Releasing the Python package

Bump `version` in `pyproject.toml`, merge, then push a tag `python/v<version>`
(for example `python/v0.1.0a1`) to GitHub. The `publish-python`
workflow reruns the port checks, builds, and uploads to PyPI through Trusted
Publishing; no token is involved.
