# Contributing to Subpoena

Start with the [README](README.md), [architecture](docs/architecture.md), and
[repository rules](AGENTS.md). The engineering rules in AGENTS.md apply to
human and agent contributions alike.

## Repository layout

| Path | Purpose |
| --- | --- |
| `pkg/` | Public Go libraries: harness, TraceQL evaluator, witnesses, cgroup support, and production export helpers. |
| `internal/` | Implementation of CLI tooling; Go restricts imports from outside this module's directory tree. |
| `cmd/` | Executable entry points built on the libraries and internal tooling. |
| `registry/`, `weaver-templates/`, `generated/` | Telemetry contract, generation templates, and generated language bindings. Edit the contract and templates, then regenerate. |
| `invariants/` | TraceQL assertions shared by tests and production rules. |
| `python/`, `conformance/` | Python port and shared fixtures and integration checks. See [port scope](docs/ports.md). |
| `examples/` | Quickstarts and adoption examples, including separate Go modules that exercise the public API. |
| `docs/`, `witnesses/` | Design and contributor reference material; `witnesses/` also holds the Tetragon policy. |

`pkg/` is a convention, not an import restriction. Preserve existing public
import paths when organizing code; moving an exported API needs an explicit
compatibility plan.

### Witness code and documentation

[`pkg/witness/`](pkg/witness/) contains executable Go code: shared event and
health contracts, local observers, and log readers. Backend-specific packages
such as `execbpf`, `netbpf`, and `dbproxy` live beneath it. Put a new backend
with its own protocol, platform machinery, or dependencies in a subpackage,
using the shared contracts from `pkg/witness`. Keep backend details out of
the shared interfaces and avoid introducing a dependency from the parent
package back to a backend.

[`witnesses/`](witnesses/) contains documentation and policy assets. Its
[README](witnesses/README.md) records capture guarantees, correlation, and
known limits; update it when a backend's capabilities change.

### Test organization

Keep tests beside the package they exercise and name files and test functions
for behavior, such as session settings or transaction state, rather than a
review round. Preserve provenance markers when moving existing tests.
Database proxy parser and protocol tests live in `pkg/witness/dbproxy/`;
tests against real PostgreSQL and MySQL servers live in its `live/` package
and run with `make test-db`. Those tests may skip under plain `go test` when
Docker or the server images are unavailable.

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

Use Go 1.26 or newer. From the repository root:

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
