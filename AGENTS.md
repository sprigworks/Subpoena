# Rules for agents working in this repository

This file is for every coding agent (Claude Code reads it through CLAUDE.md,
which imports it). Keep the rules here, in one place.

Subpoena is a trace-native testing framework: the application's OpenTelemetry
spans are the test interface, and enforcement is proven by an independent
witness, not by the spans. These rules keep that true. `subpoena-lint` and
`subpoena-cross` enforce most of them mechanically; do not work around either.

## Telemetry names

- Span names and attribute keys come only from `generated/go/semconv`. Never
  write a telemetry string literal in application or test code.
- `generated/` is produced from `registry/` by Weaver (`make generate`). Never
  edit it by hand.
- Never add or change a registry entry to make a test pass. The registry is the
  contract; a failing test means the code or the test is wrong. Registry
  changes are deliberate, reviewed (CODEOWNERS), and diffed against main in CI.

## Tests

- Every test calls `Collect()` before it asserts on telemetry. A `_test.go`
  file holding only pure-logic tests (no telemetry) is marked
  `//subpoena:pure_logic` above the package clause instead; never add the
  marker to a file that touches telemetry to quiet the lint.
- Code under test gets its tracer from the harness. Never construct or install
  another tracer provider outside a `main` package to make a test pass; a
  genuine need is marked `//subpoena:own_provider <reason>` on the call, and
  the reason must be true.
- Absence assertions (`RequireAbsent`, `.Absent`) run only after `Collect()`.
  An `Inconclusive` verdict is a failure, not a pass. Do not set
  `AllowInconclusive` to get green.
- Every `_test.go` file starts with a provenance marker above the package
  clause: `//subpoena:spec_derived` (written from the registry and docs) or
  `//subpoena:impl_derived` (written after reading the implementation).
- Write spec-derived tests from `registry/` and `docs/` before reading the
  implementation. Read the code only after the test exists, and say so with the
  marker if you did not.
- A function marked `//subpoena:enforcement_point` needs a test that asks a
  Witness (`Spawned`) what actually happened. Before trusting zero processes,
  stop the witness and check capture health. Prefer `harness.RequireNoSpawn`:
  missing or failed `HealthReporter` health is Inconclusive and fails the test. The system's own spans are
  testimony, not proof.
- `go run ./cmd/subpoena-cross ./examples/gateway` must report every mutant
  killed. If a mutant survives, strengthen the tests; never remove the
  enforcement marker.

## Environment

- Normal environments: plain `make test`. Sandboxes that cannot reach
  proxy.golang.org, sum.golang.org or the vanity module hosts
  (go.opentelemetry.io, golang.org) use `make SANDBOX=1 <target>`, which
  activates `go.work.sandbox` (GitHub-mirror replaces) and sets
  `GOPROXY=direct GOSUMDB=off`. Keep `go.mod` free of those replaces.
- Tier 2 (`make oats`), tier 3 (`make alerts`) and `make conformance` need
  Docker; tier 2 needs rootful Docker, cgroup v2 and kernel BTF. Where those are missing (cloud
  sandboxes), say the target was not run; never claim it passes. Run OATS only
  through `make oats`: run directly from an agent session, gcx's agent mode
  makes `absent` and `count` assertions meaningless (oats/README.md).
- `make test-ebpf` (the eBPF witness against the real kernel) needs Docker
  and runs privileged; elsewhere its kernel tests skip, so do not claim they
  passed. After editing `pkg/witness/execbpf/bpf/exec.c`, run
  `make generate-bpf` (clang) and commit the regenerated object.
- Weaver is a Rust binary, not installed by default. See the Makefile header.
- Never commit to main. Work on a branch; do not open PRs unless asked.
