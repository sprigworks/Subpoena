# Rules for agents working in this repository

Subpoena is a trace-native testing framework: the application's OpenTelemetry
spans are the test interface, and enforcement is proven by an independent
witness, not by the spans. These rules keep that true. `subpoena-lint` and
`subpoena-gate` enforce most of them mechanically; do not work around either.

## Telemetry names

- Span names and attribute keys come only from `generated/go/semconv`. Never
  write a telemetry string literal in application or test code.
- `generated/` is produced from `registry/` by Weaver (`make generate`). Never
  edit it by hand.
- Never add or change a registry entry to make a test pass. The registry is the
  contract; a failing test means the code or the test is wrong. Registry
  changes are deliberate, reviewed (CODEOWNERS), and diffed against main in CI.

## Tests

- Every test calls `Collect()` before it asserts on telemetry.
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
  Witness (`Spawned`) what actually happened. The system's own spans are
  testimony, not proof.
- `go run ./cmd/subpoena-gate ./examples/gateway` must report every mutant
  killed. If a mutant survives, strengthen the tests; never remove the
  enforcement marker.

## Environment

- This sandbox cannot reach proxy.golang.org, sum.golang.org, or vanity module
  hosts (golang.org, google.golang.org, go.opentelemetry.io, gopkg.in). Use
  `GOPROXY=direct GOSUMDB=off` for every go command that fetches modules; the
  Makefile sets them. `go.mod` replaces the unreachable modules with GitHub
  mirrors; do not remove those replaces without checking reachability.
- No Docker, no eBPF, no root here. Tier 2 (`examples/gateway/oats`) and the
  Tetragon witness are written but cannot be executed; do not claim they pass.
- Weaver is a Rust binary, not installed by default. See the Makefile header.
- Never commit to main. Work on a branch; do not open PRs unless asked.
