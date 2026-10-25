# subpoena-lint

Static checks over a package tree, written with `go/ast`. Precision is
deliberately secondary to a clear, working skeleton: each rule is one function
in `internal/lint/` (`lint.go`, `orphan.go`, `drift.go`), with tests alongside.

```
go run ./cmd/subpoena-lint [-registry dir] [-invariants dir] <dir>...
go run ./cmd/subpoena-lint registry-drift [--base ref] [repo]
```

Exit status: 0 clean, 1 findings, 2 usage or load error. The registry package
(`generated/go/semconv`) is found by walking up from the first target unless
`-registry` is given. `testdata/`, `vendor/` and dot directories are skipped.

## Implemented rules

| Rule | Flags |
| --- | --- |
| `unknown-telemetry` | A string literal passed as the span name (`x.Start(ctx, "...")`, `SetName("...")`) or as an attribute key (`attribute.String("...", v)` and the other typed constructors) whose value is not in the registry, or a `semconv.X` selector where `X` does not exist. A literal that equals a registry value is accepted; prefer the constant. |
| `no-trace-assertion` | A `_test.go` file that defines tests but never calls `Collect()`. Files with no `Test`/`Benchmark`/`Fuzz`/`Example` function (helpers only) are exempt, and so are files marked `//subpoena:pure_logic` (below). A `pure_logic` file that imports telemetry is flagged instead. |
| `unwitnessed-enforcement` | A function whose doc comment carries `//subpoena:enforcement_point` when no `_test.go` file in the tree calls a Witness method (`Spawned`). |
| `unguarded-absence` | A `RequireAbsent(...)` or `.Absent(...)` call with no `Collect()` call earlier in the same top-level function. |
| `missing-provenance` | A `_test.go` file without `//subpoena:spec_derived` or `//subpoena:impl_derived` above the package clause. |
| `orphan-invariant` | A TraceQL string literal passed to a harness query or assert function in a `_test.go` file (`RequireAbsent`/`RequireExists` third argument; `Absent`, `Exists`, `Query` first argument) that, trimmed, does not byte-match a file in `invariants/`. Reported at the literal's `file:line`. |
| `registry-drift` | Separate subcommand, see below. |

### Pure-logic test files

Spec-derived tests of pure logic (a policy decision, a parser) have nothing to
collect, and belong in their own file. Mark the file above the package clause,
next to its provenance marker:

```go
//subpoena:spec_derived
//subpoena:pure_logic

package gateway_test
```

The marker exempts the file from `no-trace-assertion`. It is a claim that the
file does not touch telemetry, so a marked file that imports
`go.opentelemetry.io/...`, or a path ending in `/pkg/harness`, `/pkg/witness`,
`/generated/go/semconv` or `/invariants`, is reported under the same rule.
Example: `examples/gateway/policy_test.go`.

### orphan-invariant

Promotion between tiers is copy and paste, so a query that is not an invariant
file cannot be promoted and drifts. Load invariants by name instead of pasting
them:

```go
harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
```

`invariants/names.go` holds one constant per `invariants/*.traceql` file. It is
generated (`make generate-invariants`, i.e. `go generate ./invariants`) and a
test fails if it is stale. The invariants directory is found by walking up from
the lint target, or given with `-invariants`; if none is found every literal
is an orphan. Only literals are checked: a query built with `fmt.Sprintf`,
concatenation or a variable is invisible to the rule (the gateway builds its
span-level helper queries that way, from registry constants).

### registry-drift

```
go run ./cmd/subpoena-lint registry-drift                      # working tree vs HEAD
go run ./cmd/subpoena-lint registry-drift --base origin/main   # make lint-drift BASE=origin/main
```

The registry is the contract, and a test must not move together with it
(CLAUDE.md: never change a registry entry to make a test pass). The rule
reports a `_test.go` file, changed since the base, that references a generated
constant (`semconv.X`) for a span or attribute that is new or changed in the
`registry/` diff. It is a flag for a deliberate human look, not a verdict:
registry changes legitimately arrive with tests, which is why CODEOWNERS
reviews them.

Mechanics: parse `registry/**/*.yaml` at the base and in the working tree;
`--base` is resolved to its merge-base with HEAD, so a branch is compared with
where it left main. An attribute is "changed" if its `type`, `stability`,
`deprecated` or `annotations` (tier) differ; a span if its `span_kind`,
`stability` or attribute list (refs and requirement levels) differ. `brief`,
`note` and `examples` are ignored. Identifiers map to Go constants through
`generated/go/semconv` in the working tree (run `make generate` first). Test
files are those that differ from the base plus untracked ones.

Exit status 0 clean, 1 findings, 2 error (not a git repository, unknown base,
unparseable registry YAML). Not covered: removals (the test would not
compile), string literals (the `unknown-telemetry` rule steers tests to
constants, and fixture strings in unrelated tests would make this noisy),
and queries assembled from constants through variables.

Known imprecision: rules 2 to 4 match by call name, not by type, so any method
called `Collect` or `Spawned` satisfies them. Rule 3 is tree-wide, not
per-function. These are acceptable for a skeleton and listed here so nobody
mistakes them for guarantees. The fault gate (`cmd/subpoena-gate`) is the
backstop that checks behaviour rather than shape.

## Not implemented

- `dead-telemetry`: a registry entry with no emitter in code. Needs a
  whole-program pass. The other half of the old `registry-drift` idea,
  `generated/` out of date with `registry/`, is covered by
  `make check-generated`.
