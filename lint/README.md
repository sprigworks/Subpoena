# subpoena-lint

Static checks over a package tree, written with `go/ast`. Precision is
deliberately secondary to a clear, working skeleton: each rule is one function
in `internal/lint/lint.go`, with tests in `internal/lint/lint_test.go`.

```
go run ./cmd/subpoena-lint [-registry dir] <dir>...
```

Exit status: 0 clean, 1 findings, 2 usage or load error. The registry package
(`generated/go/semconv`) is found by walking up from the first target unless
`-registry` is given. `testdata/`, `vendor/` and dot directories are skipped.

## Implemented rules

| Rule | Flags |
| --- | --- |
| `unknown-telemetry` | A string literal passed as the span name (`x.Start(ctx, "...")`, `SetName("...")`) or as an attribute key (`attribute.String("...", v)` and the other typed constructors) whose value is not in the registry, or a `semconv.X` selector where `X` does not exist. A literal that equals a registry value is accepted; prefer the constant. |
| `no-trace-assertion` | A `_test.go` file that defines tests but never calls `Collect()`. Files with no `Test`/`Benchmark`/`Fuzz`/`Example` function (helpers only) are exempt. |
| `unwitnessed-enforcement` | A function whose doc comment carries `//subpoena:enforcement_point` when no `_test.go` file in the tree calls a Witness method (`Spawned`). |
| `unguarded-absence` | A `RequireAbsent(...)` or `.Absent(...)` call with no `Collect()` call earlier in the same top-level function. |
| `missing-provenance` | A `_test.go` file without `//subpoena:spec_derived` or `//subpoena:impl_derived` above the package clause. |

Known imprecision: rules 2 to 4 match by call name, not by type, so any method
called `Collect` or `Spawned` satisfies them. Rule 3 is tree-wide, not
per-function. These are acceptable for a skeleton and listed here so nobody
mistakes them for guarantees. The fault gate (`cmd/subpoena-gate`) is the
backstop that checks behaviour rather than shape.

## Documented but not implemented

- `orphan-invariant`: an invariant file in `invariants/` that no test loads, or
  a test-loaded invariant with no OATS and alert-rule counterpart. Would need
  to cross-reference `invariants/*.traceql` with `Load`/`MustLoad` call sites,
  the OATS YAML and the alert rule YAML.
- `registry-drift`: a registry entry with no emitter in code (dead telemetry), or
  `generated/` that differs from what `weaver registry generate` produces for
  `registry/`. The second half is covered today by `make check-generated`; the
  first needs a whole-program pass.
