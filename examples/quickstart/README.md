# quickstart: one rule, no registry (Level 0)

A solo developer protects one rule in about ten minutes. This is the smallest
honest adoption of Subpoena, and the first step of the ladder that
`examples/adopter` continues.

The rule: a delete-account request from a non-admin is refused and never runs
the purge process. `Authorize` in `handler.go` is the enforcement point, marked
`//subpoena:enforcement_point`. Span and attribute names are plain Go
constants, and the invariants are inline TraceQL strings in `handler_test.go`.
There is no Weaver registry, no generated names and no invgen.

## What this level proves

- The denial span exists, and no purge span follows it in the trace
  (`RequireExists`, `RequireAbsent` after `Collect()`).
- An independent witness (`ProcWitness`) saw no process for the refused
  request, and its capture was healthy (`Health`, `RequireNoSpawn`).
- The control test (an admin delete) runs, and the witness does see its
  process, so the absence in the first test is not vacuous.
- Cross-examination (`make cross`) removes the check in `Authorize` and
  confirms the tests go red (the mutant is killed).

## What it does not prove

- No tier 2 (a kernel-side witness in a real stack) and no tier 3 (alerts on
  production traces). Both need Docker; see the root README.
- `ProcWitness` polls `/proc`, so it can miss a process that starts and exits
  between two polls. The test keeps the process alive for `sleepArg` seconds
  to outlive the interval; a fast process could still slip past.
- The names are not registry-checked. Each name an absence query uses here is
  also required to exist in another test, which catches a typo; a name used
  only in an absence query would let it pass for the wrong reason.
- No `subpoena-lint`. Its `unknown-telemetry` and `orphan-invariant` rules
  need a registry and an `invariants/` directory, so lint arrives at Level 1.

## Commands

From this directory (Go 1.25+, a Linux box, no privileges):

```
make test     # go test ./...
make cross    # go tool subpoena-cross .
make check    # both
```

`subpoena-cross` is pinned as a Go tool in `go.mod`
(`go get -tool github.com/sprigworks/subpoena/cmd/subpoena-cross`), so its
version is the `github.com/sprigworks/subpoena` version. Here `go.mod`
replaces Subpoena with `../..` because this module lives inside the Subpoena
repository; a real adopter requires a released version.

## When you outgrow this

Move to `examples/adopter` when you want names checked against a contract: a
Weaver registry, generated span and attribute names, invariants kept in
`invariants/*.traceql` and generated with `subpoena-invgen`, and
`subpoena-lint` over all of it.
