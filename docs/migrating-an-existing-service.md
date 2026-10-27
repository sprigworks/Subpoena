# Migrating an existing service

How to take a Go service that has conventional tests and OpenTelemetry
instrumentation and move it to Subpoena, one step at a time. The worked example
is the toy gateway in `examples/gateway`: open a session, authorize, exec, and
fetch. One policy rule (a non-admin may not act on `prod-*`). A denied session
never execs (`invariants/no_exec_after_deny.traceql`) and never reaches a
forbidden address (`examples/gateway/fetch_test.go`, a witness check, not a
second invariant file). Every step leaves the build green, so
you can stop after any of them and keep what you have.

Subpoena is alpha. This guide is for a Go service. The reference implementation
is Go; Python has a partial port (`docs/ports.md`). The registry is
language-neutral. The order
matters: registry first, tests once names are stable, witnesses before you trust
any absence claim.

`examples/adopter` is a second worked example: a separate module that adopts
Subpoena from outside, as your service will, and CI keeps it working. When this
guide shows a `make` target from this repository, the adopter's `Makefile` has
the outside equivalent.

## 0. Add Subpoena and its commands

```
go get github.com/sprigworks/subpoena
go get -tool github.com/sprigworks/subpoena/cmd/subpoena-lint
go get -tool github.com/sprigworks/subpoena/cmd/subpoena-cross
go get -tool github.com/sprigworks/subpoena/cmd/subpoena-invgen
```

The commands become Go tools of your module (Go 1.25+), pinned to the Subpoena
version in your `go.mod`, and run with `go tool subpoena-lint` and so on. In
this repository the same commands run as `go run ./cmd/...`.

## 1. Extract a registry from your existing span names

Inventory what you emit today. Anything that starts a span or sets an
attribute is a candidate:

```
grep -rnE 'Start\(ctx, "[^"]+"|attribute\.(String|Bool|Int|Int64|Float64)\("[^"]+"' --include='*.go' . | grep -v _test.go
```

In the gateway before its migration that finds three span names
(`agent.session.open`, `.authorize`, `.exec`) and four attribute keys. Write
them into a Weaver registry, `registry/model/*.yaml`, as they are today. Do not rename anything in
this step; an ugly name that exists is a contract, and renaming it is a
deliberate registry change later.

```yaml
# registry/model/attributes.yaml
groups:
  - id: registry.authorization
    type: attribute_group
    brief: Attributes describing an authorization decision.
    stability: stable
    attributes:
      - id: authorization.allowed
        type: boolean
        stability: stable
        brief: Whether the authorization decision allowed the requested action.
        annotations:
          tier: all          # safe to export in production
      - id: session.id
        type: string
        stability: stable
        brief: Identifier of the agent session.
        annotations:
          tier: test         # high cardinality: never exported in production
```

A span group names the span and refs its attributes (`registry/model/spans.yaml`:
`type: span`, `name: agent.session.authorize`, `span_kind: internal`, and
`- ref: authorization.allowed` with a `requirement_level`).

Decide each attribute's `tier` now, while you are looking at them. `test`
attributes are the high-cardinality or diagnostic ones (session IDs, command
lines); `all` attributes are safe in production. In production, wrap the
exporter with `production.Exporter(exp, semconv.AttributeTiers)` or put the
Collector processor from `production.CollectorConfig` in front of the backend
(the gateway's `cmd/gateway` and `examples/gateway/production` show both). An
invariant you promote to an alert may read only `all` attributes;
`invariants/` tests that. Attributes defined upstream
(`process.command_line`) are referenced with `ref:`; the manifest depends on the
OpenTelemetry semantic conventions for that.

Copy `registry/manifest.yaml`, `weaver-templates/` and the `registry-check`,
`generate` and `check-generated` Makefile targets from this repository, then:

```
make registry-check    # weaver registry check -r registry --future
make generate          # writes generated/go/semconv/semconv.go
```

Weaver is a Rust binary (https://github.com/open-telemetry/weaver/releases).
Commit `generated/`; CI regenerates it and fails if it differs. Add `registry/`,
`generated/` and `invariants/` to `CODEOWNERS`; `.github/workflows/registry.yml`
diffs registry changes against main.

## 2. Replace string literals with generated constants

```go
// before
ctx, span := g.tracer.Start(ctx, "agent.session.authorize")
span.SetAttributes(attribute.Bool("authorization.allowed", decision.Allowed))

// after
ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionAuthorize)
span.SetAttributes(attribute.Bool(semconv.AttrAuthorizationAllowed, decision.Allowed))
```

Let the linter be your worklist: a literal that is not in the registry is a
finding, and one that is in the registry is accepted but should still go:

```
go tool subpoena-lint .          # rule: unknown-telemetry (takes directories, walks them)
```

Names that are new to you (a span someone added without telling anyone) show up
here: add them to the registry (reviewed) or delete them. Enum-typed attributes
get `Val...` constants, so values are not literals either. Test code counts: a
test asserting on `"agent.session.exec"` has its own copy of the contract.

## 3. Convert orchestration and E2E tests to Collect() + TraceQL

Typical conventional test for the gateway, asserting on a return value and a mock:

```go
func TestDeniedProdIsRefused(t *testing.T) {
    exec := &fakeExec{}
    gw := NewWithExec(exec)
    _, err := gw.Run(ctx, mallory, "prod-db1", "sleep", "1")
    if !errors.Is(err, ErrDenied) { t.Fatal(err) }
    if exec.calls != 0 { t.Fatal("exec was called") }      // testimony from a mock
}
```

It says nothing about what the system emitted, and `fakeExec` is not the real
exec. The converted test (compare `TestDeniedSessionNeverExecs` in
`examples/gateway/gateway_test.go`):

```go
h := harness.New()                                   // in-memory exporter
gw := gateway.New(h.Tracer("test"))                  // inject the tracer, real code path
ctx, sess := gw.Open(context.Background(), gateway.User{Name: "mallory"})
_, err := gw.Run(ctx, sess, "prod-db1", "sleep", "0.15")
// ... assert err ...
tr, err := h.Collect(context.Background())           // required: flush and completeness check
if err != nil { t.Fatal(err) }

harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny))
harness.RequireExists(t, tr, authorizeDenied)        // the control: the denial was seen
```

What to carry over, and what changes:

- **Inject a tracer, not a mock.** Constructors take a `trace.Tracer` (the
  gateway does); tests pass `h.Tracer(...)`. Use real collaborators where you can.
- **Call `Collect()` before asserting on telemetry.** It force-flushes and fails
  if a span was dropped, never ended, or lost attributes, events or links. After
  an incomplete capture, absence is
  `Inconclusive`, which fails the test. Never set `AllowInconclusive` to get green.
- **Pair every absence with a presence control** (the denial was observed).
- **Write the query once, as an invariant:** `invariants/<name>.traceql` (any
  match is a violation), then `invariants.<Name>`. Your `invariants` package
  embeds the files (copy `examples/adopter/invariants/invariants.go`); its
  `//go:generate go run github.com/sprigworks/subpoena/cmd/subpoena-invgen`
  writes `names.go`, so run `go generate ./invariants` after adding one.
  The `orphan-invariant` rule flags a pasted TraceQL literal in a test, because
  it cannot be promoted in step 7. One-off queries built from registry constants
  with `fmt.Sprintf`, as the gateway tests do, are fine.
- **Stay in the subset** (`docs/traceql-subset.md`): `>>`, `>`, `&&`, `||`,
  `=`, `!=` on `name` and `span.` attributes. Parenthesize when mixing `&&`
  and `||`: Tempo groups them left to right, so the subset rejects
  `a || b && c`. Pipelines, regexes, durations and `resource.` fields are
  rejected at parse time. An invariant that needs more
  can live at tiers 2 and 3 only; say so in a comment next to it.

Write new tests from the registry and docs before reading the implementation
(step 5). Delete a legacy test only after step 6 shows its replacement catches
the same fault.

## 4. Identify enforcement points and add witnesses

An enforcement point is a function whose job is to stop a side effect:
authorization, a rate limit, a sandbox check, an egress filter. Find yours by
asking "if this `return` were deleted, would anything fail?" In the gateway:

```go
// Authorize evaluates policy for running something on host.
//
//subpoena:enforcement_point
func (g *Gateway) Authorize(ctx context.Context, s *Session, host string) (context.Context, error) {
    ...
    if !decision.Allowed {
        return ctx, fmt.Errorf("%w: %s on %s", ErrDenied, decision.PolicyID, host) //subpoena:enforcement
    }
```

`//subpoena:enforcement_point` goes in the function's doc comment;
`//subpoena:enforcement` goes on the first line of the one statement that does
the enforcing. Cross-examination (step 6) deletes that statement and requires the suite
to fail. A function with the first marker but not the second makes
cross-examination exit with an error naming it.

Then ask who can observe the side effect without trusting your code. For the
gateway the effects are a process exec and an outbound connection, and the
witnesses are a process observer and a network observer.
Spans are testimony: the function that enforces also reports, so "denied" and no
`exec` span can sit next to an exec that really happened. In tests:

```go
w := witness.NewProcWitness(os.Getpid())             // pkg/witness
w.Start(); defer w.Stop()
...
w.Stop()                                             // final poll before asking
if n := len(w.Spawned(traceID)); n != 0 {            // the proof, not the spans
    t.Fatalf("witness saw %d processes after a denial", n)
}
```

To correlate by trace rather than lineage, start the session's processes in a
cgroup named with the trace ID (`pkg/cgroup`, as `gateway.Open` does).
`witnesses/README.md` has the modes and their gaps; note that `ProcWitness`
polls and can miss a process shorter than its interval. Where the tests can
run as root (CI in a privileged container), `pkg/witness/execbpf` is a
drop-in `witness.Witness` that sees every exec in the kernel; it is also the
tier-2 and production witness (`cmd/subpoena-witness`).

For outbound connections (`Gateway.Fetch` is the example) the sibling
interface is `witness.NetworkWitness`, with `Dialed(traceID)`. Assert absence
with `harness.RequireNoDial(t, w, traceID, match)`; `harness.DialTo` builds the
match. Like `RequireNoSpawn`, it fails on an Inconclusive verdict, such as a
witness that reports no capture health. Destinations are addresses, not names,
so pin what the name resolves to. Two witnesses implement it:

```go
sink, err := witness.NewSinkhole()                   // tier 1: no root, no kernel support
// point the code under test at sink.Addr() as the upstream it must not reach
...
sink.Stop()                                          // end the observation window
harness.RequireNoDial(t, sink, traceID, nil)
```

`Sinkhole` is a listener the test stands up as a destination the code must
never reach. It certifies only "nothing reached this address", so pair it with
a control where the destination is allowed and the connection arrives (see
`examples/gateway/fetch_test.go`). `pkg/witness/netbpf` sees every outbound inet
connect and named send on the host, attributed by session cgroup; like `execbpf`
it needs root and BTF. `witnesses/README.md` lists what each does not see.

Other side effects (file or database changes) need another observer, for
example an audit log. There is no interface for them; that is future work. The
`unwitnessed-enforcement` lint rule only checks that some test asks a witness
(`Spawned`, `Dialed`, `NoSpawn`, `RequireNoSpawn`, `NoDial` or `RequireNoDial`),
so for other enforcement points review has to carry it.

## 5. Add provenance markers

Every `_test.go` file starts with one of these above the package clause:

```go
//subpoena:spec_derived     // written from registry/ and docs/ before reading the code
//subpoena:impl_derived     // written after reading the implementation
```

A test written after reading the code tends to assert whatever the code does,
bugs included. Reviewers should know which kind they are looking at.

For a migration, mark every existing test `impl_derived`; that is the honest
answer and the lint rule `missing-provenance` makes it complete. New tests you
write from the registry first get `spec_derived`. Do not upgrade a legacy
test's marker because you renamed its constants.

```
for f in $(grep -rL 'subpoena:\(spec\|impl\)_derived' --include='*_test.go' .); do
  printf '//subpoena:impl_derived\n\n' | cat - "$f" > "$f.new" && mv "$f.new" "$f"
done
```

A file that begins with a `//go:build` line is fine: the marker may precede it.

## 6. Run the lint and cross-examination

```
go tool subpoena-lint -dead-telemetry .     # dead-telemetry only when . is the whole service
go tool subpoena-cross ./path/to/package     # the package(s) holding enforcement points
make lint-drift BASE=origin/main                 # registry-drift, for review
```

| Lint finding | Fix |
| --- | --- |
| `unknown-telemetry` | Use a generated constant; if the name is new, add it to the registry (reviewed) |
| `no-trace-assertion` | The file defines tests but never calls `Collect()`. If it holds only pure-logic tests, mark it `//subpoena:pure_logic` (see "What to delete") |
| `unguarded-absence` | Call `Collect()` earlier in the same function |
| `missing-provenance` | Add the marker (step 5) |
| `unwitnessed-enforcement` | Add a test that asks a witness (`Spawned`, `Dialed`) what happened |
| `orphan-invariant` | Load the query by name, or add `invariants/<name>.traceql` and regenerate |
| `provider-override` | Legacy tests often build their own `TracerProvider` with an in-memory exporter. Use the harness's tracer instead; mark a real need with `//subpoena:own_provider <reason>` |
| `dead-telemetry` | A registry entry nothing emits. Emit it, or remove it from the registry (reviewed). Pass `-dead-telemetry` only when the targets cover the whole service |
| `registry-drift` | A registry change and a test that uses it are in one change set; a human confirms the test was not bent to fit |

Cross-examination is the check that matters most. It requires a green baseline, removes
each marked enforcement statement in a temporary copy, and runs the tests. A red
suite is `enforcement-mutant-killed`. A green suite is
`enforcement-mutant-survived`: your tests cannot tell enforced from unenforced.
Strengthen them. Never remove the marker to make it pass.

On a first run cross-examination will often report a survivor, because the legacy tests
assert on return values and mocks. That is the finding, not a failure of the
tool. The gateway's `TestDeniedSessionNeverExecs` kills the mutant because the
witness sees a process that should not exist.

CI runs gofmt, build, vet, `go test -race ./...`, the lint and cross-examination
(`.github/workflows/ci.yml`), and, on a runner with a real kernel and Docker,
the real-cgroup tests, the eBPF witness, conformance and tier 2
(`.github/workflows/kernel.yml`).

## 7. Promote invariants to OATS and alerts

An invariant is a string, so promotion is copy and paste:

- **Tier 2, Grafana OATS.** Put the string under `expected.traces[].traceql`
  with `absent: true`, next to a control with `count: '>= 1'` (the OATS analogue
  of `Inconclusive`: the pipeline is live, so the absence is not vacuous). Add
  the witness query alongside. See `examples/gateway/oats/oats-case.yaml`.
- **Tier 3, production.** The same string, plus a metrics function, as an alert
  rule: `examples/gateway/alerts/no_exec_after_deny.yaml`. Use an instant
  metrics query, reduce it, then threshold it. Set `noDataState: OK` on the
  invariant: when nothing violates, the query returns no series, and that is
  the healthy state. Add a separate liveness rule (`noDataState: Alerting`) on
  the spans the invariant depends on, so missing telemetry still alerts. Copy
  the pair from the example; `make alerts` checks it against a real Grafana.
- **Keep them from drifting.** Add a row to `promotions` in
  `invariants/invariants_test.go` naming the files that must contain the
  invariant verbatim. The test fails on any difference.
- **Keep the subset honest.** `make conformance` runs the invariants and a
  fixture corpus through a real Tempo and through `pkg/traceql` and requires the
  same matches. Add a row to `conformance/expected.yaml` for each new invariant.

Tier 2 has been run (`examples/gateway/oats/README.md` lists what was verified
and the tooling traps found). Tier 3 has been run too (`make alerts`).

## What to delete

Delete these only after cross-examination shows the replacement kills the same faults:

- Mocks used only to assert "was called" (the witness answers that); keep mocks
  for slow or non-deterministic collaborators like clocks and third-party APIs.
- Assertions on log lines standing in for "the decision was made".
- Sleeps and polling for spans to appear; `Collect()` flushes deterministically.
- Hand-written fake exporters and span-capturing helpers; `pkg/harness` is the exporter.
- Test-only hooks in production code (`LastCommand()`, exported counters).
- String constants for span and attribute names; `generated/go/semconv` is the source.
- Duplicate copies of a query in tests, OATS cases and alert rules.

Keep pure unit tests of pure logic; they do not need to assert on telemetry.
Put them in their own file and mark it `//subpoena:pure_logic` above the
package clause, next to the provenance marker, as the gateway's
`policy_test.go` does for `TestPolicy`. The marker exempts the file from
`no-trace-assertion`; a marked file that imports OpenTelemetry, the harness,
the witness, the generated names or the invariants is flagged instead, so the
marker cannot hide a telemetry test that forgot `Collect()`.

Done means: registry generated, no telemetry literals, every telemetry test calls
`Collect()` (pure-logic files marked), invariants loaded by name, every enforcement point marked,
witnessed and killed by cross-examination, every test file marked, lint clean, invariants
promoted with a drift test.
