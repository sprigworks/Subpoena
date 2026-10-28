# Subpoena: Design

Oct 25, 2026 · Nick Henggeler

This is why Subpoena is built the way it is: the problem, the principles, and how each part serves them. What each package does in detail is in [architecture.md](architecture.md). The decisions behind it, with their reasons, are in [decisions.md](decisions.md). To adopt it on a Go service, see [migrating-an-existing-service.md](migrating-an-existing-service.md).

## The problem

A test that checks enforcement usually asks the code whether it enforced. The authorization function returns an error, the span says `authorization.allowed = false`, and the test is green. None of that shows the denied action did not happen. If someone deletes the `return` after the denial, the error is still logged and the span still says "denied". The command runs anyway, and the test stays green.

Subpoena treats what the application reports about itself (spans, return values, logs) as **testimony**, and requires **evidence** from a witness the application does not control before it accepts that enforcement worked.

## Principles

1. **Testimony is not proof.** Every enforcement point needs a witness assertion on the effect it guards: a process that never ran, a connection that was never made. A span reporting the decision is not enough.
2. **Silence proves nothing unless the capture was complete.** An absence check has three outcomes: pass, fail, and *inconclusive*. Inconclusive is a failure. This applies to spans (anything dropped or unfinished) and to witnesses (a witness that could not see reports that it could not see).
3. **One invariant, written once, checked at three tiers.** An assertion is a TraceQL string in `invariants/`. The same string runs over in-memory spans in unit tests, against Tempo in integration, and as a Grafana alert in production. Nothing is translated between tiers, so nothing can drift.
4. **Prove the tests can fail.** For each enforcement point, cross-examination removes the statement that enforces and requires the suite to go red. A suite that stays green cannot tell enforced from unenforced code.
5. **A closed vocabulary.** Span names and attributes come from a versioned registry, and code gets them as generated constants. An agent choosing a name looks it up instead of inventing one. A registry change is a reviewed change of its own, never a way to make a test pass.
6. **The linter is the loudest check, so it must be right.** Agents copy the nearest example and satisfy the loudest check. Where code type-checks, rules resolve calls by type, not by name, and lint says when it had to fall back to names. A false positive teaches people and agents to route around the linter, and a false negative lets the rule be bypassed.
7. **Improvement by addition.** Subpoena adds an observation layer and a witness to an existing suite. It does not replace unit, property-based or mutation tests, and it builds on the upstream OpenTelemetry SDKs rather than its own.

## How the parts serve the principles

| Part | Where | Principle |
| --- | --- | --- |
| Registry and generated names | `registry/`, `generated/` (Weaver) | 5 |
| Harness: in-memory capture, `Collect()`, three-valued verdicts | `pkg/harness` | 2, 3 |
| TraceQL subset evaluator, held to Tempo by a conformance suite | `pkg/traceql`, `conformance/` | 3 |
| Witnesses: `ProcWitness`, `execbpf`, `Sinkhole`, `netbpf` | `pkg/witness` | 1, 2 |
| Invariants shared by tests, OATS cases and alert rules | `invariants/` | 3 |
| Lint | `cmd/subpoena-lint` | 1, 5, 6 |
| Cross-examination | `cmd/subpoena-cross` | 4 |
| Rules for coding agents | `AGENTS.md` | 5, 6 |

Witnesses enter at the assertion layer, beside the spans, never through the application. A witness ties what it saw to a trace through the session's cgroup, which the application creates and names after the trace ID, or through process lineage when no cgroup is available. It never relies on anything the spawned process could change.

## Prior art

Each piece exists somewhere. What Subpoena adds is the combination, with witnesses and cross-examination aimed at enforcement.

| Piece | Who does it | What they have | What they lack for this design |
| --- | --- | --- | --- |
| Domain semconv registry + codegen | [OpenTelemetry Weaver](https://github.com/open-telemetry/weaver) | Custom YAML registries that import upstream semconv; `registry check`, `diff`, `generate` | Generates constants and docs, not assertions |
| Registry → compile-time enforcement | [Qyl.OpenTelemetry.SemanticConventions](https://github.com/ANcpLua/Qyl.OpenTelemetry.SemanticConventions) (.NET) | Weaver-generated constants plus Roslyn analyzers | .NET only; no test harness |
| In-memory capture for unit tests | OTel SDKs: Java [`opentelemetry-sdk-testing`](https://central.sonatype.com/artifact/io.opentelemetry/opentelemetry-sdk-testing), Python/Node `InMemorySpanExporter` | Deterministic, no collector | Nothing checks completeness before an absence assertion |
| Trace-based integration tests | [Tracetest](https://docs.tracetest.io/concepts/tests) | Trigger, wait for trace, assert with selectors | Collector-backed only; repo [quiet since June 2025](https://gittrend.io/repo/kubeshop/tracetest) |
| Acceptance tests against a real stack | [Grafana OATS](https://github.com/grafana/oats) | YAML cases with TraceQL/PromQL/LogQL against LGTM | No unit tier, no witnesses |
| Assert on traces for AI agents | [agentevals](https://pypi.org/project/agentevals-cli/), [Microsoft ASSERT](https://github.com/responsibleai/ASSERT/releases) | Score agent behaviour from OTel traces | Score behaviour; do not verify enforcement or external effects |
| System-call observers in tests | [AssertSyscall](https://www.nuget.org/packages/assertsyscall.nunit), [netaudit](https://github.com/CyberSecAuto-Labs/netaudit) | strace outside the process under test; netaudit attributes each `connect()` to the test that made it | Attribute to a test, not to a trace; no third verdict for incomplete capture |
| Mutation testing aimed at security | [Loise et al. 2017](https://xdevroey.be/publications/loise-2017/), [AutoMutSec](https://sol.sbc.org.br/index.php/sast/article/view/45863) | Security-aware mutation operators; AutoMutSec mutates Spring Security authorization policies | Judge the suite by its assertions; no mutant that keeps the audit record while removing the effect |
| Independent witness for process execution | [Cilium Tetragon](https://tetragon.io/docs/concepts/) | eBPF `process_exec` events with lineage; can kill on policy | No trace correlation; outside Kubernetes it does not report the session cgroup |
| Formal lineage | [Runtime verification](https://cris.biu.ac.il/en/publications/runtime-verification-from-propositional-to-first-order-temporal-l-2/) | Temporal logic over finite traces with a third verdict, *inconclusive* | Academic |

Two of these shaped the design directly. Runtime verification had already answered what a negative assertion means over a partial trace: a third verdict. The agent-eval tools show people already assert on OTel traces, but on behaviour and quality, not on enforcement. The witness layer is the gap.

## Where it fits in a test suite

A test can be retired only if its inputs, its oracle, and its ability to detect failure are all preserved by a trace assertion, plus a witness where it guarded an effect.

| Test type | With Subpoena | Why |
| --- | --- | --- |
| E2E smoke ("request completes, right services involved") | Candidate to replace with a trace-based integration test | The trace records participation better than status codes do |
| Orchestration tests (mock A, verify B was called) | Candidate to replace with a span-structure assertion | Parent-child spans replace mock-call verification without coupling to internal signatures |
| Test-only observation plumbing (log scraping, debug hooks) | Candidate to replace with the production instrumentation | One instrumentation serves production and tests |
| Security and authorization tests | Improved | Each gains a witness assertion |
| Regression detection between releases | Improved | Tier-3 rules run the same invariants on live traffic |
| Contract tests between services | Partly improved | Span shapes pinned to stable registry entries act as a provider contract; consumer-driven contracts still catch what a provider never emits |
| Spec-derived unit tests on pure logic | Unchanged | A span records a decision; it cannot say whether the decision was right |
| Property-based tests and fuzzing | Unchanged | Input generation is outside the observation layer |
| Mutation testing | Unchanged, and cross-examination is a targeted form of it | The only measure of whether assertions and witnesses detect injected faults |

## Coding agents

The rules are in [`AGENTS.md`](../AGENTS.md), which Claude Code and other agents load. Advice drifts under long contexts and refactors. A linter in CI does not. So the rules that matter are also lint rules:

| Rule | Flags |
| --- | --- |
| `unknown-telemetry` | A span name or attribute key not in the registry |
| `no-trace-assertion` | A test file that never calls `Collect()` (pure-logic files are marked and exempt) |
| `unwitnessed-enforcement` | An `//subpoena:enforcement_point` with no witness assertion in the suite |
| `unguarded-absence` | An absence assertion with no `Collect()` before it |
| `missing-provenance` | A test file not marked `spec_derived` or `impl_derived` |
| `orphan-invariant` | A TraceQL literal in a test that is not an `invariants/` file |
| `provider-override` | A tracer provider built or installed outside `main`, which would send spans past the harness |
| `dead-telemetry` | A registry name no code uses (opt-in) |
| `registry-drift` | A registry change in the same PR as a test that depends on it |

Each rule is described in [lint/README.md](../lint/README.md). The provenance markers carry one more rule: tests are written from the registry and the docs before reading the implementation. Tests anchored on the implementation detect fewer faults ([arXiv:2607.05139](https://arxiv.org/abs/2607.05139) measured 14% against 25%).

## Worked example: an authorization gate

The runnable version is [`examples/gateway`](../examples/gateway).

**The invariant**, `invariants/no_exec_after_deny.traceql`. Any matching trace is a session that was denied and then executed something:

```
{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }
```

**The enforcement point** ([`gateway.go`](../examples/gateway/gateway.go)). The function is marked, and so is the one statement that enforces:

```go
//subpoena:enforcement_point
func (g *Gateway) Authorize(ctx context.Context, s *Session, host string) (context.Context, error) {
	ctx, span := g.tracer.Start(ctx, semconv.SpanAgentSessionAuthorize)
	defer span.End()
	decision := Evaluate(s.User, host)
	span.SetAttributes(
		attribute.String(semconv.AttrSessionId, s.ID),
		attribute.Bool(semconv.AttrAuthorizationAllowed, decision.Allowed),
		attribute.String(semconv.AttrAuthorizationPolicyId, decision.PolicyID),
	)
	if !decision.Allowed {
		span.SetStatus(codes.Error, "denied by "+decision.PolicyID)
		return ctx, fmt.Errorf("%w: %s on %s", ErrDenied, decision.PolicyID, host) //subpoena:enforcement
	}
	return ctx, nil
}
```

**Tier 1, unit** ([`gateway_test.go`](../examples/gateway/gateway_test.go), `TestDeniedSessionNeverExecs`, shortened):

```go
_, err := r.gw.Run(ctx, sess, "prod-db1", "sleep", sleepArg)
if !errors.Is(err, gateway.ErrDenied) {
	t.Fatalf("expected ErrDenied, got %v", err)
}
r.w.Stop() // final poll before asking the witness
if err := r.w.Health(); err != nil {
	t.Fatalf("witness capture incomplete: %v", err)
}
tr, err := r.h.Collect(context.Background())
if err != nil {
	t.Fatal(err)
}
harness.RequireAbsent(t, tr, invariants.MustLoad(invariants.NoExecAfterDeny)) // structure
harness.RequireExists(t, tr, authorizeDenied)                                 // the decision was recorded
harness.RequireNoSpawn(t, r.w, tr.TraceIDs()[0])                              // the evidence
```

The three assertions check different things: the structure of the trace, the recorded decision, and what actually ran. Only the last one is evidence. The first two are the application's own account.

**Tier 2, integration** ([`oats-case.yaml`](../examples/gateway/oats/oats-case.yaml)). The same invariant runs on Tempo, next to a control request that is allowed. `subpoena-witness` (the `execbpf` witness) reads each exec's cgroup in the kernel and ships its events to Loki. Exactly one exec inside a session cgroup must appear for the whole run: one proves the pipeline is live, and two would mean the denied session ran something. This case needs no argument matching. A second case, [`oats-case-argument.yaml`](../examples/gateway/oats/oats-case-argument.yaml), runs the gateway unprivileged, where it cannot create session cgroups, and tells the witness's events apart by a unique command-line argument instead.

**Tier 3, production** ([`no_exec_after_deny.yaml`](../examples/gateway/alerts/no_exec_after_deny.yaml)). The same string with `| count_over_time()` becomes a Grafana alert. A second rule alerts when authorize spans stop arriving, because "no violations" and "no telemetry" look the same to the invariant. `make alerts` drives both through silence, clean traffic, and a violation. Production has no test witness, so this tier checks the application's own report only. A kernel exec backstop for production is decided but not built ([decisions.md](decisions.md)).

**Cross-examination.** `subpoena-cross` removes each line marked `//subpoena:enforcement`, runs the suite on a copy of the module, and requires red. Removing `Authorize`'s deny return lets the session run, and the suite fails on several counts: no `ErrDenied`, an exec span under the denied authorize span, and a process the witness saw. `Fetch` ([`fetch_test.go`](../examples/gateway/fetch_test.go)) shows why the witness is required. Removing its deny return leaves the authorize span saying "denied" and emits no span for the connection, so every span assertion still passes. Only the sinkhole, which sees the connection arrive, turns the suite red.

## Open questions

- **Cross-service registry migration.** `weaver registry diff` shows a breaking rename at review time, and CODEOWNERS approves it. How services on different registry versions move together is a team decision that no tool makes.
- **Whether the provenance markers hold up.** Lint requires every test file to say whether it was written from the spec or from the implementation. Nothing yet checks that the label is true, and nothing counts spec-derived tests apart.
- **What cross-examination costs on a large suite.** It runs the suite once per enforcement mutant, one after another. That is seconds on the example gateway. On the first outside adopter, measured on 2026-10-27, it was about 21 minutes for a suite that takes about three and a half minutes on its own. `-j` now runs mutants in parallel and `-select` runs each mutant against only the tests that cover it. Re-examining only the enforcement points a change touches is still open.
- **SDK-level trust.** Everything assumes spans reach the harness. `provider-override` catches a tracer provider installed outside `main`. It cannot catch code that patches the SDK at runtime.

The proposal this document grew from is in the repository history ([`7a11727:docs/design.md`](https://github.com/sprigworks/subpoena/blob/7a11727/docs/design.md)).

## Sources

- [OpenTelemetry Weaver](https://github.com/open-telemetry/weaver) and [Weaver Forge](https://github.com/open-telemetry/weaver/blob/main/crates/weaver_forge/README.md)
- [Last9 — custom registries with Weaver](https://last9.io/blog/otel-weaver-consistent-observability-with-semantic-conventions)
- [Qyl.OpenTelemetry.SemanticConventions](https://github.com/ANcpLua/Qyl.OpenTelemetry.SemanticConventions)
- [opentelemetry-sdk-testing (Java)](https://tessl.io/registry/tessl/maven-io-opentelemetry--opentelemetry-sdk-testing)
- [In-memory span exporters across languages](https://oneuptime.com/blog/post/2026-02-06-in-memory-span-exporters-unit-tests/view)
- [Tracetest — tests concept](https://docs.tracetest.io/concepts/tests); [repo activity](https://gittrend.io/repo/kubeshop/tracetest)
- [Grafana OATS](https://beta.pkg.go.dev/github.com/grafana/oats@v0.1.1)
- [Tempo TraceQL structural operators](https://grafana.com/docs/tempo/latest/release-notes/v2-3.md)
- [agentevals](https://pypi.org/project/agentevals-cli/)
- [Microsoft ASSERT](https://github.com/responsibleai/ASSERT/releases)
- [Tetragon concepts](https://tetragon.io/docs/concepts/)
- [Runtime verification: from propositional to first-order temporal logic (RV 2018)](https://cris.biu.ac.il/en/publications/runtime-verification-from-propositional-to-first-order-temporal-l-2/)
- [arXiv:2607.05139 — On the risk of coding before testing](https://arxiv.org/abs/2607.05139)
- [arXiv:2610.11835 — Risks of LLM-generated regression tests](https://arxiv.org/pdf/2610.11835)
