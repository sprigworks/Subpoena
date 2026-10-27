# Trace-Native Testing: A Design for Hybrid Test + Telemetry Suites

Oct 25, 2026 · Nick Henggeler

> Exported from the design doc written with Claude before the repo existed. Project name chosen afterwards: **Subpoena**. The architecture diagram did not survive export; `docs/architecture.md` describes the same five components in text.
>
> **Status.** This file is the original proposal of 25 October 2026, not the current specification. What exists is in [architecture.md](architecture.md). How to adopt it on a Go service is in [migrating-an-existing-service.md](migrating-an-existing-service.md). The TraceQL that tier 1 evaluates is in [traceql-subset.md](traceql-subset.md).
>
> Two choices below were superseded. Python-first became Go, then Python, then TypeScript ([decisions.md](decisions.md), language-order row). The tier-2 witness in the worked example is Tetragon; the witness that shipped is `pkg/witness/execbpf`, run as `cmd/subpoena-witness`, and Tetragon is kept for enforcement only ([decisions.md](decisions.md), amendment 3). The Python, OATS and alert snippets are the proposal's sketch. The runnable forms are [`examples/gateway/gateway.go`](../examples/gateway/gateway.go), [`examples/gateway/oats/oats-case.yaml`](../examples/gateway/oats/oats-case.yaml) and [`examples/gateway/alerts/no_exec_after_deny.yaml`](../examples/gateway/alerts/no_exec_after_deny.yaml).

## Thesis: improvement by addition

The hybrid is not telemetry instead of tests. It is a suite where the application's OpenTelemetry instrumentation is the primary observation interface for tests, and the same assertions are evaluated in three places: an in-memory exporter in unit tests, a real collector in integration, and a query engine over production traces. One invariant, written once, enforced at three tiers.

What this adds that a conventional suite lacks:

- **Cross-service causality as a first-class assertion.** The trace already encodes who called whom with what; tests assert on that structure instead of rebuilding it with mocks and fixtures.
- **Test-to-monitor promotion.** An assertion that passes in CI can be deployed as a production alert rule with no translation, because test and monitor share a query language.
- **A legible vocabulary for AI agents.** A versioned domain semantic-conventions registry gives an agent a closed set of span names and attributes to emit and assert on, instead of inventing them per task.
- **Independent witnesses.** The harness pairs the application's self-reported spans with observers the application does not control (process hooks, DB triggers, proxies). This closes the gap where a span says "denied" but the action ran anyway.

What it lets you retire: hand-rolled E2E smoke tests, integration tests whose only content is "did the right services participate," and most mock-heavy orchestration tests. What stays untouched: spec-derived unit tests for pure logic, property-based tests, and mutation testing. Section 4 draws that boundary in detail.

The design goal for the agent drop-in (Section 5) is that an agent writing a feature produces correct instrumentation, trace-level tests, and at least one witness assertion for every enforcement point, with a linter rejecting anything else.

## Prior art: the pieces, separately

Each component of the design has a working implementation somewhere. The proposal treated them as separate projects. It does not claim, and this file does not check, that no later package has wired the same pieces together.

| Piece | Who does it | What they have | What they lack for this design |
| --- | --- | --- | --- |
| Domain semconv registry + codegen | [OpenTelemetry Weaver](https://github.com/open-telemetry/weaver) | Custom YAML registries that import upstream semconv; `registry check`, `diff`, `generate` (code + docs), `emit` (synthetic telemetry), a policy engine (Rego) | No test-side artifacts; generates constants and docs, not assertions |
| Registry → compile-time enforcement | [Qyl.OpenTelemetry.SemanticConventions](https://github.com/ANcpLua/Qyl.OpenTelemetry.SemanticConventions) (.NET) | Weaver-generated constants plus Roslyn analyzers that reject non-conformant telemetry at build time | .NET only; no test harness; the closest existing thing to "registry + linter" |
| In-memory capture for unit tests | OTel SDKs: Java [`opentelemetry-sdk-testing`](https://tessl.io/registry/tessl/maven-io-opentelemetry--opentelemetry-sdk-testing) (JUnit extension + AssertJ assertions), Python/Node `InMemorySpanExporter` | Deterministic, no collector, assertions on spans/metrics/logs | Java is the only SDK with a real assertion library; nothing enforces completeness before an absence check |
| Trace-based integration tests | [Tracetest](https://docs.tracetest.io/concepts/tests) | Trigger → wait for trace → YAML selectors + assertions; CI integration | Collector-backed only; repo [last pushed June 2025](https://gittrend.io/repo/kubeshop/tracetest) — adoption risk |
| Acceptance tests against a real stack | [Grafana OATS](https://beta.pkg.go.dev/github.com/grafana/oats@v0.1.1) | YAML cases; expected traces/metrics/logs via TraceQL/PromQL/LogQL against LGTM | The query languages are the right choice for promotion to alerts; no unit tier, no witnesses |
| Assert on traces for AI agents | [agentevals](https://pypi.org/project/agentevals-cli/), [Microsoft ASSERT](https://github.com/responsibleai/ASSERT/releases) | Score agent behavior from recorded OTel traces: tool-trajectory matching, golden eval sets, LLM judges grounded in spans | Scores behavior; does not verify enforcement or external effects; no registry discipline |
| Trace invariants for agent gateways | [Gravitee](https://gravitee.io/corpus/gen-2261/test-plan/opentelemetry-trace-verification.html) (vendor corpus) | Invariants like "a tool span exists only after a successful authorization decision"; LTL framing of always/eventually/never over traces | Vendor-specific; no open harness or registry |
| Independent witness for process execution | [Cilium Tetragon](https://tetragon.io/docs/concepts/) | eBPF `process_exec`/`process_exit` events with `exec_id`, parent lineage, binary, args; can SIGKILL on policy | Not packaged as a test fixture; no trace-ID correlation out of the box |
| Formal lineage | [Runtime verification](https://cris.biu.ac.il/en/publications/runtime-verification-from-propositional-to-first-order-temporal-l-2/) (RV conference since 2001) | LTL/first-order temporal logic over execution traces; 3-valued semantics (true / false / inconclusive) over finite, partial traces | Academic; the 3-valued result is exactly what an absence assertion over possibly-incomplete capture should return |

Two findings change the design. First, the runtime-verification literature already solved "what does a negative assertion mean over a partial trace": the answer is a third verdict, *inconclusive*, and the harness should return it rather than pass or fail. Second, the agent-eval tools (agentevals, ASSERT) show the AI community is already asserting on OTel traces, but on trajectory and quality, not on enforcement. The witness layer is the gap.

## Architecture: five components

_(diagram omitted; see docs/architecture.md)_

The registry feeds both the code (typed constants) and the linter (what is allowed). The application emits spans through the library, the same spans reach three capture tiers, and one assertion set evaluates against all three. Witnesses enter at the assertion layer, beside the spans, never through the application.

**1. Domain semconv registry.** A Weaver registry (YAML) that imports upstream OTel semconv and adds the domain: span names such as `agent.session.authorize`, `agent.session.exec`, attributes such as `authorization.allowed`, `authorization.policy_id`, `session.id`, each with a requirement level and a stability marker. `weaver registry check` validates it in CI; `weaver registry diff` makes a breaking rename visible at review time; `weaver registry generate` emits typed constants for each language.

**2. Instrumentation library.** One decorator per operation kind, generated from the registry, so a span is one line: `@traced(Spans.SESSION_AUTHORIZE)`. Attribute setters are typed; a string that is not in the registry does not compile or lint. The library also handles the dull parts agents get wrong: exception recording, status codes, context propagation across async boundaries.

**3. Trace-fixture harness.** Each test runs with an in-memory exporter. `trace.collect()` force-flushes, checks that the exporter dropped nothing, and returns a queryable span tree, or raises. Assertions are written in TraceQL (or a TraceQL subset evaluated in-process), so they are the same strings at every tier. Absence assertions return a three-valued verdict: pass, fail, or *inconclusive* when capture was incomplete; inconclusive fails CI by default.

**4. Independent witnesses.** Fixtures that observe effects without going through the application: a process-exec watcher (Tetragon or an `execve` hook in the test container), a DB trigger table, a socket proxy, a filesystem watcher. Each witness tags its observations with the active trace ID so they join the span tree. An assertion on a witness is the only thing that proves enforcement rather than a reported decision.

**5. Lint and cross-examination.** Static checks: every span name and attribute in the code and tests resolves to the registry; every test file has at least one trace assertion; every function tagged as an enforcement point has at least one witness assertion somewhere in the suite. Dynamic check: a CI job that patches each enforcement point to take the deny path in telemetry but allow the action, re-runs the suite, and requires red.

**Assertion promotion.** A test's TraceQL becomes an integration check in an OATS-style YAML case against a real collector and Tempo, and becomes a production alert rule with the same query. For example `{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }` returning any trace is a CI failure at tiers 1 and 2 and a security incident at tier 3.

## The test taxonomy after adoption

Three test types are retired, four are improved, and three are untouched. The rule for retirement: a test can go only if its inputs, its oracle, and its failure-detection capability are all preserved by a trace assertion plus, where the test guarded an effect, a witness.

| Test type today | After adoption | Why |
| --- | --- | --- |
| E2E smoke ("request completes, right services involved") | **Retired** → trace-based integration test | The trace is a better record of participation than status codes; the failure narrative names the span that broke |
| Orchestration integration tests (mock A, verify B was called) | **Retired** → span-structure assertion | Parent-child and sibling relationships in the span tree replace mock-call verification, and the test no longer couples to internal call signatures |
| Hand-rolled observation plumbing (log scraping, debug hooks, test-only callbacks) | **Retired** → instrumentation library | One instrumentation serves production and tests; the test-only hooks are deleted |
| Integration tests on cross-service workflows | **Improved** | Same test, assertions move from side-channel checks to TraceQL over the real causal structure |
| Security and authorization tests | **Improved** | Each gains a mandatory witness assertion; the self-report gap is closed |
| Regression detection between releases | **Improved** | Tier-3 alert rules run the suite's invariants continuously against live traffic |
| Contract tests between services | **Improved, partly** | Span-shape assertions pinned to stable registry entries act as a provider contract; consumer-driven contracts (Pact-style) still catch what the provider never emits |
| Spec-derived unit tests on pure logic | **Untouched** | A span records a decision; it cannot say whether the decision was right. Unit tests derive expectations from the spec |
| Property-based tests and fuzzing | **Untouched** | Input generation is outside the observation layer entirely |
| Mutation testing | **Untouched, and now load-bearing** | The only measure of whether trace assertions and witnesses detect injected faults; cross-examination in Section 3 is a targeted mutation run |

The net is fewer test files and more assertions per execution. The proposal expected the integration and E2E directories to shrink, the unit directory to stay the same, and a new `invariants/` directory of TraceQL strings shared by CI and the alerting config. It did not measure by how much.

## The agent drop-in

The drop-in is a repository template plus a skill, and the linter is the part that makes it hold. A skill is advice; agents drift from advice under long contexts and refactors. A linter in CI does not drift. The skill teaches the pattern, the library makes the pattern the shortest path, and the linter rejects everything else.

**Package layout**

```markdown
trace-native/
  SKILL.md                  # the rules + 4 canonical examples, loaded by the agent
  registry/                 # Weaver registry: domain spans, attributes, stability
    registry_manifest.yaml
    spans.yaml
    attributes.yaml
  generated/                # weaver registry generate → typed constants per language
  harness/                  # trace fixture, collect(), TraceQL-subset evaluator
  witnesses/                # process, filesystem, socket, db — each tags trace_id
  lint/                     # registry conformance, assertion presence, witness coverage
  cross/                    # patches enforcement points, re-runs suite, requires red
  invariants/               # TraceQL strings; consumed by tests, OATS, and alert rules
```

**What SKILL.md says** (the body, roughly in priority order):

1. Every externally visible operation emits exactly one span whose name is a registry constant; attributes come from the generated setters, never from string literals.
2. Every test calls `trace.collect()` before asserting, and asserts with a TraceQL string from `invariants/` or a new one added there.
3. Any function marked `@enforcement_point` must have, somewhere in the suite, a witness assertion on the effect it guards. A span attribute reporting the decision is not sufficient.
4. Absence assertions are three-valued; treat *inconclusive* as a failure and fix capture before weakening the assertion.
5. Write tests from the registry and the spec in a fresh session, before reading the implementation. Implementation-aware tests are for exploring branches, not for the oracle.
6. Never add a span name to the registry to make a test pass; propose the registry change in its own PR with `weaver registry diff` output.

**What the linter enforces**

| Rule | Failure |
| --- | --- |
| Span or attribute string not resolvable in the registry | `unknown-telemetry` |
| Test module with no trace assertion | `no-trace-assertion` |
| `@enforcement_point` with no witness assertion anywhere in the suite | `unwitnessed-enforcement` |
| Absence assertion not preceded by `collect()` | `unguarded-absence` |
| Invariant string in a test not present in `invariants/` | `orphan-invariant` |
| Registry change in the same PR as a test that depends on it | `registry-drift` |

**What cross-examination does.** For each `@enforcement_point`, generate a mutant that keeps the span attributes identical and removes the enforcement (skips the early return, swallows the raise, comments out the kill). Run the suite against the mutant. Any mutant that survives is reported as `enforcement-mutant-survived` with the function name. This is mutation testing restricted to the one class of fault the whole design exists to catch.

**Why this works on agents specifically.** Agents copy the nearest working example and satisfy the loudest check. The four examples in SKILL.md are the nearest example; the linter is the loudest check. The registry means an agent choosing a span name is doing lookup, not invention, which is the mode where current models are most reliable. The fresh-session rule addresses the [measured 14%→25% detection gap](https://arxiv.org/abs/2607.05139) between implementation-anchored and spec-derived tests.

## Worked example: an authorization gate across three tiers

The invariant is one TraceQL string. It lives in `invariants/no_exec_after_deny.traceql` and is referenced by name everywhere else.

```markdown
{ name = "agent.session.authorize" && span.authorization.allowed = false }
  >> { name = "agent.session.exec" }
```

Any trace matching it is a violation: a session that was denied and then executed something.

**Registry entries** (`registry/spans.yaml`, abbreviated):

```markdown
- id: span.agent.session.authorize
  stability: stable
  attributes:
    - ref: authorization.allowed      # required, boolean
    - ref: authorization.policy_id    # required
    - ref: session.id                 # required
- id: span.agent.session.exec
  stability: stable
  attributes:
    - ref: session.id
    - ref: process.command_line       # upstream semconv
```

**Application code** (conceptual sketch, not the implementation; the runnable example is Go, [`examples/gateway/gateway.go`](../examples/gateway/gateway.go)):

```markdown
@enforcement_point
@traced(Spans.SESSION_AUTHORIZE)
def authorize(session, span):
    decision = policy.evaluate(session)
    span.set(Attrs.AUTHORIZATION_ALLOWED, decision.allowed)
    span.set(Attrs.AUTHORIZATION_POLICY_ID, decision.policy_id)
    if not decision.allowed:
        raise Denied(session)      # the enforcement; cross-examination will remove this line
    return decision
```

**Tier 1, unit** (conceptual sketch. The runnable tests are [`examples/gateway`](../examples/gateway)):

```markdown
def test_denied_session_executes_nothing(trace, witness):
    with pytest.raises(Denied):
        gateway.open(user="eve", host="prod-db", command="ls")
    t = trace.collect()                                    # raises if capture incomplete
    assert t.query(Invariants.NO_EXEC_AFTER_DENY) == []
    assert t.span(Spans.SESSION_AUTHORIZE).attr(Attrs.AUTHORIZATION_ALLOWED) is False
    assert witness.process.spawned(trace_id=t.id) == []    # the enforcement check
```

The three assertions have different jobs. The invariant query checks the span structure. The attribute check confirms the decision was recorded. The witness check is the only one that fails when `raise Denied` is deleted, because the other two still see a span that says "denied."

**Tier 2, integration** (conceptual `oats.yaml`. The runnable case is [`examples/gateway/oats/oats-case.yaml`](../examples/gateway/oats/oats-case.yaml), which uses `cmd/subpoena-witness`, not Tetragon):

```markdown
input:
  - path: /session
    method: POST
    body: '{"user":"eve","host":"prod-db","command":"ls"}'
expected:
  traces:
    - traceql: '{ name = "agent.session.authorize" && span.authorization.allowed = false }'
      spans:
        - name: agent.session.authorize
    - traceql: '{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }'
      count: 0
  logs:
    - logql: '{ service_name="witness-exec" } | json | trace_id = "${trace_id}"'
      count: 0
```

The witness at this tier is a Tetragon `process_exec` stream exported to Loki, tagged with the trace ID the gateway injects into the environment of anything it spawns. Zero matching log lines is the enforcement check. Superseded: Tetragon does not carry the session cgroup outside Kubernetes, and the shipped tier-2 witness is `execbpf` ([decisions.md](decisions.md), amendment 3).

**Tier 3, production** (conceptual alert rule. The runnable file is [`examples/gateway/alerts/no_exec_after_deny.yaml`](../examples/gateway/alerts/no_exec_after_deny.yaml), checked by `make alerts`):

```markdown
- alert: AgentExecAfterDeny
  expr: '{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }'
  for: 0s
  labels: { severity: critical }
```

The same string, now a pager. Tier 3 cannot evaluate the witness (there is no test container), so the production rule covers the self-report structure only. The production witness is the Tetragon policy itself, set to enforce: a `process_exec` from a session whose authorize span said `false` is killed at the kernel, and that event is its own alert. Superseded for the witness: Tetragon is kept for enforcement only, and that kernel backstop is decided, not built ([decisions.md](decisions.md), amendments 3 and 4).

**Cross-examination run.** It deletes `raise Denied(session)`, re-runs tier 1. The invariant query still returns `[]` (no exec span is emitted on this code path), the attribute check still passes, and `witness.process.spawned()` returns one entry. Red. If a team removes the witness line, the linter reports `unwitnessed-enforcement` before cross-examination ever runs.

## Open questions and risks

> Resolved in `docs/decisions.md`. Kept here as originally written.

- [ ] **TraceQL in-process.** Tier 1 needs a TraceQL evaluator that runs over an in-memory span list without Tempo. No such library exists; the options are a hand-written subset (name, attribute equality, `>>` descendant, `>` child, count), or a Tracetest-style selector language with a documented mapping to TraceQL. The subset is the smaller project and keeps one query language.
- [ ] **Witness trace-ID propagation.** A spawned process has to carry the trace ID for Tetragon events to join the span tree. Environment variable injection works for processes the gateway spawns; it does not cover processes spawned by a compromised child. Decide whether lineage via `parent_exec_id` is enough.
- [ ] **Tracetest viability.** The repo has been quiet since mid-2025. OATS is maintained by Grafana and uses TraceQL directly, which fits the promotion design better. Build tier 2 on OATS and treat Tracetest as a reference, not a dependency.
- [ ] **Registry governance.** Who approves a registry change, and how is a breaking rename handled across services on different versions? Weaver's `diff` reports it; the policy for acting on it is a team decision.
- [ ] **Cardinality in tier 3.** `session.id` on every span is fine in a test; in production it is a high-cardinality attribute that some backends will reject or bill for. The registry should mark which attributes are test-tier only.
- [ ] **What the fresh-session rule costs.** Generating tests before reading the implementation means the agent cannot see which branches exist. The skill allows a second, implementation-aware pass for branch exploration, but those tests are labeled and excluded from oracle coverage metrics. Whether that labeling holds up in practice is untested.
- [ ] **Scope of the first cut.** Python first (the harness, the lint, one witness), with the registry language-neutral from day one. Go and TypeScript codegen from the same registry is a later step. Superseded: Go shipped first ([decisions.md](decisions.md), language-order row).

One risk outside the design: the whole stack assumes instrumentation is trustworthy at the SDK level. An agent that monkeypatches the tracer provider can make any invariant pass. The linter should flag any import of the SDK's provider-setting APIs outside the harness.

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
- [Gravitee — OpenTelemetry trace verification](https://gravitee.io/corpus/gen-2261/test-plan/opentelemetry-trace-verification.html) (URL returned 404 on 2026-10-27; left as the proposal cited it)
- [Tetragon concepts](https://tetragon.io/docs/concepts/)
- [Runtime verification: from propositional to first-order temporal logic (RV 2018)](https://cris.biu.ac.il/en/publications/runtime-verification-from-propositional-to-first-order-temporal-l-2/)
- [arXiv:2607.05139 — On the risk of coding before testing](https://arxiv.org/abs/2607.05139)
- [arXiv:2610.11835 — Risks of LLM-generated regression tests](https://arxiv.org/pdf/2610.11835)
