# Test-Driven Development vs. Telemetry-Driven Development

## Can OpenTelemetry spans, metrics, and logs with semantic assertions replace traditional test suites?

**Date:** October 22, 2026
**Scope:** A technical analysis of whether OTel spans, metrics, and logs with semantic assertions can replace unit and integration tests — including coverage gaps, edge cases, determinism, maintenance overhead, and specific implications for AI-generated codebases.

---

## 1. Executive Verdict

**Short answer: No — but the boundary is more interesting than the question suggests.**

Three different practices get lumped under "telemetry-driven development," and they have very different substitution power:

1. **Passive production telemetry with assertions** (SLO monitors, anomaly alerts, semantic-convention checks against live signals). This cannot replace tests. It only observes executions that actually occurred, may omit executions entirely when sampling is enabled, and cannot demonstrate correctness for behavior no input has exercised.
2. **Controlled trace-based testing** — deliberately triggering execution, then asserting against the resulting OpenTelemetry telemetry (Tracetest; Grafana's OATS, a declarative acceptance-test framework where YAML cases drive an instrumented application — or seed telemetry directly — and check expected traces, logs, metrics, and profiles via TraceQL/PromQL/LogQL queries against a real observability stack). This is testing: integration or end-to-end tests with a different observation interface. It can legitimately replace a slice of traditional integration and E2E assertions — but it inherits integration testing's limitations and, depending on the capture architecture, adds pipeline dependencies on top.
3. **Observability-driven development as a workflow** (Charity Majors' advocacy of moving beyond TDD toward production-guided development, Martin Thwaites' telemetry-in-TDD practice). This is a development discipline, not a verification mechanism.

The decisive test for any proposed replacement is not "does it use OpenTelemetry" but: **does it preserve the original test's inputs, its oracle, and its failure-detection capability?** The decisive question is what is observed, who produces that observation, and where the expected result comes from — not which medium the observation travels through. A telemetry assertion can inspect an independently produced observation (for example, a process monitor reporting whether a protected command executed), while an ordinary unit test can merely check an implementation's misleading return value. Trace-based testing passes the substitution test for executed behavior; passive production assertions do not pass it for anything an adversarial test would have exercised.

For AI-generated codebases the stakes are higher and the answer skews further toward "no." An empirical study across three benchmarks and five models found that tests generated after the model saw the faulty implementation detected 14% of faults versus 25% when generated independently — the authors call this "error propagation," where faults in generated code are systematically replicated in associated test artifacts ([arXiv:2607.05139](https://arxiv.org/abs/2607.05139)). An agent that writes the code, the instrumentation, and the telemetry assertions from the same misunderstanding can produce a fully green, fully observed, fully wrong system.

**Recommended position:** OpenTelemetry is an observation layer, not an input generator or a correctness oracle. Telemetry assertions can absorb redundant integration assertions when the harness controls inputs and the expected outcomes are trustworthy; passive production assertions cannot provide equivalent pre-release verification; and neither removes the need for adverse-input exploration, independent expected outcomes, and checks of actual effects. The right architecture is a hybrid (Section 8).

---

## 2. Definitions and Landscape

### 2.1 Classical TDD

Red-green-refactor: write a failing test against a specification, write the minimal implementation, refactor. Two properties matter for this analysis:

- **Controlled execution:** the test decides exactly what enters the system, including inputs that have never occurred in production.
- **Expected-result derivation:** the expected output comes from the specification, not from the implementation's self-report.

Note that neither property is automatic. A test whose expectation was copied from the implementation's output has controlled execution but no independent oracle — the same weakness telemetry assertions can have.

### 2.2 What "telemetry-driven development" actually consists of

| Form | Mechanism | Representative tooling |
|---|---|---|
| Production assertions | Monitors/SLOs/alerts evaluated over live OTel signals | Honeycomb SLOs, Grafana alerting |
| Trace-based testing | Test triggers execution; assertions run against the resulting telemetry | [Tracetest](https://docs.tracetest.io/), [Grafana OATS](https://github.com/grafana/oats) |
| ODD workflow | Instrument first, explore production data, use telemetry as a design feedback loop | [Honeycomb's ODD advocacy](https://www.honeycomb.io/blog/a-next-step-beyond-test-driven-development2) |

"Semantic assertions" is used throughout as a concept — assertions over semantically meaningful telemetry — rather than a claim about a specific standard framework. Semantic conventions are the shared vocabulary that makes such assertions portable across producers.

### 2.3 What OpenTelemetry actually guarantees (and doesn't)

This matters more than most discourse admits. Key properties from the specification and docs:

- **Sampling may omit executions.** Head sampling decides early without seeing the whole trace and "cannot ensure that every trace containing an error is sampled"; tail sampling can consider whole traces but is stateful, expensive ("may require dozens or hundreds of compute nodes"), and often vendor-limited ([OpenTelemetry sampling docs](https://opentelemetry.io/docs/concepts/sampling/)). A 1% head-sampled production system carries a statistically representative sample — not a verification record. Sampling is also configurable, so this is a property of a deployment, not of OTel itself.
- **Evidence can also be lost outside sampling** — export failures, collector outages, and dropped spans create blind spots that look like "nothing happened."
- **Semantic conventions have maturity tiers, not uniform guarantees.** Instrumentations are labeled Stable or Unstable; unstable ones "provide no guarantees about the shape of their telemetry or how it changes between versions," and even stable producers are bound by restrictive change rules (additive changes allowed; renaming/removing is breaking) ([Telemetry Stability spec](https://opentelemetry.io/docs/specs/otel/telemetry-stability/)). Semantic conventions define a **common set of semantic attributes which provide meaning to data** ([semconv docs](https://opentelemetry.io/docs/specs/semconv/)) — but a standardized name for `http.request.method` says nothing about whether the application behaved correctly. Conventions are a schema, not an oracle.

---

## 3. Comparison Matrix

| Axis | Classical TDD (unit/integration) | Trace-based testing (Tracetest/OATS) | Passive production assertions |
|---|---|---|---|
| **Input control** | Full — you choose every input | Full — test trigger controls inputs | None — whatever users did |
| **Cases production never exercised** | Yes — tests deliberately execute boundary and fault cases | Yes, same bounds as any integration test — limited by what you think to trigger | No — only observed behavior |
| **Oracle independence** | Depends on where expectations come from | Depends on what is observed and who observes it | Weakest when asserting on the system's own self-description |
| **Pure computation correctness** | Excellent (unit tests) | Possible but indirect — telemetry can record a computed value, but asserting a return value directly is simpler and more local; the practical cost is extra instrumentation and coupling | Poor — aggregation hides per-case detail |
| **Cross-service behavior** | Expensive (contract/stub setup) | Excellent — the trace is the cross-service narrative | Good for observed executions |
| **Determinism** | High (controlled harness) | Deterministic in a controlled harness; distributed collection adds timing and availability risks | Low — timing, sampling, load variance |
| **Failure localization** | Exact function (unit) / boundary (integration) | Span-level in context — good narrative, coarser than unit | Coarsest — "SLO burned" |
| **Cost profile** | CI compute + fixture maintenance | CI compute + capture infrastructure (varies by architecture) + selector maintenance | Collector + backend + cardinality costs, continuous |
| **Feedback latency** | Seconds (unit) | Seconds–minutes | Depends on relevant traffic and evaluation windows |
| **Detects wrong-side-effect bugs** | Only if asserted | Only if the effect is independently observed | Sometimes — if metrics capture it |

Two distinctions from this matrix drive the rest of the analysis:

- **Assertion depth ≠ case coverage.** Rich semantic assertions over one happy-path trace verify that one executed path deeply — they do not broaden the set of exercised cases. Tracetest's expression language (`attr:`, `var:`, `json_path`, `regex`, `contains` comparators that tolerate additional attributes, like Jest's `toMatchObject`) is genuinely powerful for deep verification of what ran ([Tracetest expressions](https://docs.tracetest.io/concepts/expressions)) — but the trigger defines the input, and the trigger is just a test fixture.
- **A violated invariant and a located defect are different outcomes.** Production assertions tell you that something is wrong; a failing unit test tells you where and why.

---

## 4. What Telemetry Assertions CAN Replace

Being fair to the telemetry side — there are real substitutions available:

1. **Redundant E2E smoke assertions.** If your E2E suite mostly checks "the request completed and the right services were involved," a trace-based test with assertions on span structure, service names, and key attributes does the same job with better failure narratives. Tracetest's model — trigger via HTTP, ingest the resulting trace, assert against spans ([Tracetest docs](https://docs.tracetest.io/getting-started/create-trace-based-test)) — is a direct E2E test replacement.
2. **Some integration-test plumbing.** Trace assertions can replace hand-rolled orchestration checks like "did the worker service participate in handling this request." The trace shows the worker's span and its inputs in causal order. Caveat: a worker span does not by itself establish that the intended transaction committed correctly — that still needs an assertion on the actual outcome, whether collected directly or through independently produced telemetry.
3. **Post-deploy verification / synthetic monitoring.** Production assertions over semantically stable signals are a strong form of canary analysis: check that new-version spans of an operation carry expected attributes and latency profiles.
4. **Regression detection on observed behavior.** SLO burn alerts detect regressions in the paths users actually exercise — continuously, as traffic occurs rather than at release boundaries.

In all four cases the substitution works because inputs are either controlled (trace-based testing) or the claim is statistical rather than universal (production monitors). Failures occur when the statistical form is treated as proof of the universal.

---

## 5. Coverage Gaps and Adversarial Examples

### 5.1 The core epistemic gap

A dynamic test verifies the cases it executes — no more. Its power over production telemetry is that it can **deliberately execute cases production traffic has never hit**: boundary values, malformed input, injected faults, duplicate submissions. Production telemetry only reports what actually occurred, may omit executions when sampling is enabled, and can lose evidence through collection and export failures. No volume of production assertions lets you conclude anything about behavior no input has exercised — including the adversarial inputs a security reviewer would test first.

### 5.2 The self-report problem (worked example)

Consider an authorization gate — directly analogous to an agent-SSH gateway. The service handles a request and emits a span:

```
span: ssh.session.authorize
  attr: authorization.allowed = false
  status: OK
```

The span says the request was denied. Two different properties:

- **Property A:** the service decided to deny (self-report). The span assertion verifies this.
- **Property B:** the connection was actually refused — no shell spawned, no command executed (external effect). The span assertion verifies nothing about this.

A bug where the deny path is taken in the policy engine but the session proceeds anyway (a skipped early return after refactoring, a race between check and enforcement) produces clean telemetry and a compromised system. Asserting `authorization.allowed=false` verifies the reported decision, not enforcement. An assertion on the actual protected effect is also required — and that observation may be collected directly or through independently produced telemetry; the medium is not what matters, the independence of the observer is.

A concrete check for any proposed replacement suite: introduce a fault that preserves the expected denial telemetry while allowing the protected action, and verify the suite fails. If it stays green, the suite verifies testimony, not enforcement.

### 5.3 Systematic gap inventory

| Gap | Why passive telemetry misses it | What catches it |
|---|---|---|
| **Branches no traffic reaches** | No execution ever occurred there | Deliberate test cases, coverage-guided generation |
| **Boundary/negative inputs** | Users rarely send malformed input deliberately | Fuzzing, property-based tests |
| **Pure computational logic** | Spans describe the call, not the computed value | Unit tests |
| **Race conditions / interleavings** | Rare timing windows; potentially sampled out at exactly the interesting moment | Stress tests, controlled schedulers, fault injection |
| **Failure before instrumentation init** | Crash before the first span or exporter exists | Process-level tests, health checks |
| **Exporter/collector failure** | The observation pipeline itself is down — a silent blind spot | Synthetic checks outside the pipeline |
| **Duplicate/idempotency violations** | Each duplicate execution can produce valid-looking spans | Explicit idempotency tests with duplicate submission |
| **Partial failure across services** | Trace may never complete; tail-sampling state lost | Transactional/outbox tests |
| **Security invariants** | Attacker-shaped traffic is by definition not representative | Adversarial test suites, security scanning |
| **Metric aggregation aliasing** | Averages and histograms hide per-case violations | Per-case assertions (unit tests) |

### 5.4 Signal-by-signal capability

The question covers spans, metrics, and logs — they are not interchangeable:

| Signal | Useful assertions | Important limitations |
|---|---|---|
| **Spans** | Per-operation attributes, dependency behavior, retries, parent-child relationships | Missing propagation, omitted or late spans, incomplete capture; span hierarchy is not a total execution order |
| **Metrics** | Counts, error ratios, resource budgets, aggregate invariants | Each data point carries attributes and a time window `(start, end]` with a temporality (cumulative or delta), so aggregation loses case identity and interpretation depends on temporality, resets, background traffic, and collection windows ([metric data model](https://opentelemetry.io/docs/specs/otel/metrics/data-model/)) |
| **Structured logs** | Business events, validation failures, audit-event content | A log record carries optional trace/span IDs for correlation, but the model specifies no delivery guarantees; completeness, duplication, ordering, and producer trust all affect what a log absence proves ([log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)) |

**Negative assertions deserve special care.** "No forbidden-action span or log appeared" does not establish that no forbidden action occurred unless capture completeness and the observation window are established. An incomplete capture should fail the test or be marked inconclusive — never silently pass an absence assertion.

### 5.5 The empirical softness of the "tests are dead" claim

The strongest honest version of the telemetry argument is Charity Majors' observability-driven development: use production observability to explore real states and follow curiosity — a workflow for discovering questions you did not know to ask ([Honeycomb](https://www.honeycomb.io/blog/a-next-step-beyond-test-driven-development2); her DevOps Institute talk frames the progression as "TDD + Production == ODD" ([talk slides](https://www.devopsinstitute.com/wp-content/uploads/2021/01/2020-Observ-Charity-Majors-ppt.pdf))). The pragmatic literature is more measured than the rhetoric: production testing "complements, but does not replace, traditional methods like unit testing and integration testing" ([BugBug](https://bugbug.io/blog/software-testing/production-testing/)), and Keploy positions production validation as "an additional layer" ([Keploy](https://keploy.io/blog/community/production-testing)).

---

## 6. Determinism and Maintenance Overhead

### 6.1 Determinism: two separate problems

Distinguish **controlling the system under test** from **reliably collecting the evidence**:

- **Test determinism** (input/output): identical to integration testing. A trace-based test is exactly as deterministic as the system it triggers.
- **Evidence determinism** (getting the telemetry to the assertion): depends entirely on the capture architecture. In a controlled harness, telemetry can be captured in memory through SDK test facilities and asserted synchronously — removing distributed-collection dependencies, though batching, flushing, clocks, and the system's own dependencies still require control for full determinism. When evidence flows through a distributed collector pipeline, the test inherits asynchrony: traces are exported after execution, so the test must wait for, select, and possibly retry trace retrieval. A slow collector becomes a flaky test. A unit test has no such dependency: the assertion and the computation are in the same process.

### 6.2 Maintenance overhead — the honest ledger

Trace-based testing's pitch is that instrumentation is written once and serves both production observability and the test suite. True — but the ledger has more entries:

**Costs unique to telemetry-as-test:**
- **Selector and shape brittleness.** OTel's stability rules permit additive changes freely (new attributes, new spans) for both stable and unstable instrumentations ([stability spec](https://opentelemetry.io/docs/specs/otel/telemetry-stability/)). Additive changes do not break `contains`-style comparators, which tolerate additional attributes — but they can break exact-match object comparisons, span-count assertions, and strict topology expectations. Tests written only against unstable instrumentations inherit their "no guarantees" churn.
- **Infrastructure as a test dependency — when you choose it.** Collector, agent, network path, and backend become CI dependencies in distributed-capture setups. A unit test needs a compiler; a pipeline-backed trace test needs a distributed system to observe the distributed system. In-memory capture avoids this at the cost of testing the capture path less realistically.
- **Cardinality and privacy in production assertions.** Assertions over high-cardinality attributes (user IDs, SSH session IDs) stress backends and can expose sensitive data in telemetry stores — an audit-logging-sensitive concern.
- **Async wait management.** Every distributed-capture test needs trace-completeness logic (how long to wait for late spans?), which is a homegrown flakiness generator.

**Costs where telemetry wins:**
- **One instrumentation, two uses.** The same spans serve debugging and CI, replacing the hand-rolled observation plumbing for cross-service assertions — though input fixtures and environment setup are still required.
- **No environment drift for production monitors.** The monitor watches the real system, not a staging approximation.

**Net assessment:** trace-based testing replaces integration/E2E assertion content but may swap fixture maintenance for capture-pipeline maintenance, depending on architecture. For teams already operating OTel in production, marginal cost is low and the swap is favorable. For teams without existing observability infrastructure, distributed-capture trace testing adds new infrastructure cost — though a production observability stack is not a prerequisite for controlled telemetry assertions.

---

## 7. Implications for AI-Generated Codebases

This is where the substitution question becomes sharpest, and where the evidence is most against the telemetry-only position.

### 7.1 The oracle-independence problem, empirically

A 2026 empirical study ("On the risk of coding before testing") evaluated LLM-based test generation across HumanEval+ (164 Python problems), MBPP (974 tasks), and BigCodeBench (1,140 tasks spanning 139 Python libraries), using five models (GPT-5-mini, GPT-4.1-mini, DeepSeek-V4-Flash, Claude Haiku 4.5, Llama 3.3 Instruct 70B) ([arXiv:2607.05139](https://arxiv.org/abs/2607.05139)). Its core finding, in the authors' words: "error propagation, where faults in generated code are systematically replicated in associated test artifacts... leads to cases where incorrect implementations and tests are mutually consistent, masking defects rather than revealing them."

Key results:

- Tests generated independently detected **25%** of faults; tests generated after faulty code, **14%** — reported detection rates on the study's deliberately selected, retained faults ([arXiv:2607.05139 full text](https://arxiv.org/html/2607.05139v1)).
- Prompting mitigations (chain-of-thought, chain-of-verification) did not remove the effect of implementation exposure.
- A test-driven workflow (tests generated from the specification in a fresh session) outperformed a code-then-test agentic workflow across all five models.
- The authors state the study "does not directly evaluate oracle correctness" — error propagation is their interpretation of the reduced detection, supported indirectly.

Two scope caveats: the fault detection rates come from a benchmark of deliberately selected, retained faults in self-contained programming tasks — not industrial codebases — and coverage stayed above 95% while detection dropped, so the authors conclude **assertion quality, not execution breadth, is the decisive variable**.

The mapping to telemetry is direct: when telemetry assertions target the implementation's self-reported decisions, they are expectations written against the implementation's self-description. If an agent generates the code and the instrumentation from the same misunderstanding, the telemetry will faithfully describe the wrong behavior — and any assertion generated against that telemetry from the same context will encode the same misunderstanding. All artifacts agree; the system is wrong; nothing is red.

Crucially, this is a property of **shared context**, not of telemetry per se. Deriving expectations from the specification rather than the implementation reduces implementation-induced anchoring — it does not by itself guarantee oracle correctness or eliminate shared misunderstandings between spec-reading and code-writing. Conversely, a unit test whose expected values were copied from the implementation has the same problem. What makes the difference is whether the expectation's source is independent of the implementation's own understanding.

### 7.2 What actually improves trust in AI-generated code

- **Separate contexts for spec, code, and validation.** Generate tests from the specification in a fresh session rather than from the implementation-writing session. This is a recommendation about oracle independence, not a prohibition on implementation-aware generation, which remains useful for exploring branches and diagnosing failures; it just cannot by itself provide an independent correctness oracle.
- **Assertions on external effects.** Prefer asserting on observable side effects (DB rows, sockets closed, files written, processes spawned) — especially for security-adjacent behavior where the self-report gap is a vulnerability class. The observation can be collected directly or via independently produced telemetry.
- **Mutation testing as a strong signal — with caveats.** Coverage measures execution, not fault detection. Mutation testing "remains the most honest signal for evaluating the real fault-detection capability of a test suite" ([Thoughtworks Technology Radar](https://www.thoughtworks.com/zh-cn/radar/techniques/summary/mutation-testing)) and is specifically recommended for AI-generated tests ([Augment Code guide](https://www.augmentcode.com/guides/mutation-testing-ai-generated-code)). It is still a proxy: mutant selection and representativeness matter, and it does not establish specification completeness or eliminate shared misunderstandings between code and tests. The research community is actively questioning how well coverage and mutation scores of LLM-generated suites track real fault-detection effectiveness ([ISSTA 2026](https://conf.researchr.org/details/issta-2026/issta-2026-research-papers/2/Do-Coverage-and-Mutation-Scores-of-LLM-Generated-Test-Suites-Correlate-With-Their-Eff)).
- **Human-authored invariants, including telemetry-shape invariants.** A small set of human-written, spec-derived invariants — including invariants over telemetry shape ("every `session.start` span must have a matching `session.end`") — that the agent must not modify.
- **A worked adversarial check.** For any replacement suite, inject a fault that preserves the expected telemetry while changing the actual behavior, and confirm the suite fails. This directly tests the replacement's failure-detection capability rather than its green-ness.

### 7.3 Where telemetry genuinely shines for AI codebases

Fairness cuts both ways. AI-generated codebases have specific properties that favor telemetry-driven approaches as a complement:

- **AI code changes fast and in bulk**, and mutation/coverage feedback loops are slow. Production assertions over stable semantic conventions provide cheap continuous regression detection between releases.
- **AI code is often refactor-heavy, and behavior preservation is the main risk.** Golden-trace comparison is a strong behavior-preservation check for executed paths.
- **Agentic systems have emergent behavior** — as Thwaites notes, teams "cannot know how a system will react to a given input," making production telemetry exploration disproportionately valuable for AI applications ([InfoQ](https://www.infoq.com/news/2026/04/observability-telemetry/)).

---

## 8. Recommended Hybrid Verification Strategy

A layered stack, with the substitution boundary drawn explicitly:

| Layer | What it is | What it uniquely provides |
|---|---|---|
| **Unit tests** (spec-derived, fresh-session generation for AI code) | Classical TDD | Pure logic, deliberate case execution, exact localization |
| **Property-based tests / fuzzing** | Generated input exploration | Boundary and malformed inputs, idempotency, invariants |
| **Mutation testing** (sampled runs in CI) | Fault-injection on the test suite | Measures whether the tests detect injected faults — the oracle-quality check |
| **Trace-based integration tests** (Tracetest/OATS) | Controlled execution + OTel assertions | Cross-service causality, E2E smoke replacement, async workflow verification |
| **External-effect assertions** | Checks on DB/files/sockets outside the code | Verification independent of self-report — mandatory for security invariants |
| **Production assertions / SLOs** | Monitors over live telemetry | Statistical regression detection, discovery of unimagined states |
| **Fault injection / chaos** | Deliberate degradation | Partial failure, races, exporter outages — the gaps in both previous layers |

**Rules of thumb:**

1. Derive expected outcomes from specifications or independent observations, not from the implementation's own output — whether the check is a unit test or a telemetry assertion.
2. For any security or authorization behavior, at least one assertion must target the actual effect, not only the emitted decision.
3. Treat coverage as necessary-not-sufficient; use mutation testing to check that tests can detect injected faults, while remembering it is a proxy with its own limits.
4. Use trace-based testing to replace E2E smoke assertions and integration orchestration checks — and retain deliberate adverse-input generation and effect-level oracles regardless of whether assertions consume telemetry or inspect results directly.
5. Treat production telemetry assertions as a statistical safety net with a known sampling configuration, never as proof of correctness; write absence assertions so that incomplete capture fails rather than silently passes.
6. Pin telemetry assertions to stable semantic conventions; prefer `contains`-style comparators over exact-match where additive change tolerance matters.

---

## 9. Conclusion

The question "can OpenTelemetry semantic assertions replace test suites" decomposes into one thing that's true, one thing that's false, and one thing that's a category error:

- **True:** trace-based testing can replace a meaningful slice of integration and E2E assertions, particularly for event-driven architectures, and can do so with better failure narratives and shared instrumentation.
- **False:** that passive production telemetry can provide equivalent pre-release verification — it cannot deliberately execute adversarial cases, cannot speak to behavior no input has exercised, may omit executions when sampling is on, and (like any self-report-based check) says nothing about effects it does not observe.
- **Category error:** that "semantic" in semantic conventions means "behavioral correctness." Semantics standardize vocabulary; they do not establish truth, and OpenTelemetry is an observation layer — not an input generator or an oracle.

For AI-generated codebases the verdict is amplified. The central risk of AI code is not that it is untested — it is that code, tests, and telemetry can all be generated from the same model's understanding, creating correlated errors that green dashboards cannot expose (the 14%-vs-25% fault-detection result is the measured shape of this problem). The strongest verification stack for AI code combines spec-derived tests in independent contexts, assertions on external effects, mutation testing, and trace-based integration tests — with production telemetry as the outermost net, not the only one.

---

## Sources

- [arXiv:2607.05139 — On the risk of coding before testing: An empirical study on LLM-based test generation workflow](https://arxiv.org/abs/2607.05139)
- [Tracetest documentation — create a trace-based test](https://docs.tracetest.io/getting-started/create-trace-based-test)
- [Tracetest expressions and assertions](https://docs.tracetest.io/concepts/expressions)
- [OpenTelemetry sampling concepts](https://opentelemetry.io/docs/concepts/sampling/)
- [OpenTelemetry telemetry stability specification](https://opentelemetry.io/docs/specs/otel/telemetry-stability/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
- [InfoQ — Martin Thwaites on observability and software engineering (GOTO Copenhagen)](https://www.infoq.com/news/2026/04/observability-telemetry/)
- [Honeycomb — Charity Majors, "A Next Step Beyond Test Driven Development"](https://www.honeycomb.io/blog/a-next-step-beyond-test-driven-development2)
- [DevOps Institute — Charity Majors, Observability-Driven Development talk slides](https://www.devopsinstitute.com/wp-content/uploads/2021/01/2020-Observ-Charity-Majors-ppt.pdf)
- [ISSTA 2026 — Do Coverage and Mutation Scores of LLM-Generated Test Suites Correlate With Their Effectiveness?](https://conf.researchr.org/details/issta-2026/issta-2026-research-papers/2/Do-Coverage-and-Mutation-Scores-of-LLM-Generated-Test-Suites-Correlate-With-Their-Eff)
- [Thoughtworks Technology Radar — Mutation Testing](https://www.thoughtworks.com/zh-cn/radar/techniques/summary/mutation-testing)
- [Augment Code — Mutation Testing for AI-Generated Code](https://www.augmentcode.com/guides/mutation-testing-ai-generated-code)
- [BugBug — Production Testing: What It Is and How to Do It Safely](https://bugbug.io/blog/software-testing/production-testing/)
- [Keploy — Production Testing FAQ](https://keploy.io/blog/community/production-testing)
- [Grafana OATS — OpenTelemetry Acceptance Tests](https://github.com/grafana/oats)
- [OpenTelemetry metric data model](https://opentelemetry.io/docs/specs/otel/metrics/data-model/)
- [OpenTelemetry log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [arXiv:2607.05139 — full text](https://arxiv.org/html/2607.05139v1)
