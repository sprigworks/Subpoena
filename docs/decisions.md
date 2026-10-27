# Subpoena: Decisions

Oct 25, 2026 · Nick Henggeler

The decisions behind Subpoena, and why they were made. [design.md](design.md) explains the design these decisions shape. [architecture.md](architecture.md) describes what is built.

## License and positioning

Subpoena is open source under Apache-2.0: the registry format, harness, TraceQL evaluator, witnesses, lint and cross-examination. It is infrastructure, and developer-tool adoption runs on trust and contributions, which a restrictive license would kill. The agent-session registry could also be proposed upstream as an OpenTelemetry semantic convention.

Petiole, a separate product, holds the agent-aware layer. Its license is not final.

| Layer | What it holds | License |
| --- | --- | --- |
| Subpoena | Registry format, harness, evaluator, observe-only witnesses, lint, cross-examination, conformance suite, and an optional exec backstop | Apache-2.0 |
| Petiole | Mapping agents and routing tokens to sessions, the signed provenance chain, evidence reports, confinement beyond exec (Landlock, seccomp, microVM) | Source-available, not final |

**Where the line is.** Subpoena holds generic, application-agnostic primitives: observing execs and connections, and an optional exec backstop that kills processes in a session's cgroup. Petiole holds anything agent-aware. Subpoena's docs and site never describe the backstop as an agent guardrail or runtime protection for AI agents. That is Petiole's lane. Petiole's side was consulted and sees no overlap. Keeping the witnesses and backstop in Subpoena also lets Petiole use them.

## The TraceQL evaluator

**Decision:** tier 1 evaluates a documented subset of TraceQL in Go (`pkg/traceql`). A conformance suite runs every case through both the subset and a real Tempo and requires identical verdicts.

**Why:** Tempo is AGPL-3.0 and cannot be linked into an Apache-2.0 library. The suite is the standard; the grammar is whatever it currently covers ([traceql-subset.md](traceql-subset.md)). Where Tempo's behaviour is inconsistent, as with conditions on array attributes, the evaluator refuses the query instead of guessing.

## Witnesses

**Decision:** one cgroup per session, named with the trace ID. Witnesses attribute what they see by that cgroup, with process lineage as a fallback. Subpoena ships its own observe-only witnesses:

| Witness | Sees | Needs |
| --- | --- | --- |
| `ProcWitness` | Processes, by polling `/proc` | Nothing special; can miss very short processes on a busy host |
| `execbpf` (run by `cmd/subpoena-witness`) | Every exec, in the kernel, with its cgroup | Root, cgroup v2, kernel BTF |
| `Sinkhole` | Connections to an address it owns | Nothing special |
| `netbpf` | Every connect and sendmsg, in the kernel | Root, kernel BTF |

`cmd/subpoena-witness` ships exec events only; it does not run `netbpf` yet.

**Why:** lineage only says "a descendant of the gateway ran X", not which session it ran for, and a compromised child can fork past any environment-variable marker. Every process in the session lands in its cgroup regardless. Tetragon was the first witness, but outside Kubernetes it does not report the session cgroup: v1.7.1 reports a container ID only when the cgroup name looks like one. Tetragon is kept for enforcement, not for witnessing ([witnesses/README.md](../witnesses/README.md)).

## The exec backstop

**Decision:** Subpoena may ship an optional backstop that kills an exec inside a denied session's cgroup. **Decided, not built.**

**Why:** Petiole confines exec only for what it launches itself, so it cannot backstop processes on hosts it does not wrap, and many Subpoena users will never run Petiole.

**Rules:** in a test run, a backstop intervention is a failure, because it means the application's own enforcement failed. Cross-examination runs with the backstop observing only, so it measures the application and not the kernel.

## Integration tier

**Decision:** tier 2 is built on Grafana OATS. Tracetest is a reference, not a dependency.

**Why:** OATS is maintained and uses TraceQL directly, so an invariant moves to tier 2 unchanged. Tracetest has been quiet since mid-2025.

## Registry governance

**Decision:** every PR that touches `registry/` runs `weaver registry check` and `weaver registry diff` against main ([`.github/workflows/registry.yml`](../.github/workflows/registry.yml)) and needs a CODEOWNERS review. A diff that removes or obsoletes an entry also needs the `registry-breaking-approved` label. `subpoena-lint registry-drift` (`make lint-drift`) flags a registry change made together with a test that depends on it, for a human to look at. It does not run in CI yet.

**Not built:** the original decision also asked for a version bump on every breaking change, and for each service to declare the registry version it uses (`schema_url`).

**Open:** how services on different registry versions migrate together. That is a team decision, and no tool makes it.

## Cardinality in production

**Decision:** every registry attribute carries a `tier` annotation, `test` or `all`. Test-tier attributes such as `session.id` are dropped before export in production, by a Go exporter wrapper or a generated collector config (`pkg/production`).

**Why:** `session.id` on every span is fine in tests, but in production backends it is a cost or a rejection.

## Writing tests from the spec

**Decision:** every test file is marked `//subpoena:spec_derived` (written from the registry and docs, before reading the implementation) or `//subpoena:impl_derived`. Lint requires the marker.

**Why:** tests written after reading the implementation inherit its blind spots ([arXiv:2607.05139](https://arxiv.org/abs/2607.05139)). An agent can still infer the implementation from a well-named registry, but that leak is smaller than reading the code.

**Intended, not built:** the test-writing agent gets the registry, the docs and the harness API, with no read access to the implementation, and coverage and cross-examination count only spec-derived tests. Today nothing checks that a marker is true, and nothing counts spec-derived tests separately.

## Language order

**Decision:** Go first, then Python, then TypeScript. The registry is language-neutral, so names are generated for every language.

**Status:** Go has all three tiers, lint and cross-examination. Python has the harness, the evaluator and a witness reader, without lint or cross-examination ([ports.md](ports.md)). TypeScript has generated names only.

## A distribution, not an SDK

**Decision:** build on the upstream OpenTelemetry SDKs. Do not replace them.

**Why:** a separate SDK would mean re-implementing context propagation and giving up auto-instrumentation for HTTP, gRPC and database clients, for nothing the design needs. Code under test takes its tracer provider from the harness, and lint (`provider-override`) refuses any other provider outside `main`.
