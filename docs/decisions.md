# Subpoena: Decisions

Oct 25, 2026 · Nick Henggeler

The decisions behind Subpoena, and why they were made. [design.md](design.md) explains the design these decisions shape. [architecture.md](architecture.md) describes what is built.

## License and positioning

Subpoena is open source under Apache-2.0: the registry format, harness, TraceQL evaluator, witnesses, lint and cross-examination. It is infrastructure, and developer-tool adoption runs on trust and contributions, which a restrictive license would kill. The agent-session registry could also be proposed upstream as an OpenTelemetry semantic convention.

**Where the line is.** Subpoena holds generic, application-agnostic primitives: observing execs and connections, and an optional exec backstop, decided but not yet built, that would kill processes in a session's cgroup. Everything Subpoena ships is in this repository, under Apache-2.0. Agent-specific runtime protection (mapping agents to sessions, signed provenance, confinement beyond exec such as Landlock, seccomp or microVMs) is out of scope.

## Where the test-evidence report and bundle live

**Decision:** Subpoena holds the generic report and the generic test-evidence bundle. Aggregating many assertion runs into one page, binding one run into a versioned manifest, and verifying that manifest are application-agnostic primitives, like the rest of this repository: they work on anyone's test results and know nothing about the system under test. What stays out is what is specific to one application or workflow: agent and session context, and a compliance workflow. A bundle may be signed by the CI or observer identity, never by the process under test. Hash chains wait until their trust anchor and ordering are defined.

**Why:** an adopter who runs Subpoena and nothing else still has to be able to show what was tested. A readable page and a record a reviewer can check cannot depend on a second product.

**How the two fit together:** Subpoena works the results out once and writes them as a data file beside the readable page. A product that adds its own, agent-aware report reads that data file and recomputes nothing, so a reader ends up with one report in which each layer supplies its own facts.

**Status:** the many-run report is built (`cmd/subpoena-report`, `pkg/report`, [evidence-reports.md](evidence-reports.md)). The single-run bundle and its verifier are not.


## The TraceQL evaluator

**Decision:** tier 1 evaluates a documented subset of TraceQL in Go (`pkg/traceql`). A conformance suite runs every case through both the subset and a real Tempo and requires identical verdicts.

**Why:** Tempo is AGPL-3.0. Linking its engine into this library would make the combined work subject to the AGPL, and Subpoena is meant to stay usable under Apache-2.0 alone. The suite is the standard; the grammar is whatever it currently covers ([traceql-subset.md](traceql-subset.md)). Where Tempo's behaviour is inconsistent, as with conditions on array attributes, the evaluator refuses the query instead of guessing.

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

**Why:** a sandbox confines exec only for processes it launches itself. A backstop on the session cgroup covers every process in the session wherever it was started, on any host the witness runs on.

**Rules:** in a test run, a backstop intervention is a failure, because it means the application's own enforcement failed. Cross-examination runs with the backstop observing only, so it measures the application and not the kernel.

## Layered enforcement in cross-examination

**Decision:** a layer that survives on its own but is caught together with other layers of its group fails the run. The one way to accept it is a line in `cross-masked.txt` naming that layer, with a reason, under review. A line that no longer matches a masked layer fails too.

**Why:** a masked layer is an unproven result: nobody has shown that the layer does anything by itself. Subpoena treats unproven results as failures, as it does an Inconclusive witness verdict. Letting masked layers pass would also let anyone turn a survivor green by declaring a group. The exception is per layer and carries a reason, like `//subpoena:own_provider <reason>`, so nothing is waived in bulk.

**Cost:** services with layered enforcement need either a test that catches each layer alone, which is preferred, or a reviewed entry for each layer that cannot be isolated.

## Integration tier

**Decision:** tier 2 is built on Grafana OATS. Tracetest is a reference, not a dependency.

**Why:** OATS is maintained and uses TraceQL directly, so an invariant moves to tier 2 unchanged. Tracetest has had no commits since June 2025.

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

**Status:** Go has all three tiers, lint and cross-examination. Python has the harness, the evaluator, the witness reader with its process and network absence checks, session cgroups, the production exporter, cross-examination for pytest with layer groups, and AST lint for the eight L1 rules; registry-drift remains Go-only ([ports.md](ports.md)). TypeScript has generated names only.

## A distribution, not an SDK

**Decision:** build on the upstream OpenTelemetry SDKs. Do not replace them.

**Why:** a separate SDK would mean re-implementing context propagation and giving up auto-instrumentation for HTTP, gRPC and database clients, for nothing the design needs. Code under test takes its tracer provider from the harness, and lint (`provider-override`) refuses any other provider outside `main`.
