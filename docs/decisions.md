# Trace-Native Testing: Positioning, Decisions, and Next Steps

Oct 25, 2026 · Nick Henggeler

> Exported from the decisions doc. Amendments made after it was written:
>
> 1. **TraceQL engine.** The row below says "in Go, embed Tempo's TraceQL engine." That was withdrawn: Grafana Tempo is AGPL-3.0 and cannot be linked into this Apache-2.0 library. The documented subset in `pkg/traceql` plus the Tempo-over-HTTP conformance suite is the design. See `docs/traceql-subset.md`.
> 2. **Petiole license.** The table below named a specific license for the Petiole layer; that was never decided. Petiole is source-available with its license not final. Subpoena is Apache-2.0 regardless.
> 3. **The witness, tested (2026-10-25).** The "witness propagation" row assumes Tetragon events carry the session cgroup. Outside Kubernetes they do not: Tetragon v1.7.1 reports a container ID only when the leaf cgroup name looks like one. The cgroup-per-session decision stands; Subpoena now has its own kernel-side witness (`pkg/witness/execbpf`, eBPF), which reports each exec's cgroup ID and path, and Tetragon is kept for enforcement only. See `witnesses/README.md`. **Decided (2026-10-26):** the observe-only witnesses (`ProcWitness`, `execbpf`) stay in this Apache-2.0 repository. The table's "exec/session witnesses" in the Petiole layer means the integrated kind: mapping sessions to Petiole agents, writing witness events into Petiole's signed provenance chain, and enforcement. Petiole already records exec provenance its own way (audit netlink, Landlock/seccomp), so an open test witness does not compete with it. Petiole's licence is still not set (see amendment 2).
>
> 4. **An exec backstop may live in the open core (2026-10-26).** Amendment 3 put all enforcement on the Petiole side. Two facts revise that: Petiole confines exec only for what it launches itself (`petiole run`, its recorder), so it cannot backstop processes on hosts it does not wrap; and many Subpoena users will never run Petiole, which would leave the open core with no backstop at all. Petiole's side was consulted and sees no undercut and no overlap. **The line:** Subpoena may hold generic, application-agnostic primitives: observing execs, and an optional per-session-cgroup exec backstop described as a test backstop or tripwire. Petiole keeps agent-aware policy (mapping routing tokens and agents to sessions), the signed chain, evidence reports, and confinement beyond exec (Landlock, seccomp, microVM). **Copy rule:** Subpoena never describes the backstop as an agent guardrail or runtime protection for AI agents; that is Petiole's lane. **Test rule:** in a test run, a backstop intervention is a failure (it means the application's own enforcement failed), never a pass; and cross-examination runs with the backstop observing only, so cross-examination measures the application, not the kernel. The exec witness and the backstop stay Apache-2.0 in Subpoena (the user's decision), which also lets Petiole use them later. **Status:** decided, not built. Petiole's license is not final (amendment 2).
>
> 5. **Network witnesses are observe-only, and they are in this repo (2026-10-27).** Amendment 3 named `ProcWitness` and `execbpf` only. `witness.Sinkhole` (tier 1, no root) and `pkg/witness/netbpf` (kernel fentry on connect and sendmsg) also observe, and they stay in this Apache-2.0 repository. `cmd/subpoena-witness` still ships exec events only; it does not run `netbpf`. See `witnesses/README.md`.
>
> Name and repo chosen after this doc: **Subpoena**, `github.com/sprigworks/subpoena`, `subpoena.dev` (with `subpena.dev` as a typo redirect).

Follow-up to the design doc: how to position the project, what is needed to start, and the answers to its open questions.

## What you can do with it

Open-source the core, keep the agent-security layer under Petiole's license, and use the open core as the consulting funnel. This is infrastructure, not a product: its value depends on adoption, and developer-tool adoption runs on trust and contributions, which a restrictive license on the core would kill.

| Layer | What it holds | License | What it earns |
| --- | --- | --- | --- |
| Open core | Registry format, harness, linter, cross-examination, conformance suite | Apache 2.0 | Reputation, OTel-community credibility, inbound |
| Petiole layer | Agent-session registry, exec/session witnesses, Tetragon policies | Source-available, license not final | Commercial users pay; nonprofits and noncommercial use free |
| Services | Setting it up inside a client's agent infrastructure | SprigWorks engagement | Scoped implementation work |
| Hosted (later) | Cross-examination as a service, registry hub | Decide in year two | Recurring revenue, if the core gets adoption |

Two reasons reputation-first is the right call here specifically. The agent-session registry could plausibly be proposed upstream as an OpenTelemetry semantic convention, which is a larger reputation lever than repository stars. And nobody has packaged this combination yet, so being the canonical reference is available now.

The license split is a judgment about incentives, not legal advice.

## What is needed to start

Four decisions, then a scaffolding session.

- [ ] **Where it lives.** A separate repository with a neutral name is recommended, so Petiole is its first consumer rather than its owner.
- [ ] **A target application.** The first cut needs a real service to instrument: a Petiole gateway or a toy equivalent.
- [ ] **A name.** The registry's `name:` field needs one.
- [ ] **Go/no-go on scaffolding.** Registry, Go harness, one witness, and the lint rules as a spec, built in a session for review.

## Open questions, resolved

Six of the seven open questions from the design doc now have a direction; cross-service registry migration stays open.

| Question | Decision | Reasoning |
| --- | --- | --- |
| TraceQL in-process: is a subset the right standard? | The subset is legitimate only with a conformance suite. In Go, embed Tempo's TraceQL engine directly and skip the subset. | The conformance suite runs every invariant through both the in-process evaluator and a real Tempo and requires identical verdicts; that suite is the standard, the grammar is what it currently covers. Tempo's engine is an importable Go package, so Go needs no subset. Python and TypeScript get the subset plus the suite. |
| Witness propagation: is `parent_exec_id` enough? | No. One cgroup per session, named with the trace ID; lineage as a secondary check. | Lineage says "a descendant of the gateway spawned X," not which session. A compromised child can fork past any environment-variable marker. Every process in the session lands in the cgroup regardless. The clause that Tetragon events carry that cgroup does not hold outside Kubernetes; amendment 3 withdraws it. |
| Tracetest viability | OATS as the base; Tracetest as a reference only. | OATS is maintained by Grafana and uses TraceQL directly, which fits assertion promotion. The Tracetest repo has been quiet since mid-2025. |
| Registry governance via CI/CD | Yes for the first cut: `weaver registry diff` on every PR to `registry/`; breaking changes require a version bump and CODEOWNERS approval; each service declares its `schema_url` version. | Cross-service migration policy is a team decision no tool can make; leave it open. |
| Cardinality in tier 3 | Each registry attribute gets a `tier` annotation (`test` or `all`); the generated production exporter config drops `test`-tier attributes. | `session.id` on every span is fine in tests and a billing or rejection problem in production backends. |
| Fresh-session rule via harness constraints | Mostly yes: access scoping plus a required marker. | The test-writing subagent gets the registry, the spec, and the harness API, with a deny rule on `src/`. Each test carries `@spec_derived` or `@impl_derived`; cross-examination and coverage metrics count only `@spec_derived`. An agent can still infer the implementation from a well-named registry, but that leak is smaller than reading the code. |
| Language order | Go harness first, Python second, TypeScript third; registry language-neutral from day one. | The order stands. Go shipped the reference harness. Python has the harness, evaluator and witness reader, and not lint or cross-examination (`docs/ports.md`). TypeScript has generated names only (`generated/ts/semconv.ts`). The original reason cited embedding Tempo's TraceQL engine; amendment 1 withdrew that. |

## Own SDK or not

No. Build a distro on the upstream OpenTelemetry SDKs, not a replacement for them.

An own SDK would mean re-implementing context propagation, losing auto-instrumentation for HTTP, gRPC, and database clients, and giving up the upstream stability guarantees, in exchange for nothing the design needs. A distro is the OpenTelemetry-sanctioned way to ship an opinionated SDK configuration; Honeycomb and Splunk ship theirs this way, and it stays compatible with everything already instrumented.

What the distro bundles:

- The in-memory exporter with completeness tracking (the `collect()` guarantee)
- The `@traced` decorators and typed attribute setters generated from the registry
- The witness correlation hooks (trace ID into the session cgroup)
- The lint rules and cross-examination
