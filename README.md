# Subpoena

Trace-native testing for OpenTelemetry. The application's own instrumentation
is the primary way tests observe it, and the same assertion, written once as a
TraceQL string, runs in unit tests, in an integration environment and in
production. The distinctive part: a system's spans are testimony, not proof.
The code that enforces a policy is also the code that reports having enforced
it, so enforcement is only proven by an independent witness, an observer of
process execs and outbound connections that the application does not control,
and cross-examination checks that the suite can tell the difference.

**Status: alpha** (v0.1.0-alpha.1, see [CHANGELOG.md](CHANGELOG.md)). Go has
all three tiers, lint and cross-examination. Python is on PyPI
(`pip install subpoena`) with the harness, TraceQL evaluator, witness file
reader and witnessed absence checks (`no_spawn`, `watch_spawns`), which pass
the same contract checks as Go. Python does not yet have lint or
cross-examination. TypeScript has generated names and is next. The
registry, invariants, witness output and tiers 2–3 are language-neutral, and
[docs/ports.md](docs/ports.md)
is the contract a harness in another language must meet, with a check for
each part. APIs will change.

To use it in a service of your own, follow
[docs/migrating-an-existing-service.md](docs/migrating-an-existing-service.md);
`examples/adopter` is a separate module doing exactly that.

## The three tiers

One invariant, `invariants/no_exec_after_deny.traceql`:

```
{ name = "agent.session.authorize" && span.authorization.allowed = false } >> { name = "agent.session.exec" }
```

Any matching trace is a violation. It is evaluated three times:

1. Tier 1, unit tests. An in-memory exporter (`pkg/harness`) captures spans;
   `Collect()` force-flushes and errors if a span was dropped or left unfinished,
   or lost attributes, events or links.
   Absence assertions return Pass, Fail or Inconclusive, and Inconclusive fails
   by default, because "we saw nothing" from an incomplete capture proves nothing.
2. Tier 2, integration, via Grafana OATS: a real collector and Tempo, plus the
   witness (kernel-side exec events from `subpoena-witness` in Loki), in
   `examples/gateway/oats`.
3. Tier 3, production: the same TraceQL string as a Grafana alert rule, in
   `examples/gateway/alerts`.

Promotion between tiers is copy and paste; a test checks the strings match.
Details in [docs/architecture.md](docs/architecture.md).

## Quickstart

```
make test      # tier 1: harness, traceql, witness, lint, cross-examination and gateway tests
make check     # build + vet + test + subpoena-lint + subpoena-cross over examples/gateway, then cross-self
make conformance  # subset vs a real Tempo in Docker (optional)
make oats         # tier 2: OATS + the eBPF witness (rootful Docker, cgroup v2, BTF)
make test-ebpf    # the eBPF witness against the real kernel, in a privileged container
make test-cgroup  # real-cgroup tests without root, in a delegated systemd scope
```

Needs Go 1.25 or newer. In a sandbox that cannot reach the Go module proxy or
the vanity module hosts, use `make SANDBOX=1 test` (see the Makefile header).

## What runs here, and what does not

| Piece | Status |
| --- | --- |
| Registry (`registry/`), Weaver check and Go generation | Runs. Weaver 0.28 checked the registry and generated `generated/go/semconv` |
| `pkg/harness`, `pkg/traceql`, `pkg/witness` (`ProcWitness`, `Sinkhole`), `pkg/cgroup` | Runs, in `make test`. Cgroup tests use a real cgroup v2 when the machine allows it and skip that part otherwise |
| `examples/gateway` tier-1 tests | Runs, in `make test` |
| `subpoena-lint`, `subpoena-cross` | Runs; cross-examination kills both gateway mutants (`Authorize` and `Fetch`) |
| Tier 2: `examples/gateway/oats` (`make oats`) | Runs (needs rootful Docker, cgroup v2, BTF): both cases pass, cgroup-correlated and argument-correlated, and both fail against the enforcement mutant |
| Kernel-side witnesses, `pkg/witness/execbpf`, `pkg/witness/netbpf`, `cmd/subpoena-witness` | Runs: unit tests in `make test`, kernel tests in `make test-ebpf` (privileged container); `execbpf` with `cmd/subpoena-witness` is the tier-2 witness |
| Tetragon policy, `witnesses/tetragon` | Loads on Tetragon v1.7.1; kept for enforcement, not used. Not the witness: outside Kubernetes its events lack the session cgroup |
| `pkg/production`: test-tier attributes kept out of production | Runs, in `make test`; the generated Collector config was validated and run on otelcol-contrib 0.116.1 |
| Tier 3: `examples/gateway/alerts` (`make alerts`) | Runs (needs Docker): provisioned into Grafana 13.2 with Tempo 3.1 and driven through the scheduler. Quiet on silence and on clean traffic, fires on a violation. The first run found the unvalidated rule could never fire; see the rule file's header |
| `examples/adopter`: adopting Subpoena from a separate module | Runs in CI (`adopter` job): test, lint, cross-examination, and its generated names checked with Weaver |
| `examples/quickstart`: Level 0, one rule with no registry | Runs in CI (`quickstart` job): test and cross-examination (no lint, which needs a registry) |
| `examples/python-quickstart`: Level 0 for a Python project, one rule and two pytest tests | Runs in CI (`python-quickstart` job): installs `python/`, runs pytest, then removes the check and requires pytest to fail. No witness or cross-examination at this level |
| Conformance, fixtures and expected results (`conformance/`) | Runs, in `make test` |
| Python port, `python/` (`make python`) | Runs, in CI on Python 3.9 and 3.12: the harness passes every `conformance/harness.yaml` case, its native evaluator agrees on all 139 corpus cases, and its witness reader passes the Go reader's cases. No lint or cross-examination yet. On PyPI: `pip install subpoena` (0.1.0a1) |
| Port checks: `subpoena-traceql`, `subpoena-conform` (`make conform`), the witness file format and reader (`witness.ReadLog`) | Runs, in `make test`: the Go evaluator, through the same protocol a port uses, agrees on all 139 cases (13 queries over 9 fixtures, 22 rejected queries) |
| Conformance, subset vs real Tempo (`make conformance`) | Runs (needs Docker): 0 divergences against Tempo 2.8.2. The first run found Tempo's `&&`/`\|\|` precedence differs; the subset now requires parentheses. Array values are refused: Tempo's answers on them follow no rule the subset could copy (measured; see `docs/traceql-subset.md`) |

Other things to know:

- TraceQL is a documented subset (`docs/traceql-subset.md`), not Tempo's engine,
  by design: Tempo is AGPL-3.0, and linking its `pkg/traceql` into this
  Apache-2.0 library would put the combined work under AGPL. Querying a
  running Tempo over HTTP carries no such obligation, which is how the
  conformance suite (`conformance/README.md`) keeps the subset honest.
- Weaver generation is the real path (`make generate`). Weaver is a Rust binary:
  download it from https://github.com/open-telemetry/weaver/releases.
- `go.mod` is clean. The GitHub-mirror `replace` directives needed in
  proxy-less sandboxes live in `go.work.sandbox`, activated only by
  `make SANDBOX=1`.
- The OATS stack uses a small stdlib OTLP/JSON exporter
  (`examples/internal/otlpjson`) instead of the standard OTLP exporter, for the
  same reason (protobuf and gRPC live on unreachable hosts).

## Where the thinking lives

- `docs/design.md` — the design: the problem, the principles, prior art, where it fits in a test suite, rules for coding agents, a worked example, open questions.
- `docs/decisions.md` — the decisions behind it (license, evaluator, witnesses, backstop, governance, language order), with reasons.
- `docs/architecture.md` — what was actually built, in text.
- `docs/traceql-subset.md`, `docs/migrating-an-existing-service.md` — the subset grammar and the migration playbook.
- `docs/ports.md` — the contract for a Python or TypeScript harness, and how each part is checked.
- `docs/background/tdd-vs-telemetry.md` — the analysis that started the project: whether OTel assertions can replace test suites (they can't; this is what they can do).

## Layout

```
registry/             Weaver registry: manifest + model/ (tier annotation per attribute)
weaver-templates/     Weaver template that generates the Go constants
generated/go/semconv/ generated constants
pkg/harness/          in-memory exporter, Collect, Trace, Verdict
pkg/traceql/          TraceQL subset evaluator
pkg/witness/          Witness and NetworkWitness interfaces, ProcWitness, Sinkhole
pkg/witness/execbpf/  kernel-side exec witness (eBPF)
pkg/witness/netbpf/   kernel-side network witness (eBPF)
pkg/cgroup/           one cgroup per session, named with the trace ID
pkg/production/       drop test-tier attributes in production (exporter, Collector config)
witnesses/            witness design notes, Tetragon policy (enforcement)
invariants/           *.traceql invariants (+ embedded loader)
cmd/subpoena-lint/    static checks (see lint/README.md)
cmd/subpoena-cross/    cross-examination
cmd/subpoena-witness/ runs the kernel-side witness, JSON lines out
cmd/subpoena-invgen/  writes invariants/names.go (also for other modules)
cmd/subpoena-traceql/ the Go evaluator as a command (the port protocol)
cmd/subpoena-conform/ checks any language's evaluator against the corpus
python/               the Python port: harness, TraceQL subset, witness reader
examples/gateway/     toy agent gateway, tests, OATS stack, alert rule
examples/adopter/     separate module adopting Subpoena from outside (CI keeps it working)
examples/quickstart/  Level 0: one rule, no registry, in its own module (test + cross)
examples/python-quickstart/  Level 0 for Python: one rule, two pytest tests
conformance/          fixtures + expected results, subset-vs-Tempo conformance test
docs/                 architecture, TraceQL subset, migrating an existing service
```

Licensed under Apache-2.0.
