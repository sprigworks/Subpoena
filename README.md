# Subpoena

Subpoena is a testing framework for code that enforces a rule: an auth check,
a sandbox, a policy that says a denied request never runs a command. It tests
that kind of code in three ways.

1. **The app's own OpenTelemetry spans are the test interface.** You write the
   rule once as a TraceQL query, and the same string runs in unit tests, in an
   integration stack and as a production alert.
2. **An independent witness checks what really happened.** The code that
   enforces a rule is also the code that reports it did, so its spans only
   count as testimony. A witness the app doesn't control (`/proc` polling, or
   eBPF probes in the Linux kernel, for process execs and outbound connections)
   records what actually ran. A capture the witness can't vouch for fails the
   test.
3. **Cross-examination checks that the tests can tell.** `subpoena-cross`
   deletes each marked enforcement statement in turn (each deletion is a
   mutant) and requires the suite to go red. A mutant that survives means the
   tests would still pass with the protection gone.

**Status: alpha, v0.1.0-alpha.1.** APIs will change. Go is the reference
implementation, and Python is a port (see [Languages](#languages)).

## What a test looks like

Trimmed from [`examples/quickstart`](examples/quickstart). The rule: a non-admin
delete is refused, and the purge process never runs.

```go
func TestNonAdminDeleteNeverPurges(t *testing.T) {
	ctx := context.Background()
	h, d, w := rig(t) // harness, handler under test, process witness
	harness.WatchSpawns(t, w, "", harness.SpawnRule{Never: []string{"sleep " + sleepArg}})

	err := d.Delete(ctx, quickstart.Request{AccountID: "acct-1", Command: "sleep", Args: []string{sleepArg}})
	if !errors.Is(err, quickstart.ErrRefused) {
		t.Fatalf("want ErrRefused, got %v", err)
	}

	w.Stop()
	tr, err := h.Collect(ctx) // flush; fails if any span was dropped or truncated
	if err != nil {
		t.Fatal(err)
	}
	harness.RequireExists(t, tr, refused)    // the denial is on the record
	harness.RequireAbsent(t, tr, purgeAfter) // no purge span follows the denial (testimony)
	harness.RequireNoSpawn(t, w, tr.TraceIDs()[0]) // and the witness saw no process (evidence)
}
```

Here `refused` and `purgeAfter` are TraceQL strings, for example
`{ name = "account.delete.authorize" && span.account.delete.allowed = false } >> { name = "account.delete.purge" }`.
`RequireNoSpawn` returns Inconclusive, and fails the test, when the witness
can't vouch for its capture.

Run it, Go 1.25+ on Linux, no privileges needed:

```
git clone https://github.com/sprigworks/subpoena
cd subpoena/examples/quickstart
make check
```

The tests pass, then cross-examination deletes the refusal and the suite
catches it. The end of the output:

```
enforcement-mutant-killed Authorize
  at handler.go:71, removed: return ctx, fmt.Errorf("%w: %s", ErrRefused, r.AccountID)
  suite went red; failing: TestNonAdminDeleteNeverPurges
  first evidence (other): want ErrRefused, got <nil>
```

To adopt it in a service of your own, follow
[docs/migrating-an-existing-service.md](docs/migrating-an-existing-service.md).
[`examples/adopter`](examples/adopter) is a separate module that does exactly
that, with a Weaver registry, generated names and lint.

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

## Languages

| | Go | Python |
| --- | --- | --- |
| Harness: capture, completeness, Pass / Fail / Inconclusive | yes | yes |
| TraceQL subset evaluator | yes | yes, native (agrees on all 139 shared cases) |
| Witnessed absence checks (`RequireNoSpawn`, `WatchSpawns`, capture health) | yes | yes, over the witness file |
| Running a witness (`/proc`, eBPF exec, eBPF network) | yes | reads the file `subpoena-witness` writes |
| Network absence checks (`RequireNoDial`) | yes | not yet |
| Cross-examination (`subpoena-cross`) | yes, plus layer groups, `-j` and `-select` | yes, for pytest |
| Lint (`subpoena-lint`) | yes | not yet |
| Tiers 2 and 3 (OATS, alert rules) | same files, any language | same files, any language |

The Python package is `pip install subpoena`; see [python/README.md](python/README.md).
The PyPI release (0.1.0a1) predates the absence checks and cross-examination,
which are on `main` and arrive with the next release.
TypeScript is next, and has generated names already. Every port meets the
contract in [docs/ports.md](docs/ports.md), and shared conformance cases check
each part.

## Running the checks

```
make test         # tier 1: harness, TraceQL, witness, lint, cross-examination, the gateway example
make check        # build, vet, test, subpoena-lint, subpoena-cross over examples/gateway, cross-self, examples/platform
make python       # the Python port: pytest and the shared conformance cases
make conformance  # the TraceQL subset against a real Tempo (Docker)
make oats         # tier 2: OATS with the eBPF witness (rootful Docker, cgroup v2, BTF)
make alerts       # tier 3: the alert rule in Grafana and Tempo (Docker)
make test-ebpf    # the eBPF witnesses against the real kernel (privileged container)
make test-cgroup  # real-cgroup tests without root, in a delegated systemd scope
```

Needs Go 1.25 or newer. `make check` and `make cross-self` take about 15
minutes, because cross-examination reruns the suite once per mutant; `make test`
takes about a minute. `make python` needs [uv](https://docs.astral.sh/uv/),
`make test-cgroup` needs a systemd user session, and `make generate` needs
Weaver. In a sandbox that can't reach the Go module proxy or
the vanity module hosts, use `make SANDBOX=1 test` (see the Makefile header).
CI covers each of these on every pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Examples

| Example | What it shows |
| --- | --- |
| [`examples/quickstart`](examples/quickstart) | The smallest setup in Go: one rule, no registry, a witness and cross-examination |
| [`examples/python-quickstart`](examples/python-quickstart) | The smallest setup in Python: one rule, two pytest tests, cross-examination |
| [`examples/adopter`](examples/adopter) | A separate module adopting Subpoena: Weaver registry, generated names, lint, cross |
| [`examples/platform`](examples/platform) | Several services sharing one registry |
| [`examples/gateway`](examples/gateway) | The reference app: all three tiers, kernel witnesses, OATS stack and alert rule |

## Design notes

- Subpoena evaluates a documented subset of TraceQL (`docs/traceql-subset.md`)
  with its own evaluator, by design: Tempo is AGPL-3.0, and linking its `pkg/traceql` into this
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
- `docs/background/tdd-vs-telemetry.md` — the analysis that started the project: whether OTel assertions can replace test suites, and what they can do instead.

## Layout

```
registry/             Weaver registry: manifest + model/ (tier annotation per attribute)
weaver-templates/     Weaver templates that generate the Go, Python and TypeScript names
generated/            generated names: go/semconv, python, ts
pkg/harness/          in-memory exporter, Collect, Trace, Verdict, witness checks
pkg/traceql/          TraceQL subset evaluator
pkg/witness/          Witness and NetworkWitness interfaces, ProcWitness, Sinkhole, witness file reader
pkg/witness/execbpf/  kernel-side exec witness (eBPF)
pkg/witness/netbpf/   kernel-side network witness (eBPF)
pkg/cgroup/           one cgroup per session, named with the trace ID
pkg/production/       drop test-tier attributes in production (exporter, Collector config)
witnesses/            witness design notes, Tetragon policy (enforcement)
invariants/           *.traceql invariants (+ embedded loader)
cmd/subpoena-lint/    static checks (see lint/README.md)
cmd/subpoena-cross/   cross-examination
cmd/subpoena-witness/ runs a witness, JSON lines out
cmd/subpoena-invgen/  writes invariants/names.go (also for other modules)
cmd/subpoena-traceql/ the Go evaluator as a command (the port protocol)
cmd/subpoena-conform/ checks any language's evaluator against the corpus
python/               the Python port: harness, TraceQL subset, witness reader and checks, cross
examples/             quickstart, python-quickstart, adopter, platform, gateway (see above)
conformance/          shared cases for every port, and the subset-vs-Tempo test
docs/                 design, decisions, architecture, TraceQL subset, ports, migration
```

Licensed under Apache-2.0.
