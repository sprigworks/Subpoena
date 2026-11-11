# Changelog

Each release below has a short summary. The full text of every entry is in
[docs/releases](docs/releases/).

## v0.1.0-alpha.5 and v0.1.0-alpha.6 (2026-11-07)

Tagged `v0.1.0-alpha.5` and `v0.1.0-alpha.6` on the same commit. No Python release goes with these
tags; PyPI stays at 0.1.0a4 until a `python/` tag is cut.

- **New witnesses:** file writes (inotify, plus a SQLite commit reader), database commits for
  Postgres and MySQL (experimental), and delivery on an inbound socket. The harness gains `NoWrite`,
  `NoRow` and delivery checks, and Python reads their log lines. Running the witnesses stays Go-only.
- **A kill has to hold:** cross reruns it on the whole suite, with and without the mutant. A Go kill
  needs a failed test whose binary links the mutated package, and a witness mark is good for one run
  of one mutant. Many edge cases of crashes, hangs, second `m.Run` calls and printed text were fixed
  so they no longer cost a real kill or fake one.
- **Changed for users:** a marker in the wrong case is an error; a Go test that wrote `witness:` by
  hand must call `harness.WitnessErrorf`; Python tests that wrote the tag by hand change verdict under
  `--require-witness`. Sinkhole can answer 200 and `Marked` tells arrivals apart. Cross output prints
  upstream line numbers and counts markers against mutants. Python gains `--test-helper` and treats
  `Mock.assert_*` under pytest-mock as a kill.
- **Stated limits:** forged runner output can fool a plain kill. Only a verified witness mark under
  `--require-witness` holds against it (docs/architecture.md, "What forged output can do"). A witness
  mark does not hold against code that reads the key and signs its own mark, so do not rely on one
  against a suite written to cheat.
- **Experimental:** a Pass from the database witness can be false and does not count as witness
  evidence for any published claim. Its open problems are listed in the full entry and in
  `witnesses/README.md`. The file witness cannot see mmap or native AIO writes that inotify misses.

Full text: [docs/releases/v0.1.0-alpha.5-and-v0.1.0-alpha.6.md](docs/releases/v0.1.0-alpha.5-and-v0.1.0-alpha.6.md)

## v0.1.0-alpha.4 and Python 0.1.0a4 (2026-11-02)

Tagged `v0.1.0-alpha.4` and `python/v0.1.0a4`. Hardens Subpoena's own checks; no new language surface.

- **Cross `--require-witness` (Go and Python):** opt-in strict mode where a clean kill whose first
  evidence is not a witness becomes `enforcement-mutant-killed-by-self-report` and fails the run. The
  default is unchanged.
- **Lint resolves telemetry constants** with `go/types`, so a constant can no longer hide an unknown
  key. Both Level 0 quickstarts are linted in CI. Missing, misplaced, duplicate or stale markers and
  unused exemptions exit 2 in both linters.
- **Tier 2** finalizes kernel capture before OATS judges absence. Healthy kernel capture does not
  imply lossless collector or Loki delivery.

Full text: [docs/releases/v0.1.0-alpha.4-and-python-0.1.0a4.md](docs/releases/v0.1.0-alpha.4-and-python-0.1.0a4.md)

## v0.1.0-alpha.3 and Python 0.1.0a3 (2026-11-01)

Tagged `v0.1.0-alpha.3` and `python/v0.1.0a3`. Python gains network absence, lint, cross-examination
with layer groups, session cgroups, the production exporter, invariants by name and a pytest plugin.

- **Python:** a pytest plugin with `subpoena_harness`, `subpoena_watch_spawns` and `subpoena_sinkhole`
  fixtures; `Sinkhole` network witness with `no_dial` checks; `invariants.load`; `Trace.query`
  returns a `Result`; `subpoena.cgroup`; `subpoena.production`.
- **Python lint:** `subpoena-lint <dir>` runs the eight `internal/lint` rules with `ast`.
- **Python cross** catches up with Go: layer groups with a reviewed `cross-masked.txt`, `-j`,
  `-select` and `-evidence-dir`. A grouped survivor never counts as killed.
- **Known limits:** running a witness and registry-drift stay Go only.

Full text: [docs/releases/v0.1.0-alpha.3-and-python-0.1.0a3.md](docs/releases/v0.1.0-alpha.3-and-python-0.1.0a3.md)

## v0.1.0-alpha.2 and Python 0.1.0a2 (2026-10-28)

Tagged `v0.1.0-alpha.2` and `python/v0.1.0a2`. Python gains the witnessed absence checks and
cross-examination; lint is still Go only.

- **Python cross-examination:** `subpoena-cross <dir>` forces guards and removes marked statements in
  a copy and requires pytest to fail on an assertion from test code. Groups, `cross-masked.txt`,
  `-j` and `-select` were Go only at this release.
- **Witness file health:** `subpoena-witness` writes `start` and `stop` records with capture health,
  so `NoSpawn` over a witness file can Pass. Python gains `Log.health()` and the absence checks.
- **Go:** `harness.WatchSpawns`, `CheckNoSpawn`, `CheckNoDial`; name-only sightings are marked and
  can fail `WatchSpawns`; failures are tagged `witness:` or `testimony:`; `ProcWitness.Coverage`.
- **Breaking:** enforcement markers no longer accept trailing text; only `group=<name>` may follow
  one, and a marker that would take no effect is an error. Cross also refuses ambiguous
  `cross-masked.txt` entries.
- **Fix:** the Python harness now sets unlimited span limits, so `OTEL_*_LIMIT` variables no longer
  truncate attributes. In 0.1.0a1 they did, and still reported a complete capture.

Full text: [docs/releases/v0.1.0-alpha.2-and-python-0.1.0a2.md](docs/releases/v0.1.0-alpha.2-and-python-0.1.0a2.md)

## Python 0.1.0a1 (2026-10-26)

First PyPI release of the Python port: `pip install subpoena`. The harness, a native TraceQL subset
evaluator and the witness-file reader. No lint or cross-examination yet.

Full text: [docs/releases/python-0.1.0a1.md](docs/releases/python-0.1.0a1.md)

## v0.1.0-alpha.1 (2026-10-26)

First alpha. Go only at this release; APIs will change.

- **What you get:** a Weaver registry and generated names, the tier 1 harness with three-valued
  absence verdicts, a TraceQL subset, process witnesses (`/proc` and eBPF), `subpoena-lint`,
  `subpoena-cross`, `subpoena-invgen`, `pkg/production`, tier 2 and tier 3 examples, and a contract
  for other languages (`docs/ports.md`).
- **Verified** on Linux 6.17 with rootful Docker and in CI: `make check`, `make conformance`,
  `make test-cgroup`, `make test-ebpf`, `make oats`, `make alerts`, `examples/adopter`, `make conform`.
- **Known limits:** Go only; no Python or TypeScript harness yet; no instrumentation helper library;
  the witness interface is process-shaped; lint matches some calls by name, not type; Tetragon is
  only a draft policy, not the witness.

Full text: [docs/releases/v0.1.0-alpha.1.md](docs/releases/v0.1.0-alpha.1.md)
