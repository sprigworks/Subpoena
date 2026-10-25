# Tier 2: OATS

`oats-case.yaml` runs the first invariant against a real collector and Tempo,
and checks the independent witness (Tetragon exec events in Loki) next to it.

Status: written, never executed. The scaffold environment has no Docker and no
eBPF. Known unknowns to check on the first real run:

- OATS schema: written against OATS `meta.version: 3` (`oats-config.yaml` plus
  `oats-case.yaml`), as documented in grafana/oats `docs/case-reference.md`.
- Tetragon version, flags and the TracingPolicy in `../../../witnesses/tetragon`.
- Loki label for the shipped events (`service_name="tetragon"`) and whether the
  exec arguments land in the log body as the LogQL filters assume.
- Correlation is by a unique `sleep` argument here, not by trace ID. The
  production design (cgroup per session named with the trace ID) is not
  implemented in the toy gateway.

Run (on a Linux host with Docker and BTF): `oats` in this directory.
