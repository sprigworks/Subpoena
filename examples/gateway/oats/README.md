# Tier 2: OATS

Two cases run the first invariant against a real collector and Tempo, and check
the independent witness (Tetragon exec events in Loki) next to it. They differ
in how the witness is tied to the session:

- `oats-case.yaml`, preferred: by cgroup. The gateway puts each session's exec
  in `<SUBPOENA_CGROUP_ROOT>/<trace id>`, and the case asserts exactly one exec
  event inside any session cgroup across an allowed and a denied request, with
  no argument matching.
- `oats-case-argument.yaml`, fallback: by a unique `sleep` argument per request.
  Use it where the cgroup cannot be created or Tetragon's event does not carry
  the cgroup name. The gateway's exec spans record which applies
  (`subpoena.witness.correlation`).

Status: written, never executed. The scaffold environment has no Docker and no
eBPF. Known unknowns to check on the first real run:

- OATS schema: written against OATS `meta.version: 3` (`oats-config.yaml` plus
  `oats-case.yaml`), as documented in grafana/oats `docs/case-reference.md`.
- Tetragon version, flags and the TracingPolicy in `../../../witnesses/tetragon`.
- Loki label for the shipped events (`service_name="tetragon"`) and whether the
  exec arguments land in the log body as the LogQL filters assume.
- Whether the Tetragon event contains the cgroup path (`/subpoena/<trace id>`)
  that `oats-case.yaml` greps for. If not, that case fails and
  `oats-case-argument.yaml` is the one to use.
- The gateway container runs `privileged` with `cgroup: host` so it can create
  session cgroups; that is a demo rig. If the cgroup cannot be created the
  gateway falls back and says so on its spans, and only the argument case
  applies.
- The `count: '== 1'` comparison operator in OATS.

Run (on a Linux host with Docker and BTF): `oats` in this directory.
