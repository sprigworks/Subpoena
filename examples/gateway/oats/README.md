# Tier 2: OATS

The invariant runs against a real collector and Tempo, and the independent
witness (subpoena-witness exec events in Loki) is checked next to it.

```
make oats
```

Needs rootful Docker on a Linux host with cgroup v2 and kernel BTF
(`/sys/kernel/btf/vmlinux`), and `go install github.com/grafana/oats@latest`.
The witness loads an eBPF program, so it runs privileged: this does not work on
Docker Desktop for Mac or Windows, or under rootless Docker or Podman.

Two cases, each with its own fixture (its own stack), differing in how the
witness ties a process to the session:

- `oats-case.yaml`, **preferred: by session cgroup.** The gateway starts each
  session's exec in `<SUBPOENA_CGROUP_ROOT>/<trace id>`; the witness
  (`cmd/subpoena-witness`, `pkg/witness/execbpf`) reads each exec's cgroup in
  the kernel and labels it `attribution="cgroup"`. The proof needs no argument
  matching: across an allowed and a denied request, exactly one exec ran in any
  session cgroup on the host (`count: '== 1'`), and it is the allowed command.
- `oats-case-argument.yaml`, **fallback: by a unique `sleep` argument.** The
  gateway runs unprivileged (`docker-compose.unprivileged.yml`), cannot create
  session cgroups, and its exec spans say `argument`. The witness writes every
  exec on the host (`-all`); the case matches the denied command exactly.

Both cases send their requests through the fixture-only `capture` controller
in the witness container. It starts `subpoena-witness` as a child and forwards
requests to the gateway only while capture is active. The final input,
`POST /capture/stop`, waits for all requests to finish, signals the witness,
and waits for its final drain, kernel loss accounting and stop record. It
then reads the file with `witness.ReadLog` and requires healthy capture before
returning HTTP 200. A crash, missing boundary, restart, malformed record,
lost kernel event, read failure or write failure fails this input. Further
gateway requests are refused after finalization.

OATS also requires exactly one start, exactly one stop, and a healthy stop
without an error in Loki alongside the exec queries. Missing shipped records
therefore cannot prove an absence. This closes the kernel capture before
judgment rather than taking a periodic health snapshot, which could miss
loss during the final drain. The controller and its stop endpoint belong
only to the test fixture; the gateway does not control them.

This guarantees kernel capture health, not lossless transport through the
collector and Loki. The allowed exec and boundary checks exercise that
pipeline, but do not prove that the collector delivered every exec line.

## Verified (2026-10-25)

Linux 6.17, Docker 28.2 (rootful), cgroup v2, OATS v0.10.0 with gcx 1.0.0,
grafana/otel-lgtm 0.38.

- `make oats` passes 2/2.
- Against cross-examination's mutant (the enforcement statement in `Authorize`
  removed, and the 403 check relaxed so the witness decides): the cgroup case
  counts 2 execs in session cgroups instead of 1, the argument case sees the
  denied command, and the invariant fires in both. With the 403 check in place
  the mutant fails on the status first.
- OATS schema `meta.version: 3` is accepted; `count: '== 1'` works.
- The gateway needs `privileged` to create session cgroups (without it
  `/sys/fs/cgroup` is read-only, which is exactly the argument case's setup).
  It does not need `cgroup: host`: in a private cgroup namespace the session
  cgroups nest under the container's own cgroup.

## Why not Tetragon

Tetragon was the witness here first. It ran (v1.7.1; v1.4.0 could not load
its kprobe policy on 6.17), but outside Kubernetes its `process_exec` events
carry no cgroup path: only a container ID guessed from the leaf cgroup name,
which a 32-hex trace ID does not match. The cgroup case could not be written
honestly, and its first form passed by accident on a substring match against
an unrelated host command line. Details in `../../../witnesses/README.md`.

## Traps in the tooling (why `make oats` exists)

- **gcx agent mode.** gcx switches to JSON output when it detects an AI agent
  (`CLAUDECODE`, `CLAUDE_CODE`, `CURSOR_AGENT`, `GITHUB_COPILOT`, `AMAZON_Q`,
  `GCX_AGENT_MODE`). OATS v0.10.0 counts the JSON as one row, so every
  `absent` fails and every `count: '>= 1'` passes whatever the data. The target
  unsets those variables.
- **Skip-when-unchanged cache.** OATS skips a case whose case files are
  unchanged, even when the application changed, and reports `PASS` with the
  case skipped. The target passes `--no-cache`.
- **Runtime.** `--container-runtime auto` picks Podman when it is installed;
  the target forces Docker.
- **gcx version.** A `go install` build of OATS has no pinned gcx; the target
  passes `--gcx-version 1.0.0` (the version OATS's own `mise.toml` pins).
- **Shared fixtures.** Cases with identical fixtures share one stack and see
  each other's requests; exact counts then break. The two cases here have
  different compose file lists, so each gets its own stack.
