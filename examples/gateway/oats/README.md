# Tier 2: OATS

The invariant runs against a real collector and Tempo, and the independent
witness (Tetragon exec events in Loki) is checked next to it.

```
make oats
```

Needs rootful Docker on a Linux host with cgroup v2 and kernel BTF
(`/sys/kernel/btf/vmlinux`), and `go install github.com/grafana/oats@latest`.
Tetragon runs privileged, so this does not work on Docker Desktop for Mac or
Windows, or under rootless Docker or Podman.

Two case files, differing in how the witness is tied to the session:

- `oats-case-argument.yaml`, **the one that runs**: by a unique `sleep`
  argument per request. Controls: the denial span exists (`count: '>= 1'`) and
  the witness saw the allowed session's exec exactly once (`count: '== 1'`).
  Checks: the invariant is absent in Tempo and the witness saw no exec for the
  denied session.
- `oats-case.yaml`, **blocked, not in the run**: by cgroup. Tetragon's events do
  not carry the session cgroup name; see below.

## Verified (2026-10-25)

Run on Linux 6.17, Docker 28.2 (rootful), cgroup v2, OATS v0.10.0 with gcx
1.0.0, grafana/otel-lgtm 0.38, Tetragon v1.7.1.

- `make oats` passes. Against the fault gate's mutant (the enforcement
  statement in `Authorize` removed) it fails: first on the denied request's
  expected 403, and with that check relaxed, on both the invariant and the
  witness `absent` assertions. The suite tells enforced from unenforced.
- OATS schema `meta.version: 3` as written is accepted. `count: '== 1'` works.
- Tetragon process_exec events reach Loki as `service_name="tetragon"` with the
  event JSON as the log line; `| json` exposes
  `process_exec_process_binary` and `process_exec_process_arguments`.
- The gateway needs `privileged` (without it `/sys/fs/cgroup` is read-only and
  correlation falls back to `argument`). It does not need `cgroup: host`: in a
  private cgroup namespace the session cgroups nest under the container's own
  cgroup, and the exec spans still say `cgroup`.
- **Tetragon's process_exec event does not carry the cgroup path** the gateway
  creates. Outside Kubernetes the only cgroup-derived field is
  `process.docker`, filled from the leaf cgroup name only when it looks like a
  container ID: a 32-hex trace ID is not reported, a 64-hex name is (first 31
  characters). That is why the cgroup case is blocked.

## Fixed on the first run

- Tetragon v1.4.0 could not load the TracingPolicy's kprobe on Linux 6.17
  (`load program: invalid argument`); v1.7.1 loads it.
- The shipper could not read Tetragon's export (mode 600, collector runs as
  non-root): `--export-file-perm=644`.
- Witness LogQL used substring filters (`|= "0.137"`, `|= "/subpoena/"`).
  Tetragon sees every exec on the host, and the cgroup case's
  `|= "/subpoena/"` with `count: '== 1'` passed by accident on an unrelated
  command line. The queries now match parsed fields exactly, and only exec
  events are exported.

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
