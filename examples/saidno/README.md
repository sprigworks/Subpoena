# saidno: a failure ordinary tests miss

A gateway refuses a request. It answers 403, logs the denial and records a
denial span. But it has already run the tool. From the repository root:

```
make demo
```

```
The rule: a denied agent gets a 403, and its tool never runs.

1. Original code: authorize, then run.
  Ordinary tests (status, log, spans)      PASS
  Subpoena (independent witness)           PASS

2. Refactored: check the tool works first, so a broken one fails fast.
   It still answers 403 and logs the denial. The tool has already run.
  Ordinary tests (status, log, spans)      PASS
  Subpoena (independent witness)           FAIL  the witness saw: tool --version

3. Same bug, and the witness loses its view of /proc.
  Reading the witness, no health check     PASS
  Subpoena (checks capture health)         FAIL  Inconclusive: capture failed, so nothing is proven
```

It needs Go 1.25+ on Linux and no privileges. The first run has to compile, so it can take
half a minute. After that it takes a few seconds.

## What happens

**The bug.** `run_refactored.go` adds one check before authorization: run the
tool with `--version`, so a missing or broken tool fails fast with a clear
error. That looks harmless, but the tool is the agent's choice and the request
hasn't been authorized yet. `--version` is only a convention. The stand-in tool
in `testdata/tool` ignores it and does its work, as any program may. Its exit
code decides the answer: if it fails, the agent gets a 400, not a 403.

**Why the ordinary tests stay green.** `ordinary_test.go` checks the status, the
body, the log line, the denial span and the absence of an exec span. Every one
of those is true, and the real run is instrumented. The check in front of it
isn't, because nobody thought of it as running the command.

**Why Subpoena goes red.** `independent_test.go` asks a process observer the
gateway doesn't control whether anything ran. It watches `/proc`, so it doesn't
depend on the code reporting anything or on where the bug is.

**Step 3.** Here the observer loses `/proc` just before the request. It sees
nothing, and a test that only reads what it saw passes, even though a second,
healthy observer confirms the command ran. `RequireNoSpawn` checks capture
health first and reports Inconclusive, which fails the test.

## What this doesn't show

- This is a constructed example. The bug is small on purpose, and the step 3
  fault comes from the test removing the observer's path to `/proc`.
- The ordinary suite here checks what the gateway reports: status, log, spans.
  It's not the strongest test you could write. A tool that touches a marker
  file, plus a check that the file isn't there, catches this bug every time, and
  more reliably than `ProcWitness`, which polls. So does a test that a denied
  request for a missing tool still gets 403, or a mock at the exec call, if every
  path goes through it. Those work once you know what to look for. The tool here
  stands in for any effect, and a witness doesn't need to know which one, or
  where the code goes wrong. What Subpoena adds is making that a rule: an
  enforcement point needs a check from outside the code, and
  [cross-examination](../../README.md) tests that the check can fail.
- `ProcWitness` polls `/proc`, so it can miss a short process, even with healthy
  capture. In local tests, a tool with no `sleep` was missed in about 1 run in
  10. The tool here sleeps to outlive that gap, and a real one might not. The kernel witnesses don't
  poll, but need more setup; see [witnesses/README.md](../../witnesses/README.md).
- `ProcWitness` ties a process to a test by lineage, not to a request. That's
  fine for one request per test, and weaker than the cgroup attribution in
  [`examples/gateway`](../gateway).
