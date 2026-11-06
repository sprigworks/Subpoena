# Changelog

## Unreleased

- **The database witness goes by what the server shows.** A `SET` of a setting that
  changes lexing or lookup counts in any spelling, and the session survives only a
  plain value on an allow-list; the startup packet and `options` go by the same rule.
  A keyword is excused only in its exact position, and bare `JOIN (`, alias column
  lists, `WITH t(a) AS`, `INSERT INTO o AS u (id)`, `LIKE (` and `trim(both` no longer
  read as calls. On MySQL a write open at `COM_QUIT` or a session reset is `unknown` and
  a fault, even on InnoDB, where it was `rolled_back`; a failed statement commits unless
  its verb is known not to; savepoint names fold as the server folds them; and `LOAD
  DATA ... SET` is checked. Any opaque statement makes Postgres prepared names
  opaque. `INHERIT`, `SET SCHEMA`, `ATTACH PARTITION`, `INHERITS` and `PARTITION OF` are
  opaque, and `Missed` now says that a claim on a table is only as good as the name in
  the statement: updatable views, partitions and inheritance reach a table it does not name.
- **Cross's verdicts no longer turn on which package finished first.** `-require-witness`
  reads evidence by package, and a test of the first run that gives witness evidence on the
  repeat is enough, wherever it ran. A package that dies on the repeat, or a later crash under
  `-shuffle`, no longer loses a kill: the first run's failed tests run again alone. `go test`'s
  own `-failfast`, in `GOFLAGS` too, no longer skips packages or stops the repeat, and
  `-evidence-dir` keeps the repeat's output. A printed open line before a test's failure is
  no crash. A `fail` event counts only for a test that ran and did not pass, so a framed line
  in a test's output cannot name a test that passed; `docs/architecture.md` states what is left.
- **Markers.** A marker in the wrong case or with two letters swapped is an error, in Go and
  Python. On a line of its own, `// subpoena: enforcement points are listed` is prose again, and
  the error's hint no longer speaks only of a line of code.
- **Python cross keeps its verdicts when a detached writer holds its directory:** cleanup is
  bounded as Go's is, and names a tree it could not remove.
- **The Python Sinkhole reads a request as Go's does,** including what `http.ReadRequest` refuses
  and marks in UTF-8, from one table, `conformance/sinkhole.yaml`.

- **The file witness no longer overstates.** A SQLite table claim is Inconclusive
  for a virtual table, whose rows are on no page of its own, and the reader now
  names any table whose schema row changed or whose pages changed owner, so a
  drop, rename, swap or `ADD COLUMN` is Fail where it was Pass. `WatchSQLite`
  resolves symlinks, as SQLite does, and `Path` is the real file. In rollback mode a
  database written with no net change is `unknown`, so a commit undone by
  restoring the file is Inconclusive, and so now is a spilled rollback. Linux
  native AIO joins `mmap` as a write inotify cannot see, and is documented with
  it: `Stop` now compares every file with the capture's start and reports a
  difference no event explains (`Source` `stat`), which also finds a write through
  a hard link, and reads a `chmod` as a write. `NoWrite` is Inconclusive about a
  silent close, a path crossing a symlink, and on a witness with no roots.
  `FileWitness` gains `Roots` and `SilentCloses`. `NewFileWatch` refuses one
  directory under two spellings. `Stop` and memory are bounded with writers still
  going. `subpoena-witness -file-root` writes its start record at attach, so a
  killed run cannot read healthy.
- **A kill's repeat is the whole command, and asks more.** Cross's repeat with the
  mutant runs the mutant run's whole command without `-failfast`, so `-shuffle` and a
  failure that shows in another package no longer lose a kill. A test of the first run
  must fail again, read from `fail` events and not printed text, and under
  `--require-witness` its first evidence must be witness again, or the kill is
  `killed-by-self-report`. A misspelt marker after upstream's comment is an error,
  a block comment or string that shows a marker no longer counts as one, and a
  tree moved aside goes with the run. `Sinkhole.Marked` reads a request the same in
  Go and Python.

- **A broker's delivery has a witness.** gmqtt had none: a broker writes to a
  subscriber on a socket it accepted, and `Sinkhole` and `netbpf` see outbound
  dials only. `netbpf` has a second hook on `security_socket_sendmsg` that reports
  sends on connected inet sockets from session cgroups, with the peer read from
  the socket. `witness.DeliveryWitness` (`Delivered`), `harness.NoDelivery`,
  `RequireNoDelivery`, `CheckNoDelivery`, `DeliveryTo` and `WatchDeliveries` with a
  `DeliveryRule` let a test say nothing went to one peer while the broker's acks
  to another go on; the lint counts them. It is tier 2 only: there is no honest
  tier 1. It sees that bytes went, not what they were, and the sender must be in
  the session cgroup, so a broker inside the test binary is not seen.
  `witnesses/README.md` has what else it misses. `subpoena-witness -deliveries`
  writes delivery lines, and Python reads them (`Log.delivered`, `no_delivery`).
- **The delivery witness no longer passes on what it did not see.** A witness
  file now says which captures ran (`captures` on the start record), and
  `NoDelivery` over a file without `delivery` is Inconclusive in Go and Python,
  so files written before this change are too. `netbpf` `Health` fails on kernel
  recursion misses, which `preempt=full` makes common, for `Delivered` and
  `Dialed`; on a task leaving its session by a move or `CLONE_INTO_CGROUP`; on a
  cgroup path too long to walk; and on a send under the session root in no session.
  Attribution now walks to the top of the hierarchy, so a session can nest past 8
  levels without going unseen, and a cgroup it names like another session cannot
  take the charge; `SessionTrace` in Go and Python counts only the first root
  element in a path. A raw IPv6 name with family 0 is reported, a datagram or raw
  send is charged to its name and not the socket's peer, and a name no hook can
  read is an unknown peer. `DeliveryTo`, `Never` and `DialTo` ignore a zone. `Start`
  refuses a root of `..`. `subpoena-witness` gives up on a stalled output when
  stopping, and both readers refuse a zone, a bracketed IPv4 address and a trailing
  newline in a peer.
- **A failed `netbpf` start says why.** `Health` already failed, as "capture has
  not stopped"; it now keeps the load or attach error. `Start` also refuses a
  cgroup root name the kernel can never match, which read as silence.
- **The database witness trusts less.** It treats a call as opaque unless it is an
  exact name on a short per-engine list, and on Postgres the same goes for
  operators outside a built-in list, casts to unknown types and fields of an
  expression. `EXPLAIN`, `CREATE TABLE ... AS`, `ALTER TABLE` expressions and `COPY ...
  PROGRAM` are read for what they run. A session whose lexing or function lookup it
  can't follow is opaque for good. A `CALL` or `DO` that failed where it could have
  committed is `unknown` and Inconclusive. Names take their SQL only when the server
  confirms the `Parse`, `PREPARE TRANSACTION` settles at its tag, and Postgres names
  are cut to 63 bytes. A view over a writing function, field notation (`o.w` calling
  `w(o)`) and an overload of a listed name stay out of reach: `witnesses/README.md`.
- **A database witness, for Postgres and MySQL.** `pkg/witness/dbproxy` is a
  wire-protocol proxy: point the application's DSN at its loopback listener and
  it forwards to the real server, logging statements and commits per connection.
  `harness.RequireNoRow(t, w, traceID, table)`, `NoRow`, `CheckNoRow` and
  `WatchRows` ask it, and the lint counts them with no new rule. It reports what
  the server committed: a rolled-back write is not an effect, an autocommit write
  is. A statement it cannot parse counts against every table, and an unreadable
  frame, a transaction dropped open, a connection it could not proxy and a client
  that insists on TLS are Inconclusive. Attribution is by destination, as with
  Sinkhole. It has no SQLite or MongoDB support. Python reads its row lines
  (`Log.committed`), from the file `subpoena-witness db` writes. Running it stays
  Go-only. The module now requires pgx and go-sql-driver/mysql, for its
  integration tests only.
- **A Go kill needs a failed test that links the mutant.** go-kratos/gateway got a
  kill from a test whose binary did not contain the mutated package. Cross checks
  with `go list -deps -test`, and such a kill is `unconfirmed`. A suite that runs
  the code as a separate program links none of it, so its kills are lost too.
- **Python helpers can be declared, and pytest-mock is assertion machinery.**
  `--test-helper FILE` says a file holds test code, so an assertion there is a
  kill and not a crash; a file with enforcement markers is refused. Every
  `Mock.assert_*` under pytest-mock came back `crashed`, because the plugin wraps
  them; those are kills now.
- **Markers can follow a comment, are counted, and lines map upstream.** A marker
  after an upstream comment was dropped silently, and now takes effect. Cross
  prints markers beside mutants and names any that made no mutant. A mutant's
  line prints with the line it has once marker-only lines are taken out.
- **Sinkhole can answer.** It accepted and closed, so a proxy in front of it
  turned the hangup into a 502 and hid what the proxy did next.
  `NewAnsweringSinkhole` (`Sinkhole(answer=True)` in Python) replies 200 with an
  empty body and records the request line and headers. `Marked` finds arrivals by
  their `X-Subpoena-Mark` header. A mark comes through the code under test, so it
  hides nothing from `Dialed`.
- **A file witness, tier 1.** `witness.FileWatch` is inotify on a watched root,
  recursive, with no privilege: `create`, `write`, `rename` and `unlink`, with
  path and time of reading. Attribution is by root, as `Sinkhole`'s is by
  destination, so every event is returned for every trace. Overflow, the watch
  limit, a root that vanishes and a directory lost before its watch landed fail
  `Health`; `Coverage()` reports the gaps and what no gap can show, a file made
  and removed in a new directory before its watch landed. The harness gets
  `NoWrite`, `RequireNoWrite`, `CheckNoWrite` and `WatchWrites`, and the lint
  counts them. `witness.WatchSQLite` and `RequireNoCommit` read a SQLite
  database's WAL, header and pages, with no triggers and no SQLite library, to
  tell a commit from no commit and name the tables changed, so an audit row
  does not contradict a claim about another table. Python's `read_log` reads the
  new `file_op` lines, with `no_write`, `require_no_write` and `check_no_write`;
  running the witness stays Go-only (`subpoena-witness -file-root`).
- **The wrong cause is no longer called a build failure.** A test or panic whose
  text held `[build failed]` or `[setup failed]` came back `invalid`, read from
  anywhere in the output. Cross now reads only `go test`'s own line. A package
  `go test` passes for having no tests, but which does not build, made every
  mutant `invalid` as "did not compile"; it now stops the run at the baseline.
- **Docs say what a kill does not prove.** An early return, an assignment or a
  wrong guard can stop the allowed path too, and then an allowed-path test kills
  the mutant with the refusal unexamined. This is known and cross does not
  close it; `docs/architecture.md` says how to read a kill for it.
- **Printed text no longer counts as witness evidence; deliberate forgery still
  can.** Python read `witness:` anywhere in the message, which holds pytest's diff
  of the app's own values, and then at the start of a message, which can be the
  app's own body or `__repr__`. It now reads the failure's type: `subpoena.harness`
  raises `WitnessFailure`, a test that asks a witness itself calls the new
  `harness.witness_fail`, and any other text is `other`, so a Python test that
  wrote the tag by hand changes verdict under `--require-witness`. Go read the tag
  from any line in the shape of a `t.Log`, which the app can print. Under cross
  the harness now signs its witness failures with a key made for the run, and an
  unsigned tag is `other`. A Go test that wrote `witness:` by hand now calls the
  new `harness.WitnessErrorf`; a module pinned to an older harness gets `other`
  until it updates. Only a `*testing.T`, `B` or `F` gets the mark, so a
  `testing.TB` of production code's own gets none, and a wrapper such as
  `GinkgoTB` reads as `other`. Code set on forging one can get a real `*testing.T`
  from `testing.RunTests`, though a real test must fail too. This stops what a system prints in
  the ordinary way, and no more. The key stays readable: `/proc/<pid>/environ`
  keeps it after the harness unsets it, so in-process code, a child, or any process
  of the same user can compute a mark, and Python code can raise the type. Output
  outside cross is unchanged.
- **A witness that could not see is no witness evidence.** An Inconclusive and a
  capture health failure were tagged and signed like a sighting, and the code
  under test can cause one: leak file descriptors until the scan fails, and
  `--require-witness` passed with nothing ever spawned. They still fail the test,
  now under the new `inconclusive:` tag, which reads as `other`, in Go and Python.
- **Order no longer decides a Python crash from a kill.** Cross ran pytest with
  `-x`, so a crash behind the first failure was never seen, and under
  pytest-randomly the same mutant was `killed` or `crashed` by chance. Every test
  now runs, whatever the arguments say, so Go's rule holds: a crash beside an
  assertion is a crash. First evidence comes from the first test collected, not
  the first to finish under xdist. The inner pytest runs with `-p no:randomly`.
- **Python test code is what pytest collected.** A file counted as test code by
  its name, so an `assert` in a production `limit_test.py`, or anywhere under
  `python_files = *.py`, was a kill. It is a crash now, as any assert in the code
  under test is, unless pytest collected a test from that file. So an assertion
  helper in a `test_*.py` holding no tests is a crash too, and a `conftest.py` is
  still test code by its name, even in a production directory.
- **A kill needs its tests to pass without the mutant.** A suite that went red
  for any reason was a kill: a file a test left in the shared copy, a marker
  outside it, a flake, with the enforcement never called. Each Go case now gets
  a fresh copy, as Python's did, and in both languages a kill must hold. It runs
  again once with the mutant, and must be a clean kill with a test of the first
  run among the failed, so a rare flake does not pass: runs without the mutant
  alone let one through nearly every time. Then three times without the mutant,
  the first the mutant run's whole command, so a failure that needs a test in
  another package comes back too, and in Go the rest the failed packages. Every
  run is on a fresh copy and starts the same way as the mutant run. A kill that
  does not hold is the new `enforcement-mutant-unconfirmed`, which fails the run,
  with or without `-select`, and it says why. A kill now costs up to five runs.
  State that clears itself before the reruns, or a flake that fails twice running
  in the same test, can still pass, so it stays a weak spot, stated in
  `docs/architecture.md`.
- **Cross reads a test binary's exit code.** A panic beside another writer's
  open line (`....panic: runtime error`) matched no crash line, so a real panic
  came back a kill about half the time. `go test -json` gives no exit code, so
  cross records it through `go test -exec`, and any exit but 1 is a death. The
  wrapper is a small Go program cross builds at the start of a run, so it needs no
  `sh`, filters no environment variable, and a project's own `-exec` stays in place
  under it. Every go test of a run uses it, baseline and reruns included. Cross
  stops if it cannot build it. An exit 1 is a failed test only if the binary
  finished testing, shown by a profile package testing writes when `m.Run` ends,
  so a printed `--- FAIL:` line and an `os.Exit(1)` is a crash. A project's runner
  that runs the binary on another machine leaves no profile: its kills are
  crashes, or cross stops at the baseline if the profile's path does not exist
  there. `GOFLAGS=-memprofile=...` makes every kill a crash on a single-package
  target, so unset it for a cross run. The exit code also settles a `panic:` line a passing test printed, say
  from a recover middleware: the binary lived, so the line voids no kill, in
  either test order. It did before, but only when the printing test ran first. A
  `panic:` line in a test that did not pass still voids the package's kills.
- **Output outside a test is never a failure message.** A `file.go:N:` line
  printed while `TestMain` or `init` ran, then an exit, was a kill with no test
  failed, and a `witness:` tag on that line passed `-require-witness`. It is a
  crash now.
- **A red baseline says why, in Go and Python.** `baseline suite is not green`
  could end with nothing after it: a timeout left no output, and the last 40
  lines could be all `ok` and `[no test files]`. It now gives the reason first
  (a timeout, with what was still running and `-timeout` to raise; the failing
  test; a collection error; no tests) and drops what passing tests printed.
- **Python cross works under pytest-xdist.** Workers start after the plugin
  takes its settings out of the environment, so they recorded nothing: with
  `-- -n 4`, a real kill came back `crashed`, or `invalid` if only workers
  imported the module. Workers now record their own failures and imports, and
  a worker that dies is a crash. `-select` stops with a reason under `-n`.
- **Python cross forces a guard that spans lines.** `if check(\n    x,\n):`
  became `if False\n\n:`, a SyntaxError, so the mutant came back `invalid`.
  The forced condition keeps its line breaks in brackets now.
- **Cross can remove a Go function's last `return`.** Deleting it did not
  compile, so the mutant came back `invalid` with advice to fix a placement
  that had no fix. Where the refusal is an error and every other result is
  plainly zero, cross now puts a return of zero values in its place:
  `return nil, ErrDenied` becomes `return nil, nil`. Any other such return
  stays `invalid` and says to mark the guard. That includes `return p.Check(u)`
  and `return check(u), nil`: zero can be the refusal there, so an allowed-path
  test would "kill" a mutant with the refusal unexamined. It also includes any
  call in the error, `fmt.Errorf` and `errors.New` too: `return
  s.Authorize(admins)` is the work the allowed path needs, and a stand-in would
  drop it.
- **Python cross stops counting None as enforcement gone.** A marked return
  that ends a function came back as `pass`, so `return user in ADMINS` became
  None and `assert allowed("ann")` "killed" it with no test of a denied user.
  Such a return is now `invalid` unless the function gives None on another
  path, and says to mark the guard.
- **A crash shows the package that died.** It printed the last lines of the
  whole run, usually the `--- PASS` lines of an unrelated package. It now
  prints that package's panic, or its last lines after a `log.Fatal`.
- **Python cross reads webtest's status check.** `TestApp.get(url, status=403)`
  raises webtest's `AppError`, not an `AssertionError`, so a test's expected
  status came back `crashed`. It is an assertion now when test code made the
  call and stated the status. With no `status=` the test expected nothing, and
  a 5xx is the app falling over, so both stay a crash, as does an `AppError`
  for errors the app logged.
- **A stray `.git` above the temp directory no longer invalidates mutants.** A
  copy holds no repository, so `go build` of a main package climbed to any empty
  `.git` above it, failed on VCS stamping, and reported "did not compile". Cross
  now builds its copies with `-buildvcs=false`.
- **Cross reads Ginkgo failures.** A Ginkgo v2 `[FAILED]` spec under the suite's
  `Running Suite:` banner is a kill; it was `crashed`, because Ginkgo prints no
  `file.go:N:` line. A panic beside it still makes it a crash, ahead of or
  behind the failure, Ginkgo's `[PANICKED]` included: the output cannot show
  that an assertion library printed a report. A `witness:` tag counts only when
  a report holds one message, since its timeline prints the spec's log lines.
- **Cross prints the failure text of testify and multi-line failures.** Both
  leave the `file.go:N:` line blank, so `first evidence (other):` printed
  nothing. Cross now reads the text under it. A tag still counts only on the
  `file.go:N:` line, so this cannot upgrade a kill.
- **`witness.NewSinkholeAt`.** A sinkhole can listen on a chosen address, so a
  test can witness an IPv6 path (`::1`) or use a second loopback address when
  127.0.0.1 is one the code may reach. Go only; Python keeps the 127.0.0.1
  listener.
- **Cross names a witness failure behind a log line.** Go test prints `t.Log`
  and `t.Error` alike, so a log line ahead of a witness assertion counted as
  the first evidence and strict mode rejected the kill, with nothing to say
  why. It is still rejected; cross now prints the witness failure that came
  later and the fix.
- **`make demo` and `examples/saidno`.** A gateway answers 403 and logs the
  denial, but it has already run the tool: ordinary tests stay green and
  the witness goes red. A witness that loses capture reports Inconclusive where a
  naive check passes.
- **Python cross skips virtual environments under any name.** A directory
  holding `pyvenv.cfg` (for example a venv named `env`) is no longer copied
  into every mutant's tree or walked for source; `.nox` and `.ruff_cache`
  join the skipped names.
- **Docs.** The README states the `/proc` witness's polling gap where it
  makes the witness claim, and the decisions no longer describe a second
  product's licensing.

## v0.1.0-alpha.4 and Python 0.1.0a4 (2026-11-02)

Tagged `v0.1.0-alpha.4` and `python/v0.1.0a4`. Hardens Subpoena's own checks;
no new language surface.

- **Cross `--require-witness` (Go and Python).** Opt-in strict mode: a clean
  kill whose first evidence is not a witness becomes
  `enforcement-mutant-killed-by-self-report` and fails the run. Selection
  and group masking honor that outcome. The gateway and adopter examples run
  strict, with their witness assertions first; the Level 0 Python quickstart
  and `cross-self` stay in ordinary mode. The default is unchanged. (#19)
- **Lint resolves telemetry constants.** Go `unknown-telemetry` now resolves
  constant values with `go/types` (lexical fallback for unchecked files), so
  a constant can no longer hide an unknown key. Both Level 0 quickstarts are
  linted in CI. Vocabulary exemptions need a printed reason and must
  suppress a real finding; unwitnessed enforcement can be exempted only by a
  reasoned marker on one function. Missing, misplaced, duplicate or stale
  markers, and unused invocation exemptions, exit 2 in both linters. (#18)
- **Tier 2 finalizes kernel capture before OATS judges absence.** A
  fixture-only controller (`conformance/oatscapture`) closes and drains the
  witness, waits for it to exit and validates the complete log before the
  absence assertions run. Both cases also require one `start`, one `stop`
  and a healthy, error-free stop record in Loki. Healthy kernel capture does
  not imply lossless collector or Loki delivery. (#17)

## v0.1.0-alpha.3 and Python 0.1.0a3 (2026-11-01)

Tagged `v0.1.0-alpha.3` and `python/v0.1.0a3`. Python gains network
absence, lint, cross-examination with layer groups, session cgroups, the
production exporter, invariants by name and a pytest plugin. Running a
witness and registry-drift stay Go only.

- **Python pytest plugin.** Installing `subpoena` registers a pytest11
  plugin with `subpoena_harness`, `subpoena_watch_spawns` and
  `subpoena_sinkhole` fixtures, so a test no longer wires `Harness`,
  `addfinalizer` or the sinkhole's teardown by hand.
- **Python network absence (W6).** `subpoena.witness.Sinkhole` is the
  loopback network witness: it records every connection that reaches it,
  drains its accept queue on `stop()`, and reports health only once stopped.
  `subpoena.harness` gains `no_dial`, `require_no_dial`, `check_no_dial` and
  `dial_to`, under the same verdict rules as Go's `NoDial`, plus
  `check_no_spawn`. `docs/ports.md` makes network absence part of the port
  contract.
- **Python invariants by name.** `subpoena.invariants.load(name)` reads
  `invariants/<name>.traceql` from the nearest `invariants/` above the
  caller (or a given directory), as Go's `invariants.Load` does; an unknown
  or path-shaped name raises `InvariantError`. `names()` lists them.
- **Python `Trace.query` returns a `Result`** with `matches`, `complete` and
  `count()`, as in Go; iterating or `len()` still goes over the matches.
  `Trace.spans(trace_id)` returns one trace's spans.
- **Python session cgroups (W2).** `subpoena.cgroup` ports `pkg/cgroup`, so
  a Python service can run a session's processes in
  `<root>/<trace id>`, the cgroup the witness attributes by. On a real cgroup
  the child places itself between fork and exec (Python has no
  `CLONE_INTO_CGROUP`). Otherwise the PID is written after start, and a
  failed placement comes back as `place_err` so the caller can fall back to
  lineage.
- **Python production tiers.** `subpoena.production` ports `pkg/production`: `Exporter` wraps a span exporter and removes test-tier attributes from spans, events and links without mutating the originals; `collector_config` emits the same collector transform processor as Go. `test_tier_keys` lists the test-tier keys.
- **Python lint (L1).** `subpoena-lint <dir>` (console script,
  `subpoena.lint`) runs the eight `internal/lint` rules over Python source
  with `ast`, resolving imports and aliases, so a renamed `require_absent`
  is still the harness call. Unreadable files, invalid Python, missing
  explicit configuration and star imports fail the run with exit 2.
  Registry-drift stays a Go-only subcommand.
- **Python cross-examination catches up with Go.** Layer groups with a
  reviewed `cross-masked.txt`, parallel mutant runs (`-j`), `-select` with a
  clean-baseline fallback to the full suite, and a per-result evidence file
  under `-evidence-dir`. A grouped survivor never counts as killed, and a
  masked layer stays listed.

## v0.1.0-alpha.2 and Python 0.1.0a2 (2026-10-28)

Tagged `v0.1.0-alpha.2` and `python/v0.1.0a2`. Python gains the witnessed
absence checks and cross-examination; lint is still Go only.

- **Python cross-examination (G1).** `subpoena-cross <dir>` (console script,
  `subpoena.cross`) forces each `# subpoena:enforcement_guard` condition and
  replaces each `# subpoena:enforcement` statement with `pass`, in a copy, and
  requires pytest to fail on an assertion raised from test code (a test
  module, a conftest, or a subpoena check such as `watch_spawns`). An assert in
  the code under test, other exceptions and dead test processes are `crashed`;
  a mutant that does not import, a collection error, or a module shadowed by an
  installed package is `invalid`; a hang or a pytest-timeout failure is
  `timeout`. All fail the run, as does any marker that takes no effect. The
  point marker is a full-line comment directly above the def, as Go reads a
  doc comment. Setup faults (a tree that cannot be copied, non-UTF-8 marked
  source, a copy that drifted from the discovery snapshot) exit 2, and Ctrl-C
  kills the running suite. `examples/python-quickstart` is now
  cross-examined in CI. Groups, `cross-masked.txt`, `-j` and `-select` are Go
  only for now.
- **Witness file health (W4), and absence checks in Python (W5).**
  `subpoena-witness` writes a `start` record once attached and a `stop`
  record with the capture's health (lost kernel events, read or write
  failures), which it used to drop. `witness.Log` now reports `Health`, so
  `NoSpawn` over a witness file can Pass; before, it was always Inconclusive.
  A file with no records, more than one capture window (nothing watched
  between them), an exec outside the window, or an unhealthy or missing stop
  is a capture fault. A malformed line, a time without a zone, NaN, or a key
  that matches a field only by case is a read error, in Go and Python alike. Python gains the same
  `Log.health()`, `no_spawn`, `require_no_spawn`, `watch_spawns` and
  `SpawnRule`, and `ProcessEvent.name_only`. `conformance/witness.yaml` holds
  the cases both readers pass.
- **Cross: evidence per kill, and crashes.** Each killed mutant reports its
  first evidence, from the first failure message of a failed test: `witness`,
  `testimony` (the harness tags) or `other`. A suite that goes red only by a
  crash (a panic, a runtime fatal error, `os.Exit`, or a failure with no
  message) is `enforcement-mutant-crashed` and fails the run. `-evidence-dir` keeps
  every mutant run's full `go test -json` output.
- **Cross: `-j N` parallel mutants.** Single mutants run N at a time, each in
  its own copy of the module. cross-self: 490 s at `-j 1`, 135 s at `-j 8`, same
  verdicts. Load can flip a verdict either way, so gate on `-j 1`.
- **Cross: `-select` test selection.** Each mutant runs only the tests that
  executed its line in a per-test coverage pass after the baseline. Opt-in: it
  pays off on long suites, not on short ones. A mutant its selected tests do
  not kill runs again on the whole suite, and group runs use the whole suite. A
  test that fails alone, or a selected subset that fails together without any
  mutant, is an error.

- **Guard and layered mutants in `subpoena-cross`.**
  `//subpoena:enforcement_guard true|false` on an `if` forces its condition to
  the bypass value. `group=<name>` on enforcement markers declares layers of one
  guarantee: cross also mutates the whole group, and a layer that survives alone
  but is caught with its group is `enforcement-layer-masked`, naming the masking
  layer. A masked layer fails the run unless `cross-masked.txt` lists it with a
  reason; a stale entry fails too.
- **Breaking:** enforcement markers no longer accept trailing text.
  `//subpoena:enforcement because ...` is now a discovery error; only
  `group=<name>` may follow the marker. A marker that would take no effect (a
  statement or guard marker outside an enforcement point, or a misspelt one) is
  an error too; before, it was ignored and its statement went unexamined.
- **Cross run hygiene.** A timed-out mutant names the packages and tests still
  running at `-timeout`. Ctrl-C (or SIGTERM) cancels the run, killing the
  mutant's test processes and removing the copies. Where a timeout cannot kill
  the test binary (not unix), the run stops at the first timeout. A guard
  marker on a line whose outermost statement is not the `if` (an `if` inside
  an inline closure) is an error.

- **Cross refuses ambiguous `cross-masked.txt` entries.** One entry accepts one
  masked layer; an entry matching two, or listed twice, is an error. An entry
  names the layer's group (`<file> | <func> | group=<group> | <removed text> |
  <reason>`), so a layer moved to another group needs a fresh review. A canceled
  run is an error, not a kill.

- **`harness.WatchSpawns` (Go).** A witness check registered when the witness
  starts that runs at test cleanup, even after an earlier `Fatal`: it stops the
  witness, fails on commands the `SpawnRule` refuses (`Allowed`, `Never`) and on
  missing or bad capture health, and logs every process seen when the test had
  already failed. A `Never` entry's program
  matches with or without a directory (`sleep 1` refuses `/usr/bin/sleep 1`).
- **`harness.CheckNoSpawn`, `CheckNoDial` (Go).** Non-fatal forms of the witness
  absence checks. `subpoena-lint` counts them, and `WatchSpawns`, as asking a
  witness.
- **Name-only sightings are marked.** When `ProcWitness` sees a process only
  by its kernel task name (it exited before its arguments were read),
  `ProcessEvent.CommandSource` is `comm` and `NameOnly()` is true. `WatchSpawns`
  fails on a name-only sighting whose name is a `Never` program, and, with an
  `Allowed` list, on any name-only sighting unless `SpawnRule.ExcuseNameOnly`
  is set and the name is an `Allowed` program. Before, a bare name could slip
  past `Never`.
- **Tagged failure messages.** Harness witness failures start with `witness:`,
  telemetry assertion failures with `testimony:` (Go and Python).
- **Lint: verified `Collect` wrappers.** A test helper that stops the system
  and witness, checks health and calls the harness `Collect` counts as
  `Collect` for `no-trace-assertion` and `unguarded-absence`, but only when
  every `return` hands back the trace from that call. A same-named method that
  doesn't, such as a metrics `Collect`, still doesn't count (`lint/README.md`).
- **`ProcWitness.Coverage` (Go).** The number of full scans and children walks, and
  the longest window in which a process outside the root's children tree could
  have started and exited unseen (from one scan's start to the next one's end,
  or to Stop). A process shorter than that window may have been missed. CI now runs the `BenchmarkProc*` benchmarks (report only).
- **Python harness: span limits (fix).** The Python harness now sets its own
  span limits, all unlimited, so `OTEL_*_LIMIT` variables no longer drop or
  truncate attributes (H1). `collect()` raises `IncompleteError` (`.truncated`)
  when a span lost attributes, events or links (H3). In 0.1.0a1, a span with
  more than 128 attributes silently lost its oldest ones, and
  `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT` truncated values. Both still reported a
  complete capture. `conformance/harness.yaml` gains an `env` field and an
  `env_limits_ignored` case, and the Python runner now applies `filler`.

## Python 0.1.0a1 (2026-10-26)

First PyPI release of the Python port: `pip install subpoena`. The harness,
a native TraceQL subset evaluator and the witness-file reader, passing the
port checks in docs/ports.md (H, Q, W). No lint or cross-examination yet.
Tagged `python/v0.1.0a1`; published from CI through PyPI Trusted Publishing.

## v0.1.0-alpha.1 (2026-10-26)

First alpha. Go only at this release; APIs will change. Everything listed under "Verified" has
run, on a real machine and in CI; anything else says what it is.

### What you get

- **Registry and generated names.** A Weaver registry is the telemetry
  contract; `weaver registry generate` emits Go constants and a per-attribute
  export tier (`test` or `all`). CI checks the registry, diffs it against main,
  and fails if `generated/` is stale.
- **Tier 1: `pkg/harness`.** An in-memory recorder, `Collect()` (force-flush,
  fails on dropped or unfinished spans) and three-valued absence verdicts
  (Pass, Fail, Inconclusive; Inconclusive fails by default).
- **`pkg/traceql`.** A documented TraceQL subset (`docs/traceql-subset.md`)
  evaluated in-process. Tempo is AGPL and is never linked; it runs as a
  separate process in the conformance suite.
- **Witnesses.** `pkg/witness` (`ProcWitness`, polling /proc) and
  `pkg/witness/execbpf` (eBPF, every exec with its cgroup, read in the kernel),
  with `cmd/subpoena-witness` to ship its events. `pkg/cgroup` puts each
  session in a cgroup named with its trace ID, so a witness ties a process to a
  session without trusting the application.
- **`cmd/subpoena-lint`.** unknown-telemetry, no-trace-assertion,
  unwitnessed-enforcement, unguarded-absence, missing-provenance,
  orphan-invariant, provider-override, dead-telemetry, and registry-drift as a
  subcommand. See `lint/README.md`, including its known imprecision.
- **`cmd/subpoena-cross`.** Cross-examination: removes each marked
  enforcement statement and requires the suite to go red.
- **`cmd/subpoena-invgen`.** Generates invariant name constants, from any
  module.
- **`pkg/production`.** Keeps test-tier attributes out of production: an
  exporter wrapper for Go services, and a generated Collector config for
  everything else.
- **Tier 2 and tier 3 examples.** An OATS stack with the eBPF witness, and
  Grafana alert rules (the invariant, plus a liveness rule), for
  `examples/gateway`.
- **A contract for other languages.** `docs/ports.md` says what a Python or
  TypeScript harness must do, and each part has a check: `subpoena-traceql`
  and `subpoena-conform` (any language's evaluator over the corpus),
  `conformance/harness.yaml` (the harness rules as cases), the witness output
  schema (`docs/witness-event.schema.json`, `witness.ReadLog`), and Python and
  TypeScript names generated by Weaver from the same registry.
- **Array attributes are refused.** Measured against Tempo, array values
  follow no rule a subset could copy, so a query that reads one is an error,
  never a verdict (`docs/traceql-subset.md`).
- **Two worked examples.** `examples/gateway` (inside this module) and
  `examples/adopter` (a separate module adopting Subpoena from outside, with
  the commands as Go tools).

### Verified

On Linux 6.17 with rootful Docker, and in CI on GitHub's ubuntu runners:

- `make check`: tests, lint clean, the gateway's enforcement mutant killed.
- `make conformance`: the subset agrees with Tempo 2.8.2 on every query and
  fixture.
- `make test-cgroup`, `make test-ebpf`: real session cgroups; the eBPF witness
  in the kernel, including processes that exit at once.
- `make oats`: both tier-2 cases pass, and both fail against the enforcement
  mutant.
- `make alerts`: the alert rules provisioned into Grafana 13.2 with Tempo 3.1,
  driven through the scheduler: quiet on silence and on clean traffic, firing
  on one violation.
- `examples/adopter`: tests, lint and cross-examination from a separate module.
- `make conform`: the Go evaluator, through the port protocol, agrees on all
  139 cases (13 queries over 9 fixtures, 22 rejected queries).

### Known limits

- Go only at this release. Python and TypeScript harnesses were not yet written; their contract,
  checks and generated names are.
- No instrumentation helper library yet: spans are written with the OTel API
  and the generated constants.
- The witness interface is process-shaped (`Spawned`). Network, file and
  database witnesses need a sibling interface.
- The lint matches some calls by name, not by type (`lint/README.md`).
- Tetragon is kept only as a draft enforcement policy; it is not the witness.
