# Evidence reports

A test run leaves technical results behind: one file per run, each holding the
verdict of every assertion the run evaluated. Those files are the input to
Subpoena's assertions, not a document a reader outside the team can use. This
page describes the report that turns a set of run results into one short,
readable page plus one machine-readable data file.

`subpoena-report` is the command; `pkg/report` is the same logic as a library.
It is a generic aggregator over assertion results. It knows about runs,
assertions, sources and verdicts. It knows nothing about what the runs were
about: no agents, no sessions, no product of any kind. Anything application or
agent specific belongs to the software that produced the runs.

## What the report says

Per assertion, in plain language:

- the claim, if the input supplies one, otherwise a title derived from the id;
- whether it passes when something is found or when something is not found;
- how many runs carried a result, and how many passed, failed or were inconclusive;
- how often the check had anything to check, when the input records it;
- what observed it (below); and
- for every check that did not always pass, which questions it did not pass on,
  each as a share of the runs that asked that question.

Two appendices follow the readable part. Appendix A shows the query behind every
check, including the checks that always passed. Appendix B lists every result
that did not pass, with its run and what was checked. Nothing is capped, so the
page is complete on its own.

At the top, the report states the run window, what was tested (the model and
harness fingerprints present in the input, and how many distinct labels), how
the results were observed, whether any run had an incomplete capture, how many
files were read and set aside, and that nothing here has been signed or
verified. The result line leads with how many runs had a problem, because a
share of results makes a bad set of runs look small.

Runs more than 30 minutes apart are reported as **separate batches**. A burst
five hours after the first is a different sitting: different checks exist in
it, and a total across both hides which sitting a check ever ran in. Each
batch gets its own runs, window, checks and outcomes, and the claim table says
so when there is more than one.

An input that cannot be used is a first-class result: it is listed on the page
and counted as a failure. A report whose input was damaged must not read as
"everything passed". That covers a file that is cut off, corrupt or blank
(`{}`), a file that carries a field of either input format but yields no run
(which also catches the wrong `-from`), a run with no results or no `run_id`, a
`run_id` already read from another file, and a file whose id lists and results
disagree.

The report can only count what it was given. A run whose file is missing leaves
no trace, so the page states the number of files read and set aside for a reader
to compare with the number of runs they expected.

## Verdicts keep Subpoena's meanings

- **Inconclusive is reported, never folded away.** It counts as a failure in
  the "not proven" section and in the exit status. It is never added to the
  passed count.
- **An unreadable input is a failure.** It is listed and counted, and no
  `-fail-on` setting but `none` ignores it; a run whose results are missing is
  not a passing run.
- **A run count is not coverage.** A check that never fired because the
  situation it rules out never arose proves nothing. Where the input records
  how often a check was exercised, the report shows it; where it does not, the
  page says it cannot.
- **An incomplete capture cannot prove an absence.** A pass in a run whose
  `capture_complete` is false or missing is reported as inconclusive, with the
  reason, unless its `kind` says it does not rest on absence. This matches the
  harness, where absence on an incomplete snapshot yields Inconclusive and never
  Pass (`pkg/harness/verdict.go`). `kind: exists` stands, because a span you saw
  is there, and so does `kind: other`. A missing or unrecognized kind has not
  said so, and does not stand.
- The report counts verdicts as the input recorded them. It does not re-run a
  query and does not re-judge a result.

## Sources keep Subpoena's distinctions

Every result carries a source, and the report never presents two sources as one
strength. The names are the ones `subpoena-cross` already uses when it
classifies what killed a mutant (`internal/cross`):

| Source | Meaning |
| --- | --- |
| `witness` | An independent observer saw what ran. This is evidence. |
| `testimony` | The application's own account: a span, a return value, a log line. |
| `other` | Neither: an exit code, an output check, a target record. |

An assertion checked by a span query is testimony. An assertion checked by a
witness is evidence. The report shows the source beside every row and prints a
per-source total, so a reader can see when a claim rests on testimony alone.

## Running it

```
subpoena-report [-from subpoena|run-results] [-claims file.json] \
                [-md out.md] [-json out.json] [-fail-on any|fail|inconclusive|none] <path>...
```

- `<path>` is a Subpoena results document (`-from subpoena`, the default), a
  run-results file, or a directory to search. A directory is walked for `*.json`
  files. A file that is valid JSON and plainly not this format, such as a trace
  beside a result, is set aside and counted. Anything else that cannot be used
  is an unreadable input.
- `-md` writes the readable page; `-json` writes the data file. With neither,
  the page goes to standard output.
- `-claims` reads an id-to-sentence JSON object that replaces the derived title
  for a claim, for inputs that carry no `claim` of their own. The wording
  belongs to the harness that owns the assertion: the report prints a claim, it
  does not check the claim against the query. Write a claim that says only what
  the query shows: "a record shows the request check ran", not "every request
  was checked".
- Exit status: 0 nothing failed, 1 at least one result failed or was
  inconclusive under `-fail-on` (default `any`), 2 usage or load error. An
  unreadable input counts under every setting but `none`.

## Input formats

### Subpoena results document `-from subpoena`

The stable format. Emit this where you control the harness.

```json
{
  "schema": "https://subpoena.dev/schemas/results/v1",
  "runs": [
    {
      "run_id": "2026-11-03T23:31:53Z-530c4709",
      "label": "board-allowed-audit-fee",
      "model": "nemotron-bolt",
      "harness_fingerprint": "sha256:936fb149…",
      "captured_at": "2026-11-03T23:31:53Z",
      "capture_complete": true,
      "assertions": [
        {
          "id": "no_denied_chunk_in_context",
          "claim": "No denied chunk reached the context",
          "source": "testimony",
          "kind": "absent",
          "verdict": "pass",
          "exercised": true,
          "detail": "{ name = \"context.add\" && span.acl.decision != \"allow\" }"
        }
      ]
    }
  ]
}
```

`label` is opaque: it groups runs and is printed, nothing more. `verdict` is
`pass`, `fail` or `inconclusive`. `source` is `witness`, `testimony` or `other`;
empty is reported as `other`. `kind` is `absent`, `exists` or `other`; on an
incomplete capture, anything but `exists` or `other` cannot pass. `run_id` is
required and unique across the input, and a run needs at least one assertion.
`exercised`, when present, says
whether the check had anything to check in that run: for an absence check,
whether the situation it rules out arose. Left out, the report says it cannot
state how often a check was exercised.

`captured_at` is optional. When it is absent and the run id begins with a
`20060102T150405Z` stamp, that stamp is read from the id, so a report can state
a window without a second field. The adapter below does the same.

### Run-results file `-from run-results`

One JSON file per run, the flat shape a harness commonly writes before any
Subpoena output exists:

```json
{
  "run_id": "…", "task_id": "…", "model": "…",
  "harness_fingerprint": "sha256:…", "capture_complete": true,
  "assertions": {
    "results": [
      { "id": "…", "evaluator": "subpoena", "kind": "absent",
        "verdict": "pass", "detail": "…" }
    ]
  }
}
```

The adapter reads `assertions.results` (falling back to the `passed`, `failed`
and `inconclusive` id arrays when `results` is absent), takes `task_id` as the
label, and maps each result's source. When a file has both the arrays and
`results`, they must agree, or the file is reported as unreadable. The arrays
carry no kind, so a pass read from them does not stand on an incomplete capture.


- an explicit `source` field wins;
- `evaluator: subpoena` becomes `testimony` (its results are span queries over
  the application's own telemetry);
- any other evaluator becomes `other`.

A result may carry `exercised`, with the same meaning as above. Without it, the
report will not claim a check was meaningful in a run where it never fired. A
file that recorded independent witness results should say so with `source`, or
emit the Subpoena format directly. The adapter never guesses a witness.

## The data file

`-json` writes the aggregate the page was made from. A later report reads this
file and recomputes nothing. `schema` is
`https://subpoena.dev/schemas/report/v1`.

| Field | Holds |
| --- | --- |
| `generated_at` | When the report was built. |
| `window` | `from`, `to` and `seconds` across the runs' capture times, and `untimed_runs`, the runs with no usable time. |
| `batches` | Per sitting: `index`, `from`, `to`, `runs`, `results`, `passed`, `failed`, `inconclusive`, `checks`, `runs_with_a_failed_check`, `models`, `harness_fingerprints`. |
| `inputs` | `runs`, `assertions`, `distinct_claims`, `labels`, `harness_fingerprints`, `models`, `files_read`, `files_skipped`. |
| `capture` | Runs that were `complete`, `incomplete` and `unstated`. |
| `sources` | Results per source: `witness`, `testimony`, `other`. |
| `invariants` | One entry per assertion id, below. |
| `unreadable_inputs` | Each `path` and `reason`. |
| `totals` | `passed`, `failed`, `inconclusive`, `runs_with_a_failed_check`, `unreadable_inputs`. |

Each entry in `invariants` holds `id`, `claim`, `runs_checked`, `passed`, `failed`,
`inconclusive`, `exercised`, `exercised_recorded`, `runs_per_batch` (one count per
batch, in batch order), `runs_per_label`, `kinds`, `queries` (every distinct
query, passing or not), `sources`, `failures` and `inconclusive_results`. Read
`exercised` only when `exercised_recorded` is true. Each failure or inconclusive
result holds `run_id`, `label`, `source`, `batch` (set when there is more than one
batch) and `detail`.

Fields with no content may be left out. Counts here are effective verdicts: a
pass the capture could not support is already `inconclusive`.

## What the report does not do

- It does not check a claim against the query that was run. A claim is the
  harness's wording; the page shows the query on every result that did not
  pass, so a reader can see what was actually checked.
- It does not compare runs or scores. Two runs of the same claim are counted,
  not ranked.
- It does not produce HTML or PDF. A readable page is Markdown; rendering is the
  reader's. A report from a single verified bundle is a separate piece.
- It does not sign, chain or verify anything. It reads results that another
  step produced, and says so on the page.
