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
- how many runs checked it, and how many passed, failed or were inconclusive;
- what observed it (below); and
- every failed and every inconclusive result, with its run and its detail.

At the top, the report states the run window, what was tested (the model and
harness fingerprints present in the input, and how many distinct labels), how
the results were observed, and whether any run had an incomplete capture.

## Verdicts keep Subpoena's meanings

- **Inconclusive is reported, never folded away.** It counts as a failure in
  the "not proven" section and in the exit status. It is never added to the
  passed count.
- **An incomplete capture cannot prove an absence.** A result with
  `verdict: pass` and `kind: absent` in a run whose `capture_complete` is false
  is reported as inconclusive, with the reason. This matches the harness, where
  absence on an incomplete snapshot yields Inconclusive and never Pass
  (`pkg/harness/verdict.go`). A positive match (`kind: exists`) stands even on
  an incomplete capture: a span you saw is there.
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
  files that parse in the selected format; files that do not parse are skipped.
- `-md` writes the readable page; `-json` writes the data file. With neither,
  the page goes to standard output.
- `-claims` reads an id-to-sentence JSON object that replaces the derived title
  for a claim, for inputs that carry no `claim` of their own.
- Exit status: 0 nothing failed, 1 at least one result failed or was
  inconclusive under `-fail-on` (default `any`), 2 usage or load error.

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
          "detail": "{ name = \"context.add\" && span.acl.decision != \"allow\" }"
        }
      ]
    }
  ]
}
```

`label` is opaque: it groups runs and is printed, nothing more. `verdict` is
`pass`, `fail` or `inconclusive`. `source` is `witness`, `testimony` or `other`;
empty is reported as `other`. `kind` is `absent`, `exists` or `other`; only
`absent` interacts with capture completeness.

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
label, and maps each result's source:

- an explicit `source` field wins;
- `evaluator: subpoena` becomes `testimony` (its results are span queries over
  the application's own telemetry);
- any other evaluator becomes `other`.

A file that recorded independent witness results should say so with `source`,
or emit the Subpoena format directly. The adapter never guesses a witness.

## What the report does not do

- It does not compare runs or scores. Two runs of the same claim are counted,
  not ranked.
- It does not produce HTML or PDF. A readable page is Markdown; rendering is the
  reader's. A report from a single verified bundle is a separate piece.
- It does not sign, chain or verify anything. It reads results that another
  step produced.
