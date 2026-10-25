# Conformance (planned, not yet implemented)

The subset evaluator in `pkg/traceql` is only trustworthy if it agrees with
Tempo. This directory will hold a test that proves it.

## Plan

1. Corpus: every file in `../invariants/*.traceql`, plus a table of extra
   queries covering each construct in `docs/traceql-subset.md` (including the
   missing-attribute and type-mismatch edge cases).
2. Fixtures: small trace sets in OTLP JSON, built to include passing, failing
   and edge-case traces (orphans, deep chains, repeated span names).
3. Subset side: load the fixtures into `pkg/harness` and evaluate each query
   with `pkg/traceql`.
4. Tempo side: run Tempo (the same image OATS uses, in docker compose),
   push the fixtures through an OTLP receiver, and run each query through
   `/api/search`.
5. Assertion: for every (query, fixture) pair the set of matching trace IDs
   must be identical. Any divergence fails the build and either the evaluator
   or the documented semantics gets fixed.

It needs Docker, so it runs in CI behind a build tag (`conformance`), not in
`make test`. It will also pin the Tempo version, so a Tempo upgrade becomes a
visible, reviewed event.
