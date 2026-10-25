# TraceQL subset

`pkg/traceql` evaluates a deliberately small subset of TraceQL. Subpoena's
public harness API takes TraceQL strings, so an invariant written for tier 1
is the same string you paste into OATS (tier 2) and a Grafana alert rule
(tier 3).

## Why a subset and not Tempo's engine

The plan was to embed `github.com/grafana/tempo/pkg/traceql`. That was tried
first and abandoned (roughly 25 minutes spent). What was found:

- `go get github.com/grafana/tempo@main` fails: `main` now declares its module
  as `github.com/grafana/tempo/v3`, and requires Go 1.27.3 or newer. Tempo
  v2.8.3 and later need Go 1.25.5 or newer. The newest tag buildable with Go
  1.24 is v2.8.2, and it can only be reached through a pseudo-version
  (`v1.5.1-0.20250806200423-6b92615861c3`) because the v2 line never adopted a
  `/v2` module path.
- `pkg/traceql` imports `pkg/util`, which pulls in Jaeger thrift, the
  OpenTelemetry collector pdata and contrib translators, Prometheus, gRPC and
  dskit. Tempo relies on `replace` directives in its own `go.mod` that
  downstream modules do not inherit, so a consumer has to re-derive them.
- In the build environment, every vanity-path module host
  (`golang.org`, `google.golang.org`, `go.opentelemetry.io`, `gopkg.in`) was
  unreachable, so the transitive closure could not be fetched at all.

Conclusion: embedding is impractical today. Revisit when Tempo publishes a
slim, separately versioned TraceQL module, or when we are willing to depend on
a Go 1.25+ toolchain and the full dependency weight.

## Grammar

```
query      = spanset { ( ">>" | ">" ) spanset }
spanset    = "{" [ or ] "}"            ; "{}" selects every span
or         = and { "||" and }
and        = primary { "&&" primary }
primary    = "(" or ")" | "true" | "false" | comparison
comparison = field ( "=" | "!=" ) literal
field      = "name" | "span." attr     ; attr may contain dots: span.authorization.allowed
literal    = string | integer | "true" | "false"
```

`&&` binds tighter than `||`. Strings use Go-style double-quoted escapes.
Integers are base-10 and may be negative.

## Semantics

- A condition selects spans. `name` compares the span name and only accepts a
  string. `span.<attr>` compares an attribute.
- A missing attribute makes the comparison false, for `=` and `!=` alike
  (`span.x != "a"` does not match a span without `x`).
- A type mismatch (for example `span.n = "2"` when `n` is an integer) is false
  for `=` and `!=` alike.
- `A >> B` selects spans matching `B` that have an ancestor matching `A`.
  `A > B` selects spans matching `B` whose direct parent matches `A`. A span
  is never its own descendant. Relations never cross traces. Orphans (parent
  not captured) match nothing structurally.
- Operators chain left to right: `A >> B > C` is `(A >> B) > C`, where the
  spans selected by `(A >> B)` act as the left side of `> C`.
- A trace matches when the final spanset is non-empty. Eval returns the
  matching traces with the selected spans.

## Not supported (rejected at parse time)

Pipelines (`|`, `count()`, `by()`), regex (`=~`), ordering comparisons
(`<`, `>`, `<=`, `>=` inside a spanset), floats, durations, `status`, `kind`,
`resource.` and unscoped `.attr` fields, `~` sibling and `<<` ancestor
structural operators, `&&`/`||` between spansets, and metrics queries. A query
that parses here has the same meaning in Tempo; see `conformance/README.md`.
