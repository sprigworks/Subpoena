# TraceQL subset

`pkg/traceql` evaluates a deliberately small subset of TraceQL. Subpoena's
public harness API takes TraceQL strings, so an invariant written for tier 1
is the same string you paste into OATS (tier 2) and a Grafana alert rule
(tier 3).

## Why a subset and not Tempo's engine

**Licensing decides this, not engineering.** Grafana Tempo is AGPL-3.0.
Linking `github.com/grafana/tempo/pkg/traceql` into this Apache-2.0 library
would make the combined work subject to the AGPL, which is incompatible with
Subpoena's open-core plan. Querying a running Tempo over its HTTP API carries
no such obligation, so Tempo remains the reference evaluator for the
conformance suite (`conformance/README.md`), never a linked dependency.

The engineering findings from the embedding attempt are kept for the record,
since they would apply to any future AGPL-compatible fork:

- Tempo `main` declares `github.com/grafana/tempo/v3` and requires Go 1.27.3+;
  v2.8.3+ requires Go 1.25.5+; the v2 line never adopted a `/v2` path.
- `pkg/traceql` imports `pkg/util`, which drags in Jaeger thrift, collector
  pdata, Prometheus, gRPC and dskit, and relies on `replace` directives in
  Tempo's own `go.mod` that downstream modules do not inherit.

Conclusion: the subset is the design. The conformance suite is what makes it
trustworthy: every invariant in `invariants/` is evaluated by both this
package and a real Tempo, and the verdicts must agree.

## Grammar

```
query      = spanset { ( ">>" | ">" ) spanset }
spanset    = "{" [ bool ] "}"          ; "{}" selects every span
bool       = primary ( { "&&" primary } | { "||" primary } )   ; one operator per level
primary    = "(" bool ")" | "true" | "false" | comparison
comparison = field ( "=" | "!=" ) literal
field      = "name" | "span." attr     ; attr may contain dots: span.authorization.allowed
literal    = string | integer | "true" | "false"
```

`&&` and `||` cannot be mixed at one parenthesis level: `a || b && c` is a
parse error; write `a || (b && c)` or `(a || b) && c`. Tempo gives the two
equal precedence and groups them left to right, so it reads `a || b && c` as
`(a || b) && c`, the opposite of the usual convention (found by the first
real-Tempo conformance run, against Tempo 2.8.2 and 3.1.0). Requiring the
parentheses keeps a string's meaning the same in both places and obvious to
a reader. Strings use Go-style double-quoted escapes.
Integers are base-10 and may be negative.

## Semantics

- A condition selects spans. `name` compares the span name and only accepts a
  string. `span.<attr>` compares an attribute.
- A missing attribute makes the comparison false, for `=` and `!=` alike
  (`span.x != "a"` does not match a span without `x`).
- A type mismatch (for example `span.n = "2"` when `n` is an integer) is false
  for `=` and `!=` alike.
- Array and map attribute values are outside the subset, and are refused, not
  guessed at: if any span in the input holds an array or map under an
  attribute the query reads, evaluation is an error, never a match or a
  non-match. Attributes the query does not read may hold anything. See "Why
  arrays are refused" below.
- `A >> B` selects spans matching `B` that have an ancestor matching `A`.
  `A > B` selects spans matching `B` whose direct parent matches `A`. A span
  is never its own descendant. Relations never cross traces. Orphans (parent
  not captured) match nothing structurally.
- Operators chain left to right: `A >> B > C` is `(A >> B) > C`, where the
  spans selected by `(A >> B)` act as the left side of `> C`.
- A trace matches when the final spanset is non-empty. Eval returns the
  matching traces with the selected spans.

## Why arrays are refused

Measured against Tempo 2.8.2 on 2026-10-26 (one span per trace; `arr` an
array of strings unless noted):

| Query | `["x","y"]` | `["x"]` | `[]` | `"x"` (scalar) | `["y","z"]` |
| --- | --- | --- | --- | --- | --- |
| `{ span.arr = "x" }` | match | match | – | match | – |
| `{ span.arr != "x" }` | match | – | – | – | match |
| `{ span.arr = "[x]" }` | – | – | – | – | – |
| `{ span.arr = "x" && span.arr = "y" }` | **–** | – | – | – | – |
| `{ span.arr = "x" && span.arr != "y" }` | match | match | – | match | – |
| `{ span.arr != "x" && span.arr != "y" }` | match | – | – | – | match |

One condition on its own means "some element matches" (so `!=` means "some
element differs"). Combinations do not follow from that: `arr = "x" && arr =
"y"` does not match `["x","y"]` although each half does, while `arr != "x" &&
arr != "y"` does. No simple rule reproduces both, and an evaluator that
guessed would disagree with Tempo on some queries. For an absence invariant,
disagreeing means a test can pass while production alerts. So the subset
refuses. Integer and boolean arrays behaved the same way
(`{ span.ints != 1 }` matches `[1,2]`).

## Not supported (rejected at parse time)

Pipelines (`|`, `count()`, `by()`), regex (`=~`), ordering comparisons
(`<`, `>`, `<=`, `>=` inside a spanset), floats, durations, `status`, `kind`,
`resource.` and unscoped `.attr` fields, `~` sibling and `<<` ancestor
structural operators, `&&`/`||` between spansets, and metrics queries. A query
that parses here has the same meaning in Tempo; see `conformance/README.md`.
