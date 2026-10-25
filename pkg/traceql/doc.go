// Package traceql implements a small, strictly-defined subset of TraceQL.
//
// Tempo's own engine (github.com/grafana/tempo/pkg/traceql) could not be
// embedded in the scaffold environment; see docs/traceql-subset.md for why and
// for the exact grammar and semantics implemented here. Anything outside the
// subset is rejected at parse time with an explicit error, so a query that
// parses here is guaranteed to mean the same thing in Tempo (the conformance
// suite described in conformance/README.md is what enforces that).
package traceql
