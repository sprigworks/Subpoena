# jobrunner adopts Subpoena from outside: Subpoena's commands are Go tools of
# this module (go.mod `tool` directives), run with `go tool`.
WEAVER ?= weaver

.PHONY: test lint cross check generate check-generated invariants

test:
	go test ./...

lint:
	go tool subpoena-lint -dead-telemetry .

cross:
	go tool subpoena-cross .

check: test lint cross

# Regenerate generated/go/semconv from registry/ (Weaver, as in Subpoena itself).
generate:
	$(WEAVER) registry generate -r registry --templates weaver-templates go generated/go/semconv
	gofmt -w generated/go/semconv/semconv.go

check-generated: generate
	git diff --exit-code generated/

# Regenerate invariants/names.go from invariants/*.traceql.
invariants:
	go generate ./invariants
