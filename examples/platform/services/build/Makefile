.PHONY: test lint cross check

test:
	go test -race ./...

# Imported vocabulary requires explicit paths rather than ancestor discovery.
lint:
	go tool subpoena-lint -dead-telemetry -registry ../../shared/generated/go/semconv -invariants ../../shared/invariants .

cross:
	go tool subpoena-cross .

check: test lint cross
