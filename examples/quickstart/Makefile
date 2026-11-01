# Level 0: one rule, no registry. subpoena-cross is a Go tool of this module
# (go.mod `tool` directive), run with `go tool`. Level 0 lint exemptions
# are explicit and leave the capture, provenance and witness rules enabled.
.PHONY: test lint cross check

test:
	go test ./...

lint:
	go tool subpoena-lint -registry ../../generated/go/semconv \
	  -exempt 'unknown-telemetry=Level 0 deliberately uses plain names without a registry' .

cross:
	go tool subpoena-cross .

check: test lint cross
