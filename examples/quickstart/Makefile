# Level 0: one rule, no registry. subpoena-cross is a Go tool of this module
# (go.mod `tool` directive), run with `go tool`. No lint at this level: it
# needs a registry (see README).
.PHONY: test cross check

test:
	go test ./...

cross:
	go tool subpoena-cross .

check: test cross
