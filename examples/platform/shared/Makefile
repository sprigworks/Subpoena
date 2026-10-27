WEAVER ?= weaver
.PHONY: generate check-generated check

generate:
	$(WEAVER) registry generate -r registry --templates weaver-templates go generated/go/semconv
	gofmt -w generated/go/semconv/semconv.go
	go generate ./invariants
	go run ./cmd/platform-generate

check-generated: generate
	git diff --exit-code -- generated/ invariants/names.go alerts/rules.yaml

check:
	go vet ./...
	go test -race ./...
