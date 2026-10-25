# Normal builds need nothing special: `make test` uses the module proxy and
# checksum DB like any Go project.
#
# Some sandboxes cannot reach proxy.golang.org, sum.golang.org or the vanity
# module hosts (go.opentelemetry.io, golang.org). For those, go.work.sandbox
# redirects the affected modules to their GitHub mirrors. Activate it with:
#   make SANDBOX=1 test
ifeq ($(SANDBOX),1)
export GOWORK := $(CURDIR)/go.work.sandbox
export GOPROXY := direct
export GOSUMDB := off
endif

# Weaver is a Rust binary: https://github.com/open-telemetry/weaver/releases
# Its git dependency fetch needs the CA bundle in proxied environments:
#   SSL_CERT_FILE=/root/.ccr/ca-bundle.crt make generate
WEAVER ?= weaver
REGISTRY := registry

.PHONY: all build vet fmt test lint gate check generate registry-check check-generated tidy

all: build vet test

build:
	go build ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Tier 1: harness, traceql, witness, lint, gate and gateway tests.
test:
	go test ./...

# Lint the example gateway with subpoena-lint (must be clean).
lint:
	go run ./cmd/subpoena-lint ./examples/gateway

# Fault gate: remove each enforcement statement; the suite must go red.
gate:
	go run ./cmd/subpoena-gate ./examples/gateway

# Everything that runs without Docker or eBPF.
check: build vet test lint gate

# Regenerate Go constants from the registry (intended path: Weaver).
generate:
	$(WEAVER) registry generate -r $(REGISTRY) --templates weaver-templates go generated/go/semconv
	gofmt -w generated/go/semconv/semconv.go

registry-check:
	$(WEAVER) registry check -r $(REGISTRY) --future

# Fails if generated/ is stale relative to registry/.
check-generated: generate
	git diff --exit-code generated/

# -e: tolerate test-only dependencies of dependencies on unreachable vanity hosts.
tidy:
	go mod tidy -e
