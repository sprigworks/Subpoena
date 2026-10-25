# Environment note: in the sandbox where this scaffold was built, proxy.golang.org
# and sum.golang.org are unreachable, so modules are fetched straight from VCS.
# go.mod carries replace directives pointing at GitHub mirrors of the vanity-path
# modules (go.opentelemetry.io/*, golang.org/x/sys), which are also unreachable
# there. The same settings are used in CI (.github/workflows/ci.yml).
export GOPROXY ?= direct
export GOSUMDB ?= off

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
	$(WEAVER) registry check -r $(REGISTRY)

# Fails if generated/ is stale relative to registry/.
check-generated: generate
	git diff --exit-code generated/

# -e: tolerate test-only dependencies of dependencies on unreachable vanity hosts.
tidy:
	go mod tidy -e
