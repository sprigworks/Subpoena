# Environment note: in the sandbox where this scaffold was built, proxy.golang.org
# and sum.golang.org are unreachable, so modules are fetched straight from VCS.
# go.mod carries replace directives pointing at GitHub mirrors of the vanity-path
# modules (go.opentelemetry.io/*, golang.org/x/sys) for the same reason.
export GOPROXY ?= direct
export GOSUMDB ?= off
# Weaver reads the semconv dependency over git; point it at the CA bundle if needed.
WEAVER ?= weaver
REGISTRY := registry

.PHONY: all build vet test lint gate generate registry-check check-generated tidy

all: build vet test

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

# Lint the example gateway with subpoena-lint (must be clean).
lint:
	go run ./cmd/subpoena-lint ./examples/gateway

# Fault gate: mutate each enforcement point; the suite must go red.
gate:
	go run ./cmd/subpoena-gate ./examples/gateway

# Regenerate Go constants from the registry (intended path: Weaver).
generate:
	$(WEAVER) registry generate -r $(REGISTRY) --templates weaver-templates go generated/go/semconv
	gofmt -w generated/go/semconv/semconv.go

registry-check:
	$(WEAVER) registry check -r $(REGISTRY)

# Fails if generated/ is stale relative to registry/.
check-generated: generate
	git diff --exit-code generated/

tidy:
	go mod tidy
