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

.PHONY: all build vet fmt test lint lint-drift gate test-cgroup conformance check generate generate-invariants registry-check check-generated tidy

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

# registry-drift: does a change set touch registry/ and a test that asserts on
# the changed identifiers? Working tree vs HEAD by default; in CI or on a
# branch use `make lint-drift BASE=origin/main`.
lint-drift:
	go run ./cmd/subpoena-lint registry-drift $(if $(BASE),--base $(BASE)) .

# Fault gate: remove each enforcement statement; the suite must go red.
gate:
	go run ./cmd/subpoena-gate ./examples/gateway

# The real-cgroup tests (pkg/cgroup, examples/gateway) without root: run them in
# a systemd user scope with cgroup delegation, rooted inside that scope. They
# skip under plain `make test` when /sys/fs/cgroup is not writable.
test-cgroup:
	systemd-run --user --scope -q -p Delegate=yes -- sh -c 'cg=/sys/fs/cgroup$$(cut -d: -f3 /proc/self/cgroup); \
	SUBPOENA_CGROUP_ROOT=$$cg/subpoena SUBPOENA_CGROUP_REAL_ROOT=$$cg/subpoena-gw \
	go test -count=1 -v -run "Real|StartInto" ./pkg/cgroup ./examples/gateway'

# Subset-vs-Tempo conformance. Needs Docker. SUBPOENA_CONFORMANCE_REQUIRE makes
# an unreachable Tempo a failure instead of a skip, so this target cannot go
# green by skipping. (`go test ./conformance` without Tempo still runs the
# fixture checks and skips only the Tempo comparison.)
conformance:
	docker compose -f conformance/docker-compose.yml up -d
	SUBPOENA_CONFORMANCE_REQUIRE=1 go test ./conformance -run TestTempo -count=1 -v; rc=$$?; \
	docker compose -f conformance/docker-compose.yml down -v; exit $$rc

# Everything that runs without Docker or eBPF.
check: build vet test lint gate

# Regenerate Go constants from the registry (intended path: Weaver).
generate:
	$(WEAVER) registry generate -r $(REGISTRY) --templates weaver-templates go generated/go/semconv
	gofmt -w generated/go/semconv/semconv.go

# Regenerate invariants/names.go from invariants/*.traceql.
generate-invariants:
	go generate ./invariants

registry-check:
	$(WEAVER) registry check -r $(REGISTRY) --future

# Fails if generated/ is stale relative to registry/.
check-generated: generate
	git diff --exit-code generated/

# -e: tolerate test-only dependencies of dependencies on unreachable vanity hosts.
tidy:
	go mod tidy -e
