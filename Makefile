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

.PHONY: all build vet fmt test lint lint-drift gate test-cgroup test-ebpf generate-bpf conformance oats check generate generate-invariants registry-check check-generated tidy

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

# The kernel half of pkg/witness/execbpf: load the eBPF program and watch real
# execs in real session cgroups. Needs root, so it runs in a privileged
# container (Docker, Linux host with BTF); SUBPOENA_EBPF_REQUIRE makes a skip a
# failure. Modules are downloaded on the host and mounted read-only.
GO_IMAGE ?= golang:1.24
test-ebpf:
	go mod download
	docker run --rm --privileged -v "$(CURDIR)":/src -w /src \
	-v "$$(go env GOMODCACHE)":/go/pkg/mod:ro -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
	-e SUBPOENA_EBPF_REQUIRE=1 $(GO_IMAGE) \
	go test -count=1 -v ./pkg/witness/execbpf

# Regenerate the eBPF object and Go bindings from pkg/witness/execbpf/bpf/exec.c
# (needs clang). The output is committed so ordinary builds need no clang.
generate-bpf:
	go generate ./pkg/witness/execbpf

# Subset-vs-Tempo conformance. Needs Docker. SUBPOENA_CONFORMANCE_REQUIRE makes
# an unreachable Tempo a failure instead of a skip, so this target cannot go
# green by skipping. (`go test ./conformance` without Tempo still runs the
# fixture checks and skips only the Tempo comparison.)
# The compose file publishes ephemeral host ports; read them back here.
CONFORMANCE_COMPOSE := docker compose -f conformance/docker-compose.yml
conformance:
	$(CONFORMANCE_COMPOSE) up -d
	SUBPOENA_TEMPO_URL=http://$$($(CONFORMANCE_COMPOSE) port tempo 3200) \
	SUBPOENA_OTLP_URL=http://$$($(CONFORMANCE_COMPOSE) port tempo 4318) \
	SUBPOENA_CONFORMANCE_REQUIRE=1 go test ./conformance -run TestTempo -count=1 -v; rc=$$?; \
	$(CONFORMANCE_COMPOSE) down -v; exit $$rc

# Tier 2: the OATS cases in examples/gateway/oats. Needs rootful Docker on a
# Linux host with cgroup v2 and kernel BTF (Tetragon runs privileged), and
# `go install github.com/grafana/oats@latest`. A `go install` build of OATS
# has no pinned gcx, hence GCX_VERSION (OATS's own mise.toml pins 1.0.0).
# --container-runtime docker: auto picks Podman when installed, and rootless
# Podman cannot run Tetragon. The env -u list turns off gcx's agent mode,
# auto-detected from those variables: it switches gcx to JSON output, which
# OATS v0.10.0 counts as one row, so every `absent` fails and every
# `count: '>= 1'` passes regardless of the data. --no-cache: OATS skips a case
# whose case files are unchanged even when the application changed, and
# reports the skip as a pass.
OATS ?= oats
GCX_VERSION ?= 1.0.0
oats:
	cd examples/gateway/oats && env -u CLAUDECODE -u CLAUDE_CODE -u CURSOR_AGENT \
	-u GITHUB_COPILOT -u AMAZON_Q -u GCX_AGENT_MODE \
	$(OATS) --container-runtime docker --gcx-version $(GCX_VERSION) --no-cache --timeout 2m

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
