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

.PHONY: all build vet fmt test lint lint-drift cross cross-self conform python test-cgroup test-ebpf generate-bpf conformance alerts oats check generate generate-invariants registry-check check-generated tidy

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

# Lint the example gateway with subpoena-lint (must be clean). The gateway is
# the whole service the registry describes, so dead-telemetry applies.
lint:
	go run ./cmd/subpoena-lint -dead-telemetry ./examples/gateway

# registry-drift: does a change set touch registry/ and a test that asserts on
# the changed identifiers? Working tree vs HEAD by default; in CI or on a
# branch use `make lint-drift BASE=origin/main`.
lint-drift:
	go run ./cmd/subpoena-lint registry-drift $(if $(BASE),--base $(BASE)) .

# Cross-examination: remove each enforcement statement; the suite must go red.
cross:
	go run ./cmd/subpoena-cross ./examples/gateway

# Subpoena's own fail-closed guards, cross-examined like any adopter's.
CROSS_SELF := ./pkg/harness ./pkg/witness ./internal/cross
cross-self:
	@set -e; for t in $(CROSS_SELF); do go run ./cmd/subpoena-cross $$t; done

# Check a TraceQL evaluator in any language against the conformance corpus
# (docs/ports.md): make conform EVAL="python -m subpoena.traceql". Without
# EVAL it checks the Go reference, subpoena-traceql.
conform:
	@bin=$$(mktemp -d)/subpoena-traceql && go build -o $$bin ./cmd/subpoena-traceql && \
	go run ./cmd/subpoena-conform -- $${EVAL:-$$bin}

# The Python port: a local venv (uv), its tests over the shared corpus, and its
# evaluator through subpoena-conform.
python:
	cd python && (test -x .venv/bin/python || uv venv -q .venv) && uv pip install -q --python .venv/bin/python -e ".[test]"
	cd python && .venv/bin/python -m pytest -q
	$(MAKE) conform EVAL="$(CURDIR)/python/.venv/bin/python -I -m subpoena.traceql"

# The real-cgroup tests (pkg/cgroup, examples/gateway) without root: run them in
# a systemd user scope with cgroup delegation, rooted inside that scope. They
# skip under plain `make test` when /sys/fs/cgroup is not writable;
# SUBPOENA_CGROUP_REQUIRE makes that skip a failure here.
test-cgroup:
	systemd-run --user --scope -q -p Delegate=yes -- sh -c 'cg=/sys/fs/cgroup$$(cut -d: -f3 /proc/self/cgroup); \
	SUBPOENA_CGROUP_REQUIRE=1 SUBPOENA_CGROUP_ROOT=$$cg/subpoena SUBPOENA_CGROUP_REAL_ROOT=$$cg/subpoena-gw \
	go test -count=1 -v -run "Real|StartInto" ./pkg/cgroup ./examples/gateway'

# The kernel half of pkg/witness/execbpf: load the eBPF program and watch real
# execs in real session cgroups. Needs root, so it runs in a privileged
# container (Docker, Linux host with BTF); SUBPOENA_EBPF_REQUIRE makes a skip a
# failure. Modules are downloaded on the host and mounted read-only.
GO_IMAGE ?= golang:1.25
test-ebpf:
	go mod download
	docker run --rm --privileged -v "$(CURDIR)":/src -w /src \
	-v "$$(go env GOMODCACHE)":/go/pkg/mod:ro -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
	-e SUBPOENA_EBPF_REQUIRE=1 $(GO_IMAGE) \
	go test -count=1 -v ./pkg/witness/execbpf ./pkg/witness/netbpf

# Regenerate the eBPF objects and Go bindings from pkg/witness/{execbpf,netbpf}/bpf/*.c
# (needs clang). The output is committed so ordinary builds need no clang.
generate-bpf:
	go generate ./pkg/witness/execbpf ./pkg/witness/netbpf

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

# Tier 3: the alert rules in examples/gateway/alerts, provisioned into a real
# Grafana with Tempo behind it, driven through Grafana's scheduler from silence
# to clean traffic to a violation. Needs Docker; takes about four minutes (the
# rule group evaluates once a minute). SUBPOENA_ALERTS_REQUIRE makes a missing
# Grafana a failure, not a skip.
ALERTS_COMPOSE := docker compose -f conformance/docker-compose.alerts.yml
alerts:
	$(ALERTS_COMPOSE) up -d
	SUBPOENA_GRAFANA_URL=http://$$($(ALERTS_COMPOSE) port lgtm 3000) \
	SUBPOENA_TEMPO_URL=http://$$($(ALERTS_COMPOSE) port lgtm 3200) \
	SUBPOENA_OTLP_URL=http://$$($(ALERTS_COMPOSE) port lgtm 4318) \
	SUBPOENA_ALERTS_REQUIRE=1 go test ./conformance -run TestAlertRules -count=1 -v -timeout 12m; rc=$$?; \
	$(ALERTS_COMPOSE) down -v; exit $$rc

# Tier 2: the OATS cases in examples/gateway/oats. Needs rootful Docker on a
# Linux host with cgroup v2 and kernel BTF (the witness loads eBPF, privileged), and
# `go install github.com/grafana/oats@latest`. A `go install` build of OATS
# has no pinned gcx, hence GCX_VERSION (OATS's own mise.toml pins 1.0.0).
# --container-runtime docker: auto picks Podman when installed, and rootless
# Podman cannot run the privileged witness. The env -u list turns off gcx's agent mode,
# auto-detected from those variables: it switches gcx to JSON output, which
# OATS v0.10.0 counts as one row, so every `absent` fails and every
# `count: '>= 1'` passes regardless of the data. --no-cache: OATS skips a case
# whose case files are unchanged even when the application changed, and
# reports the skip as a pass. OATS takes its stacks down but leaves named
# volumes, so the witness-events volumes are removed afterwards.
OATS ?= oats
GCX_VERSION ?= 1.0.0
oats:
	cd examples/gateway/oats && env -u CLAUDECODE -u CLAUDE_CODE -u CURSOR_AGENT \
	-u GITHUB_COPILOT -u AMAZON_Q -u GCX_AGENT_MODE \
	$(OATS) --container-runtime docker --gcx-version $(GCX_VERSION) --no-cache --timeout 2m; rc=$$?; \
	docker volume ls -q --filter name=_witness-events | grep '^oats-' | xargs -r docker volume rm >/dev/null; exit $$rc

# Everything that runs without Docker or eBPF.
check: build vet test lint cross cross-self platform

# Regenerate the constants from the registry with Weaver: Go, Python and
# TypeScript (one module each, the same names).
generate:
	$(WEAVER) registry generate -r $(REGISTRY) --templates weaver-templates go generated/go/semconv
	gofmt -w generated/go/semconv/semconv.go
	$(WEAVER) registry generate -r $(REGISTRY) --templates weaver-templates python generated/python
	$(WEAVER) registry generate -r $(REGISTRY) --templates weaver-templates ts generated/ts

# Regenerate invariants/names.go from invariants/*.traceql.
generate-invariants:
	go generate ./invariants

registry-check:
	$(WEAVER) registry check -r $(REGISTRY) --future

# Fails if generated/ is stale relative to registry/.
check-generated: generate
	git add -N generated/ && git diff --exit-code generated/

# -e: tolerate test-only dependencies of dependencies on unreachable vanity hosts.
tidy:
	go mod tidy -e

# Multi-module platform adoption example (each service has its own CI gate).
.PHONY: platform
platform:
	$(MAKE) -C examples/platform check
