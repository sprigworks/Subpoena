# Build context is the repository root:
#   docker build -f cmd/subpoena-witness/Dockerfile -t subpoena-witness .
# Run privileged on a Linux host with cgroup v2 and BTF (/sys/kernel/btf/vmlinux).
FROM golang:1.24 AS build
WORKDIR /src
COPY . .
ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=sum.golang.org
# The eBPF object is committed (pkg/witness/execbpf/exec_bpfel.o): no clang needed.
RUN CGO_ENABLED=0 go build -o /out/subpoena-witness ./cmd/subpoena-witness

FROM scratch
COPY --from=build /out/subpoena-witness /subpoena-witness
ENTRYPOINT ["/subpoena-witness"]
