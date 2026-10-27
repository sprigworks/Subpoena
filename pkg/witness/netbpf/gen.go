package netbpf

// The eBPF object and its Go bindings (net_bpfel.go, net_bpfel.o) are
// generated and committed, so building this package needs no clang. To
// regenerate after changing bpf/net.c: make generate-bpf (needs clang). The
// libbpf headers are execbpf's.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpfel -type event net bpf/net.c -- -I../execbpf/bpf/headers -O2 -g -Wall -Werror
