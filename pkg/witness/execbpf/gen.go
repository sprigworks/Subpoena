package execbpf

// The eBPF object and its Go bindings (exec_bpfel.go, exec_bpfel.o) are
// generated and committed, so building this package needs no clang. To
// regenerate after changing bpf/exec.c: make generate-bpf (needs clang).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpfel -type event exec bpf/exec.c -- -I./bpf/headers -O2 -g -Wall -Werror
