// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// netbpf: report every outbound inet connection attempt (connect, and sends
// that carry a destination) with the calling process's cgroup, read in the
// kernel at the moment of the call.
//
// The hooks are the LSM entry points security_socket_connect and
// security_socket_sendmsg, traced with fentry (no LSM boot parameter needed).
// Every path that connects or sends from user space goes through them,
// including io_uring, and the destination address is a kernel copy by then.
//
// The kernel requires a GPL-compatible license string for the tracing helpers
// used here; this file is dual-licensed MIT or GPL-2.0 so that it can be. It is
// loaded into the kernel by pkg/witness/netbpf, never linked into Go code.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;
typedef int pid_t;

enum bpf_map_type {
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#include "bpf_helpers.h"
#include "bpf_core_read.h"

// Only the fields used, relocated against the running kernel's BTF (CO-RE).
struct kernfs_node {
	const char *name;
	struct kernfs_node *parent; // before Linux 6.15
	u64 id;
} __attribute__((preserve_access_index));

struct kernfs_node___v615 {
	struct kernfs_node *__parent; // Linux 6.15 and later
} __attribute__((preserve_access_index));

struct cgroup {
	struct kernfs_node *kn;
} __attribute__((preserve_access_index));

struct css_set {
	struct cgroup *dfl_cgrp;
} __attribute__((preserve_access_index));

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
	struct ns_common ns;
} __attribute__((preserve_access_index));

struct upid {
	int nr;
	struct pid_namespace *ns;
} __attribute__((preserve_access_index));

struct pid {
	unsigned int level;
	struct upid numbers[];
} __attribute__((preserve_access_index));

struct task_struct {
	pid_t tgid;
	struct task_struct *group_leader;
	struct pid *thread_pid;
	struct css_set *cgroups;
} __attribute__((preserve_access_index));

struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	u16 sk_protocol; // a plain field from Linux 5.6; BTF needs 5.8 anyway
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
	void *msg_name;
	int msg_namelen;
} __attribute__((preserve_access_index));

#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10

#define OP_CONNECT 1
#define OP_SENDMSG 2

#define NAME_LEN 64   // one cgroup path element (a trace ID is 32)
#define DEPTH 8       // cgroup path elements kept, leaf first
#define PIDNS_DEPTH 8 // PID namespace nesting levels searched

struct event {
	u64 cgroup_id; // bpf_get_current_cgroup_id()
	u64 kn_id;     // the cgroup's kernfs node id (equal to cgroup_id on cgroup v2)
	u32 op;
	u32 pid;      // process ID in the witness's PID namespace (0: not visible there)
	u32 host_pid; // process ID in the initial PID namespace
	u32 family;   // AF_INET or AF_INET6
	u32 sock_type; // SOCK_STREAM, SOCK_DGRAM, ...
	u32 protocol;  // sk_protocol: IPPROTO_TCP, IPPROTO_UDP, ...
	u32 depth;     // number of valid entries in cgroup
	u16 port;      // destination port, network byte order
	u16 pad;
	u8 addr[16];   // destination address: 4 bytes for AF_INET, 16 for AF_INET6
	char comm[16];
	char cgroup[DEPTH][NAME_LEN]; // cgroup path elements: [0] is the leaf
};

// Unused at run time; makes bpf2go emit the Go type (-type event).
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

// Every failed reservation is a capture gap. Per-CPU storage avoids
// contention; atomic increments also cover nested execution on a CPU. Go sums
// all CPUs after detaching both hooks.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} lost SEC(".maps");

static __always_inline void record_loss(void)
{
	u32 key = 0;
	u64 *count = bpf_map_lookup_elem(&lost, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

// Set from Go before loading: the inode of the witness's PID namespace
// (/proc/self/ns/pid), so PIDs are reported as the witness sees them.
// 0 reports initial-namespace PIDs.
const volatile u32 pidns_inum = 0;

// ns_tgid returns t's process ID as seen in the namespace pidns_inum, or 0
// when t is not visible there. The same walk as execbpf.
static __always_inline u32 ns_tgid(struct task_struct *t)
{
	if (!pidns_inum)
		return BPF_CORE_READ(t, tgid);
	struct pid *pid = BPF_CORE_READ(t, group_leader, thread_pid);
	if (!pid)
		return 0;
	unsigned int level = BPF_CORE_READ(pid, level);
	for (int i = 0; i < PIDNS_DEPTH; i++) {
		if (i > level)
			break;
		struct upid up = {};
		void *at = (void *)pid + bpf_core_field_offset(struct pid, numbers) + i * bpf_core_type_size(struct upid);
		if (bpf_probe_read_kernel(&up, sizeof(up), at) < 0 || !up.ns)
			continue;
		if (BPF_CORE_READ(up.ns, ns.inum) == pidns_inum)
			return up.nr;
	}
	return 0;
}

static __always_inline struct kernfs_node *kn_parent(struct kernfs_node *kn)
{
	if (bpf_core_field_exists(((struct kernfs_node___v615 *)0)->__parent))
		return BPF_CORE_READ((struct kernfs_node___v615 *)kn, __parent);
	return BPF_CORE_READ(kn, parent);
}

// report sends one event for a destination at addr (a kernel sockaddr). Only
// inet families are reported; anything else (AF_UNIX, AF_NETLINK) is not a
// network destination.
static __always_inline void report(u32 op, struct socket *sock, const void *addr, int addrlen)
{
	if (!addr || addrlen < (int)sizeof(u16))
		return;
	u16 family = 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), addr) < 0) {
		record_loss(); // unreadable: cannot rule the attempt out
		return;
	}
	// AF_UNSPEC on connect dissolves an association: nothing is sent. On a
	// send, IPv4 (udp_sendmsg, raw, ping) still routes to the address in an
	// AF_UNSPEC name, so take the socket's family; IPv6 treats it as no name.
	if (family == AF_UNSPEC && op == OP_SENDMSG &&
	    BPF_CORE_READ(sock, sk, __sk_common.skc_family) == AF_INET)
		family = AF_INET;
	if (family != AF_INET && family != AF_INET6)
		return;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_loss();
		return;
	}
	e->op = op;
	e->family = family;
	e->sock_type = (u16)BPF_CORE_READ(sock, type);
	e->protocol = BPF_CORE_READ(sock, sk, sk_protocol);
	e->pad = 0;
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	e->port = 0;
	// sockaddr_in and sockaddr_in6 both keep the port at offset 2. The
	// address is at 4 (in) or 8 (in6). A short addrlen leaves zeros, which
	// the reader reports rather than drops.
	if (addrlen >= 4)
		bpf_probe_read_kernel(&e->port, sizeof(e->port), addr + 2);
	if (family == AF_INET && addrlen >= 8)
		bpf_probe_read_kernel(e->addr, 4, addr + 4);
	if (family == AF_INET6 && addrlen >= 24)
		bpf_probe_read_kernel(e->addr, 16, addr + 8);

	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->pid = ns_tgid(t);
	e->host_pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	struct kernfs_node *kn = BPF_CORE_READ(t, cgroups, dfl_cgrp, kn);
	e->kn_id = kn ? BPF_CORE_READ(kn, id) : 0;
	e->depth = 0;
#pragma unroll
	for (int i = 0; i < DEPTH; i++) {
		e->cgroup[i][0] = 0;
		if (!kn)
			continue;
		const char *name = BPF_CORE_READ(kn, name);
		if (bpf_probe_read_kernel_str(e->cgroup[i], NAME_LEN, name) < 0)
			e->cgroup[i][0] = 0;
		e->depth = i + 1;
		kn = kn_parent(kn);
	}
	bpf_ringbuf_submit(e, 0);
}

// int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
SEC("fentry/security_socket_connect")
int handle_connect(u64 *ctx)
{
	report(OP_CONNECT, (struct socket *)ctx[0], (const void *)ctx[1], (int)ctx[2]);
	return 0;
}

// int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
//
// A send on a connected socket carries no name; its connect was reported.
SEC("fentry/security_socket_sendmsg")
int handle_sendmsg(u64 *ctx)
{
	struct socket *sock = (struct socket *)ctx[0];
	struct msghdr *msg = (struct msghdr *)ctx[1];
	void *name = BPF_CORE_READ(msg, msg_name);
	int namelen = BPF_CORE_READ(msg, msg_namelen);
	report(OP_SENDMSG, sock, name, namelen);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
