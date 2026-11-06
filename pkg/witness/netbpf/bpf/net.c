// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// netbpf: report every outbound inet connection attempt (connect, and sends
// that carry a destination) with the calling process's cgroup, read in the
// kernel at the moment of the call. A second hook reports sends on connected
// sockets, delivery to a peer that dialled in, from session cgroups only. Two
// more count a task leaving its session, which would otherwise take its sends
// out of the session unseen.
//
// The hooks are the LSM entry points security_socket_connect and
// security_socket_sendmsg, traced with fentry (no LSM boot parameter needed).
// Every path that connects or sends from user space goes through them,
// including io_uring, and the destination address is a kernel copy by then.
// write() on a socket is one of those paths: sock_write_iter sends through
// security_socket_sendmsg.
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

struct cgroup_root;

struct cgroup {
	struct kernfs_node *kn;
	struct cgroup_root *root;
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

// Only the size matters: these are read whole, as bytes.
struct in6_addr {
	u8 bytes[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	u16 skc_num; // host byte order
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;     // only with CONFIG_IPV6
	struct in6_addr skc_v6_rcv_saddr; // only with CONFIG_IPV6
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

#define SOCK_STREAM 1

#define IPPROTO_UDP 17
#define IPPROTO_UDPLITE 136

#define OP_CONNECT 1
#define OP_SENDMSG 2
#define OP_DELIVER 3

#define NAME_LEN 64   // one cgroup path element (a trace ID is 32)
#define DEPTH 8       // cgroup path elements kept
#define WALK 32       // cgroup levels searched for the session root; deeper is counted, never guessed
#define PIDNS_DEPTH 8 // PID namespace nesting levels searched

struct event {
	u64 cgroup_id; // bpf_get_current_cgroup_id()
	u64 kn_id;     // the cgroup's kernfs node id (equal to cgroup_id on cgroup v2)
	u64 bytes;     // on a send, the bytes the caller asked to send
	u32 op;
	u32 pid;      // process ID in the witness's PID namespace (0: not visible there)
	u32 host_pid; // process ID in the initial PID namespace
	u32 family;   // AF_INET or AF_INET6
	u32 sock_type; // SOCK_STREAM, SOCK_DGRAM, ...
	u32 protocol;  // sk_protocol: IPPROTO_TCP, IPPROTO_UDP, ...
	u32 depth;     // number of valid entries in cgroup
	u16 port;      // destination port, network byte order
	u16 local_port; // this end's port, host byte order
	u8 addr[16];   // destination address: 4 bytes for AF_INET, 16 for AF_INET6
	u8 local_addr[16]; // this end's address: always 16, IPv4 as ::ffff:a.b.c.d
	char comm[16];
	char cgroup[DEPTH][NAME_LEN]; // cgroup path elements, leaf-most first (see fill_caller)
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

static __always_inline void count(void *map)
{
	u32 key = 0;
	u64 *n = bpf_map_lookup_elem(map, &key);
	if (n)
		__sync_fetch_and_add(n, 1);
}

static __always_inline void record_loss(void)
{
	count(&lost);
}

// Sends from a session cgroup on a socket that is not inet: no address to
// report, so they are counted for the coverage report instead. Read like lost.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} other_sends SEC(".maps");

// Tasks that left a session during the capture: moved out of it, or forked out
// of it with CLONE_INTO_CGROUP. A send after that is not the session's, so it
// cannot be attributed, and Go fails Health instead. Read like lost.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} left_session SEC(".maps");

// Sends, connects and moves whose cgroup path is too long to walk to the top, so
// nothing can say whether they are in a session. Go fails Health. Read like lost.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} too_deep SEC(".maps");

// Set from Go before loading: the inode of the witness's PID namespace
// (/proc/self/ns/pid), so PIDs are reported as the witness sees them.
// 0 reports initial-namespace PIDs.
const volatile u32 pidns_inum = 0;

// Set from Go before loading: the last element of the session cgroup root,
// NUL-terminated. Connected sends are too many to report host-wide, so
// handle_deliver keeps only callers with this element in their cgroup path.
const volatile char session_base[NAME_LEN] = {};

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

// name_is_base reports whether the cgroup kn is named session_base: 1 if so, 0 if
// not, -1 if its name cannot be read. Not inlined, and not static: the verifier
// checks a global function once, where inlined into the walk below this comparison
// goes past its limit. kn is an integer because such a function takes no pointers
// to kernel memory on the oldest kernels here.
__attribute__((noinline)) int name_is_base(u64 addr)
{
	struct kernfs_node *kn = (struct kernfs_node *)addr;
	char name[NAME_LEN];
	if (bpf_probe_read_kernel_str(name, NAME_LEN, BPF_CORE_READ(kn, name)) < 0)
		return -1;
	for (int i = 0; i < NAME_LEN; i++) {
		if (name[i] != session_base[i])
			return 0;
		if (!name[i])
			return 1;
	}
	return 1;
}

// place is where a cgroup stands relative to the session root.
struct place {
	u64 session;  // kernfs id of the cgroup just below the root; 0: none
	u32 base_at;  // levels from the leaf up to the root, when found
	u8 found;     // the path has the session root in it
	u8 deep;      // the walk never reached the top, so nothing here can be relied on
};

// place_of walks from a cgroup all the way up. Only the element nearest the top
// counts: the application can create anything below its session, a cgroup named
// like the root included, but nothing above it.
static __always_inline void place_of(struct kernfs_node *kn, struct place *p)
{
	struct kernfs_node *below = 0;
	p->session = 0;
	p->base_at = 0;
	p->found = 0;
	p->deep = 0;
	for (int i = 0; i < WALK; i++) {
		if (!kn)
			return;
		int base = name_is_base((u64)kn);
		if (base < 0) {
			record_loss(); // unreadable: cannot rule the session out
			p->deep = 1;
			return;
		}
		if (base) {
			p->found = 1;
			p->base_at = i;
			p->session = below ? BPF_CORE_READ(below, id) : 0;
		}
		below = kn;
		kn = kn_parent(kn);
	}
	if (kn)
		p->deep = 1;
}

// fill_caller sets the fields every event carries about the calling task, whose
// cgroup is kn, at place p. The path keeps DEPTH elements. Usually those are the
// leaf and up, but with the session root further up than that they end at the
// root, dropping the leaf instead: Go attributes by <root>/<trace>, and the
// elements nearest the leaf are the application's to choose. With no way to find
// the root the path is left empty, so nothing can be attributed from it.
static __always_inline void fill_caller(struct event *e, struct task_struct *t, struct kernfs_node *kn, struct place *p)
{
	e->pid = ns_tgid(t);
	e->host_pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	e->kn_id = kn ? BPF_CORE_READ(kn, id) : 0;
	e->depth = 0;
	if (p->deep) {
		count(&too_deep);
		kn = 0;
	} else if (p->found && p->base_at >= DEPTH) {
		u32 skip = p->base_at - (DEPTH - 1);
		for (int i = 0; i < WALK; i++) {
			if (i >= skip || !kn)
				break;
			kn = kn_parent(kn);
		}
	}
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
}

// fill_local sets this end of the socket, and clears nothing else.
static __always_inline void fill_local(struct event *e, struct sock *sk)
{
	__builtin_memset(e->local_addr, 0, sizeof(e->local_addr));
	e->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		e->local_addr[10] = 0xff;
		e->local_addr[11] = 0xff;
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(&e->local_addr[12], &a, 4);
	} else if (family == AF_INET6 && bpf_core_field_exists(sk->__sk_common.skc_v6_rcv_saddr)) {
		BPF_CORE_READ_INTO((struct in6_addr *)e->local_addr, sk, __sk_common.skc_v6_rcv_saddr);
	}
}

// dest_family says how report reads a destination at addr (a kernel sockaddr):
// the inet family it goes to, 0 if it is no inet destination (AF_UNIX,
// AF_NETLINK, or no usable name at all), -1 if it could not be read.
static __always_inline int dest_family(u32 op, struct socket *sock, const void *addr, int addrlen)
{
	if (!addr || addrlen < (int)sizeof(u16))
		return 0;
	u16 family = 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), addr) < 0)
		return -1;
	// AF_UNSPEC on connect dissolves an association: nothing is sent. On a
	// send the protocol decides. IPv4 (udp_sendmsg, raw) routes to the address
	// in an AF_UNSPEC name. So does IPv6 raw (rawv6_sendmsg), and l2tp_ip6:
	// they refuse only a family that is neither 0 nor AF_INET6. udpv6_sendmsg
	// alone treats it as no name, and sends to the socket's peer; TCP ignores
	// names. Those two are for handle_deliver, which reads the socket, and so
	// is anything else not taken here.
	if (family == AF_UNSPEC && op == OP_SENDMSG) {
		u16 own = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
		u16 proto = BPF_CORE_READ(sock, sk, sk_protocol);
		if (own == AF_INET)
			family = AF_INET;
		else if (own == AF_INET6 && (u16)BPF_CORE_READ(sock, type) != SOCK_STREAM &&
			 proto != IPPROTO_UDP && proto != IPPROTO_UDPLITE)
			family = AF_INET6;
	}
	return family == AF_INET || family == AF_INET6 ? family : 0;
}

// report sends one event for a destination at addr. Only inet families are
// reported; anything else is not a network destination.
static __always_inline void report(u32 op, struct socket *sock, const void *addr, int addrlen, int size)
{
	int family = dest_family(op, sock, addr, addrlen);
	if (family < 0) {
		record_loss(); // unreadable: cannot rule the attempt out
		return;
	}
	if (!family)
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
	e->bytes = (u32)size;
	fill_local(e, BPF_CORE_READ(sock, sk));
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
	struct kernfs_node *kn = BPF_CORE_READ(t, cgroups, dfl_cgrp, kn);
	struct place p;
	place_of(kn, &p);
	fill_caller(e, t, kn, &p);
	bpf_ringbuf_submit(e, 0);
}

// int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
SEC("fentry/security_socket_connect")
int handle_connect(u64 *ctx)
{
	report(OP_CONNECT, (struct socket *)ctx[0], (const void *)ctx[1], (int)ctx[2], 0);
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
	report(OP_SENDMSG, sock, name, namelen, (int)ctx[2]);
	return 0;
}

// Delivery: every send on an inet socket from a session cgroup, to the peer the
// socket holds. An accepted socket had no connect here to report, which is why
// this hook exists. A send named a destination handle_sendmsg reports is left to
// it, and Go counts that event as a delivery too, when the socket has no peer or
// is datagram or raw: those go to the name, so the peer they hold would be the
// wrong one to charge. A stream socket ignores a name, and the peer it holds is
// reported beside it, or the name would be a way to hide it. Anything else goes
// out here, with whatever peer the socket holds, a zero peer if it holds none: a
// name nothing could read, and sends with no name, which raw and SCTP sockets can
// make. Only the reader can say a rule may be hit by those.
SEC("fentry/security_socket_sendmsg")
int handle_deliver(u64 *ctx)
{
	struct socket *sock = (struct socket *)ctx[0];
	struct msghdr *msg = (struct msghdr *)ctx[1];
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct kernfs_node *kn = BPF_CORE_READ(t, cgroups, dfl_cgrp, kn);
	struct place p;
	place_of(kn, &p);
	if (p.deep) {
		count(&too_deep);
		return 0;
	}
	if (!p.found)
		return 0;

	struct sock *sk = BPF_CORE_READ(sock, sk);
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6) {
		count(&other_sends);
		return 0;
	}

	u8 peer[16] = {};
	__be16 port = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (family == AF_INET) {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(peer, &a, 4);
	} else if (bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
		BPF_CORE_READ_INTO((struct in6_addr *)peer, sk, __sk_common.skc_v6_daddr);
	}
	u64 half[2];
	__builtin_memcpy(half, peer, 16);
	int peerless = !port && !half[0] && !half[1];
	int type = (u16)BPF_CORE_READ(sock, type);
	if (dest_family(OP_SENDMSG, sock, BPF_CORE_READ(msg, msg_name), BPF_CORE_READ(msg, msg_namelen)) > 0 &&
	    (peerless || type != SOCK_STREAM))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_loss();
		return 0;
	}
	e->op = OP_DELIVER;
	e->family = family;
	e->sock_type = type;
	e->protocol = BPF_CORE_READ(sk, sk_protocol);
	e->bytes = (u32)(int)ctx[2];
	e->port = port;
	__builtin_memcpy(e->addr, peer, 16);
	fill_local(e, sk);
	fill_caller(e, t, kn, &p);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// note_move counts a task going from one cgroup to another outside its session.
// Which cgroup it goes to does not matter: the session root, an ancestor or
// another session are all out of the claim about this one.
static __always_inline void note_move(struct kernfs_node *from, struct kernfs_node *to)
{
	struct place a, b;
	place_of(from, &a);
	if (!a.deep && !a.session)
		return;
	place_of(to, &b);
	if (a.deep || b.deep)
		count(&too_deep);
	else if (a.session != b.session)
		count(&left_session);
}

// int cgroup_attach_task(struct cgroup *dst_cgrp, struct task_struct *leader, bool threadgroup)
//
// Every write to cgroup.procs or cgroup.threads comes through here. The tracepoint
// of the same name fires after the move, with the old cgroup gone, so this is the
// entry instead; a move that then fails is counted, which only over-reports. A
// task in a v1 hierarchy moves there too, and that is not its session.
SEC("fentry/cgroup_attach_task")
int handle_attach(u64 *ctx)
{
	struct cgroup *dst = (struct cgroup *)ctx[0];
	struct task_struct *t = (struct task_struct *)ctx[1];
	struct cgroup *src = BPF_CORE_READ(t, cgroups, dfl_cgrp);
	if (src == dst || BPF_CORE_READ(src, root) != BPF_CORE_READ(dst, root))
		return 0;
	note_move(BPF_CORE_READ(src, kn), BPF_CORE_READ(dst, kn));
	return 0;
}

// A child made with CLONE_INTO_CGROUP starts in another cgroup without a move, so
// the hook above does not see it.
SEC("tp_btf/sched_process_fork")
int handle_fork(u64 *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx[0];
	struct task_struct *child = (struct task_struct *)ctx[1];
	struct kernfs_node *from = BPF_CORE_READ(parent, cgroups, dfl_cgrp, kn);
	struct kernfs_node *to = BPF_CORE_READ(child, cgroups, dfl_cgrp, kn);
	if (from != to)
		note_move(from, to);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
