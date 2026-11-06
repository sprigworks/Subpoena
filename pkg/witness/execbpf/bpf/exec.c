// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// execbpf: report every process exec (and, optionally, every fork) with the
// process's cgroup, read in the kernel at the moment of exec. Two more hooks count
// a task leaving its session, which would otherwise take its execs out of the
// session unseen. The walk and those hooks are netbpf's (net.c).
//
// The kernel requires a GPL-compatible license string for the tracing helpers
// used here; this file is dual-licensed MIT or GPL-2.0 so that it can be. It is
// loaded into the kernel by pkg/witness/execbpf, never linked into Go code.

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

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
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
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct pid *thread_pid;
	struct mm_struct *mm;
	struct css_set *cgroups;
} __attribute__((preserve_access_index));

struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

#define KIND_EXEC 1
#define KIND_FORK 2

#define NAME_LEN 64  // one cgroup path element (a trace ID is 32)
#define DEPTH 8      // cgroup path elements kept
#define WALK 32      // cgroup levels searched for the session root; deeper is counted, never guessed
#define PATH_LEN 256 // executable path
#define ARGS_LEN 512 // argv, NUL-separated, truncated
#define PIDNS_DEPTH 8 // PID namespace nesting levels searched

struct event {
	u64 cgroup_id; // bpf_get_current_cgroup_id()
	u64 kn_id;     // the cgroup's kernfs node id (equal to cgroup_id on cgroup v2)
	u32 kind;
	u32 pid;       // process ID in the witness's PID namespace (0: not visible there)
	u32 ppid;      // parent's process ID in the witness's PID namespace
	u32 host_pid;  // process ID in the initial PID namespace
	u32 host_ppid; // parent's process ID in the initial PID namespace
	u32 args_len;
	u32 depth; // number of valid entries in cgroup
	char comm[16];
	char cgroup[DEPTH][NAME_LEN]; // cgroup path elements, leaf-most first (see fill_common)
	char filename[PATH_LEN];
	char args[ARGS_LEN];
};

// Unused at run time; makes bpf2go emit the Go type (-type event).
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

// Every failed reservation is a capture gap, including a lost fork needed for
// lineage. Per-CPU storage avoids contention; atomic increments also cover
// nested execution on a CPU. Go sums all CPUs after detaching both hooks.
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

// Tasks that left a session during the capture: moved out of it, or forked out
// of it with CLONE_INTO_CGROUP. An exec after that is not the session's, so it
// cannot be attributed, and Go fails Health instead. Read like lost.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} left_session SEC(".maps");

// Execs and moves whose cgroup path is too long to walk to the top, so nothing can
// say whether they are in a session. Go fails Health. Read like lost.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} too_deep SEC(".maps");

// Set from Go before loading: report forks too (needed for lineage).
const volatile u32 track_forks = 0;
// Set from Go before loading: the inode of the witness's PID namespace
// (/proc/self/ns/pid), so PIDs are reported as the witness sees them.
// 0 reports initial-namespace PIDs.
const volatile u32 pidns_inum = 0;
// Set from Go before loading: the last element of the session cgroup root,
// NUL-terminated.
const volatile char session_base[NAME_LEN] = {};

// ns_tgid returns t's process ID as seen in the namespace pidns_inum, or 0
// when t is not visible there.
static __always_inline u32 ns_tgid(struct task_struct *t)
{
	if (!pidns_inum)
		return BPF_CORE_READ(t, tgid);
	struct pid *pid = BPF_CORE_READ(t, group_leader, thread_pid);
	if (!pid)
		return 0;
	unsigned int level = BPF_CORE_READ(pid, level);
	// A bounded loop, not unrolled (the early exit defeats unrolling); the
	// verifier accepts bounded loops from Linux 5.3, and BTF needs 5.8 anyway.
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
// not, -1 if its name cannot be read. Not inlined, and not static, for the verifier;
// see net.c.
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

// fill_common sets the fields every event carries. The path keeps DEPTH elements.
// Usually those are the leaf and up, but with the session root further up than that
// they end at the root, dropping the leaf instead: Go attributes by <root>/<trace>,
// and the elements nearest the leaf are the application's to choose. With no way to
// find the root the path is left empty, so nothing can be attributed from it.
static __always_inline void fill_common(struct event *e, struct task_struct *p, struct task_struct *parent, u32 kind)
{
	e->kind = kind;
	e->pid = ns_tgid(p);
	e->ppid = ns_tgid(parent);
	e->host_pid = BPF_CORE_READ(p, tgid);
	e->host_ppid = BPF_CORE_READ(parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->args_len = 0;
	e->filename[0] = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	struct kernfs_node *kn = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn);
	e->kn_id = kn ? BPF_CORE_READ(kn, id) : 0;
	e->depth = 0;
	struct place at;
	place_of(kn, &at);
	if (at.deep) {
		count(&too_deep);
		kn = 0;
	} else if (at.found && at.base_at >= DEPTH) {
		u32 skip = at.base_at - (DEPTH - 1);
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

SEC("tp_btf/sched_process_exec")
int handle_exec(u64 *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx[0];
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[2];

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_loss();
		return 0;
	}
	fill_common(e, p, BPF_CORE_READ(p, real_parent), KIND_EXEC);

	if (bpf_probe_read_kernel_str(e->filename, PATH_LEN, BPF_CORE_READ(bprm, filename)) < 0)
		e->filename[0] = 0;

	unsigned long start = BPF_CORE_READ(p, mm, arg_start);
	unsigned long end = BPF_CORE_READ(p, mm, arg_end);
	u64 len = end > start ? end - start : 0;
	if (len >= ARGS_LEN)
		len = ARGS_LEN - 1;
	len &= ARGS_LEN - 1;
	if (len > 0 && bpf_probe_read_user(e->args, len, (const void *)start) == 0)
		e->args_len = len;

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

SEC("tp_btf/sched_process_fork")
int handle_fork(u64 *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx[0];
	struct task_struct *child = (struct task_struct *)ctx[1];
	// A child made with CLONE_INTO_CGROUP starts in another cgroup without a
	// move, so handle_attach does not see it.
	struct kernfs_node *from = BPF_CORE_READ(parent, cgroups, dfl_cgrp, kn);
	struct kernfs_node *to = BPF_CORE_READ(child, cgroups, dfl_cgrp, kn);
	if (from != to)
		note_move(from, to);
	if (!track_forks)
		return 0;
	u32 pid = BPF_CORE_READ(child, pid);
	u32 tgid = BPF_CORE_READ(child, tgid);
	if (pid != tgid)
		return 0; // a new thread, not a new process

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_loss();
		return 0;
	}
	// The child has inherited the parent's cgroup by now; the IDs and the
	// cgroup walk are the child's, the cgroup ID helper reads current (the
	// parent), which is the same cgroup.
	fill_common(e, child, parent, KIND_FORK);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
