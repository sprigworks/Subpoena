// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// execbpf: report every process exec (and, optionally, every fork) with the
// process's cgroup, read in the kernel at the moment of exec.
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
#define DEPTH 8      // cgroup path elements kept, leaf first
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
	char cgroup[DEPTH][NAME_LEN]; // cgroup path elements: [0] is the leaf
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

static __always_inline void record_loss(void)
{
	u32 key = 0;
	u64 *count = bpf_map_lookup_elem(&lost, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

// Set from Go before loading: report forks too (needed for lineage).
const volatile u32 track_forks = 0;
// Set from Go before loading: the inode of the witness's PID namespace
// (/proc/self/ns/pid), so PIDs are reported as the witness sees them.
// 0 reports initial-namespace PIDs.
const volatile u32 pidns_inum = 0;

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

SEC("tp_btf/sched_process_fork")
int handle_fork(u64 *ctx)
{
	if (!track_forks)
		return 0;
	struct task_struct *parent = (struct task_struct *)ctx[0];
	struct task_struct *child = (struct task_struct *)ctx[1];
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
