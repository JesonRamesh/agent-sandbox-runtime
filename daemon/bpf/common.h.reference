// SPDX-License-Identifier: GPL-2.0
//
// Shared types and maps for agent-sandbox-runtime eBPF programs.
//
// One ringbuf carries every event upward to the daemon; one
// `cgroup -> policy_id` lookup map and one `policy_id -> ruleset`
// array map drive in-kernel decisions. See decision D-003.
//
// Heavily inspired by Tetragon's bpf/process/ layout — but minimal.

#ifndef __AGENTSANDBOX_COMMON_H
#define __AGENTSANDBOX_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_PATH       256   // see bug B-004
#define MAX_HOSTS       64
#define MAX_PATHS       64
#define MAX_BINARIES    32
#define MAX_POLICIES    32
#define COMM_LEN        16

// One discriminant per pillar; matches daemon/internal/events/decoder.go
enum event_kind {
    EVT_NET_CONNECT   = 1,
    EVT_NET_SENDTO    = 2,
    EVT_FILE_OPEN     = 3,
    EVT_CREDS_SETUID  = 4,
    EVT_CREDS_SETGID  = 5,
    EVT_CREDS_CAPSET  = 6,
    EVT_EXEC          = 7,
};

enum verdict {
    VERDICT_ALLOW = 0,
    VERDICT_DENY  = 1,
    VERDICT_AUDIT = 2,   // observe-only
};

struct event_hdr {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 kind;          // enum event_kind
    __u32 verdict;       // enum verdict
    char  comm[COMM_LEN];
};

// Per-pillar payloads — emitted as `event_hdr` followed by one of these.

struct net_event {
    __u32 family;        // AF_INET=2, AF_INET6=10
    __u16 dport;
    __u16 _pad;
    __u32 daddr_v4;
    __u8  daddr_v6[16];
};

struct file_event {
    __s32 flags;
    char  path[MAX_PATH];
};

struct creds_event {
    __u32 old_id;
    __u32 new_id;
    __u64 cap_effective;
};

struct exec_event {
    __u32 ppid;
    __u32 _pad;
    char  filename[MAX_PATH];
};

// ----- maps -----------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   // 1 MiB
} events SEC(".maps");

// cgroup_id -> policy_id (0 = unmanaged, default ALLOW + AUDIT)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);
    __type(value, __u32);
} cgroup_policy SEC(".maps");

// One entry per policy. Layouts below.
struct host_rule {
    __u32 addr_v4;
    __u32 prefix_len;    // 0..32
    __u16 port;          // 0 = any
    __u16 _pad;
};

struct path_rule {
    char prefix[MAX_PATH];
};

struct binary_rule {
    char path[MAX_PATH];
};

struct policy {
    __u32 mode;                  // 0=audit-only, 1=enforce
    __u32 n_hosts;
    __u32 n_paths;
    __u32 n_bins;
    __u64 forbidden_caps;        // bitmask, e.g. (1<<CAP_SYS_ADMIN)
    struct host_rule   hosts[MAX_HOSTS];
    struct path_rule   paths[MAX_PATHS];
    struct binary_rule bins[MAX_BINARIES];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICIES);
    __type(key,   __u32);
    __type(value, struct policy);
} policies SEC(".maps");

// ----- helpers --------------------------------------------------------

static __always_inline __u32 lookup_policy_id(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    __u32 *pid = bpf_map_lookup_elem(&cgroup_policy, &cg);
    return pid ? *pid : 0;
}

static __always_inline struct policy *lookup_policy(__u32 id)
{
    if (id == 0)
        return 0;
    return bpf_map_lookup_elem(&policies, &id);
}

static __always_inline void fill_hdr(struct event_hdr *h, __u32 kind, __u32 verdict)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    h->ts_ns     = bpf_ktime_get_ns();
    h->pid       = (__u32)pid_tgid;
    h->tgid      = (__u32)(pid_tgid >> 32);
    h->uid       = (__u32)uid_gid;
    h->gid       = (__u32)(uid_gid >> 32);
    h->cgroup_id = bpf_get_current_cgroup_id();
    h->kind      = kind;
    h->verdict   = verdict;
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

// Longest-prefix string match for path/binary rules. The kernel
// verifier (≥ 5.3) handles bounded for-loops natively, so we don't
// need `#pragma unroll` here — and unrolling MAX_PATH=256 iterations
// inside an already-bounded outer loop blows clang's unroll budget
// (bug B-014).
static __always_inline int has_prefix(const char *path, const char *prefix)
{
    for (int i = 0; i < MAX_PATH; i++) {
        char p = prefix[i];
        if (p == 0)
            return 1;
        if (path[i] != p)
            return 0;
    }
    return 1;
}

#endif // __AGENTSANDBOX_COMMON_H
