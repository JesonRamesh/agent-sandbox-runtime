// SPDX-License-Identifier: GPL-2.0
//
// Network observability + enforcement.
//
//   lsm/socket_connect            — denies disallowed outbound connects
//   tp/syscalls/sys_enter_sendto  — audits UDP sendto (observe-only, B-005)
//
// Reference: vendor/tetragon/bpf/process/bpf_generic_kprobe.c uses kprobes
// on tcp_connect; we use the LSM hook instead (decision D-004) because
// it's the only way to block from eBPF on a stable kernel ABI.

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET   2
#define AF_INET6 10

static __always_inline int host_allowed(struct policy *pol, __u32 daddr_v4, __u16 dport)
{
    for (int i = 0; i < MAX_HOSTS; i++) {
        if (i >= pol->n_hosts)
            break;
        struct host_rule *r = &pol->hosts[i];
        __u32 mask = r->prefix_len >= 32 ? 0xFFFFFFFF :
                     (r->prefix_len == 0 ? 0 : (0xFFFFFFFF << (32 - r->prefix_len)));
        if ((daddr_v4 & mask) == (r->addr_v4 & mask)) {
            if (r->port == 0 || r->port == dport)
                return 1;
        }
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(asb_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // If a previous LSM in the chain already denied, propagate it.
    if (ret != 0)
        return ret;

    __u32 pol_id = lookup_policy_id();
    struct policy *pol = lookup_policy(pol_id);
    if (!pol)
        return 0;   // unmanaged cgroup -> allow

    __u16 family = BPF_CORE_READ(address, sa_family);
    if (family != AF_INET)
        return 0;   // v6/unix not enforced in v0; emit-only path below would go here

    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    __u32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));

    int allowed = host_allowed(pol, daddr, dport);
    int verdict = allowed ? VERDICT_ALLOW
                          : (pol->mode ? VERDICT_DENY : VERDICT_AUDIT);

    struct {
        struct event_hdr  hdr;
        struct net_event  net;
    } *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        fill_hdr(&evt->hdr, EVT_NET_CONNECT, verdict);
        evt->net.family    = family;
        evt->net.dport     = dport;
        evt->net._pad      = 0;
        evt->net.daddr_v4  = daddr;
        __builtin_memset(evt->net.daddr_v6, 0, 16);
        bpf_ringbuf_submit(evt, 0);
    }

    if (verdict == VERDICT_DENY)
        return -1;   // -EPERM
    return 0;
}

SEC("tp/syscalls/sys_enter_sendto")
int asb_sendto(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pol_id = lookup_policy_id();
    if (pol_id == 0)
        return 0;

    // Observe-only: emit an audit event so the daemon can correlate
    // with the policy. Blocking via SIGKILL handled in userspace
    // (see B-005).
    struct {
        struct event_hdr  hdr;
        struct net_event  net;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    fill_hdr(&evt->hdr, EVT_NET_SENDTO, VERDICT_AUDIT);
    evt->net.family   = 0;
    evt->net.dport    = 0;
    evt->net._pad     = 0;
    evt->net.daddr_v4 = 0;
    __builtin_memset(evt->net.daddr_v6, 0, 16);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
