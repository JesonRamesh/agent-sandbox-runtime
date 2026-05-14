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
    if (family == AF_INET6) {
        // v6 connects are NOT enforced in v0 — but they used to be silent.
        // Emit an audit event so the operator's dashboard reflects reality.
        // Address bytes are recorded for forensics; verdict is AUDIT to
        // make it visually distinct from an enforced allow.
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        struct {
            struct event_hdr  hdr;
            struct net_event  net;
        } *evt6 = bpf_ringbuf_reserve(&events, sizeof(*evt6), 0);
        if (evt6) {
            __builtin_memset(evt6, 0, sizeof(*evt6));
            fill_hdr(&evt6->hdr, EVT_NET_CONNECT, VERDICT_AUDIT);
            evt6->net.family   = family;
            evt6->net.dport    = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
            evt6->net._pad     = 0;
            evt6->net.daddr_v4 = 0;
            // sizeof(daddr_v6) == sizeof(struct in6_addr) == 16, so reading
            // the whole sin6_addr struct in one go fills the destination.
            BPF_CORE_READ_INTO(&evt6->net.daddr_v6, sin6, sin6_addr);
            bpf_ringbuf_submit(evt6, 0);
        }
        return 0;
    }
    if (family != AF_INET)
        return 0;   // unix and other families: out of scope for v0

    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    __u32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));

    int allowed = host_allowed(pol, daddr, dport);

    // Cleartext-egress gate. Applies *only after* host_allowed already
    // matched — we don't want a non-TLS port to mask a host-allowlist
    // failure with a confusing reason. If the host check failed we fall
    // through to the normal deny path; if it succeeded but the port is
    // not TLS and the agent's policy forbids cleartext egress, downgrade
    // the verdict to DENY. The reason string is reconstructed in
    // userspace (internal/policy/attribute.go) from the same manifest
    // and the kernel-reported daddr:dport, so we don't need an extra
    // event-kind here.
    int cleartext_denied = 0;
    if (allowed && pol->deny_cleartext_egress && !IS_TLS_PORT(dport)) {
        allowed = 0;
        cleartext_denied = 1;
    }

    int verdict = allowed ? VERDICT_ALLOW
                          : (pol->mode ? VERDICT_DENY : VERDICT_AUDIT);
    (void)cleartext_denied;  // reserved for a future kind discriminant

    struct {
        struct event_hdr  hdr;
        struct net_event  net;
    } *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
        fill_hdr(&evt->hdr, EVT_NET_CONNECT, verdict);
        evt->net.family    = family;
        evt->net.dport     = dport;
        evt->net._pad      = 0;
        evt->net.daddr_v4  = daddr;
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
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_hdr(&evt->hdr, EVT_NET_SENDTO, VERDICT_AUDIT);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
