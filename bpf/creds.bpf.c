// SPDX-License-Identifier: GPL-2.0
//
// Credential monitoring + enforcement.
//
//   lsm/task_fix_setuid — uid escalation
//   lsm/task_fix_setgid — gid escalation
//   lsm/capset          — capability set changes
//
// Reference: vendor/tetragon/bpf/process/bpf_execve_bprm_commit_creds.c.
// Tetragon emits a richer creds-change struct; we only emit deltas.

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int caps_allowed(struct policy *pol, __u64 effective)
{
    return (effective & pol->forbidden_caps) == 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(asb_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
    if (ret != 0)
        return ret;

    __u32 pol_id = lookup_policy_id();
    struct policy *pol = lookup_policy(pol_id);
    if (!pol)
        return 0;

    __u32 new_uid = BPF_CORE_READ(new, uid.val);
    __u32 old_uid = BPF_CORE_READ(old, uid.val);

    int escalating = (new_uid == 0 && old_uid != 0);
    int verdict = !escalating ? VERDICT_ALLOW
                              : (pol->mode ? VERDICT_DENY : VERDICT_AUDIT);

    struct {
        struct event_hdr   hdr;
        struct creds_event c;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        fill_hdr(&evt->hdr, EVT_CREDS_SETUID, verdict);
        evt->c.old_id         = old_uid;
        evt->c.new_id         = new_uid;
        evt->c.cap_effective  = 0;
        bpf_ringbuf_submit(evt, 0);
    }

    if (verdict == VERDICT_DENY)
        return -1;
    return 0;
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(asb_setgid, struct cred *new, const struct cred *old, int flags, int ret)
{
    if (ret != 0)
        return ret;
    __u32 pol_id = lookup_policy_id();
    if (pol_id == 0)
        return 0;

    __u32 new_gid = BPF_CORE_READ(new, gid.val);
    __u32 old_gid = BPF_CORE_READ(old, gid.val);

    struct {
        struct event_hdr   hdr;
        struct creds_event c;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        fill_hdr(&evt->hdr, EVT_CREDS_SETGID, VERDICT_AUDIT);
        evt->c.old_id         = old_gid;
        evt->c.new_id         = new_gid;
        evt->c.cap_effective  = 0;
        bpf_ringbuf_submit(evt, 0);
    }
    return 0;
}

SEC("lsm/capset")
int BPF_PROG(asb_capset, struct cred *new, const struct cred *old,
             const kernel_cap_t *effective,
             const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted, int ret)
{
    if (ret != 0)
        return ret;

    __u32 pol_id = lookup_policy_id();
    struct policy *pol = lookup_policy(pol_id);
    if (!pol)
        return 0;

    __u64 eff = BPF_CORE_READ(effective, val);

    int allowed = caps_allowed(pol, eff);
    int verdict = allowed ? VERDICT_ALLOW
                          : (pol->mode ? VERDICT_DENY : VERDICT_AUDIT);

    struct {
        struct event_hdr   hdr;
        struct creds_event c;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        fill_hdr(&evt->hdr, EVT_CREDS_CAPSET, verdict);
        evt->c.old_id        = 0;
        evt->c.new_id        = 0;
        evt->c.cap_effective = eff;
        bpf_ringbuf_submit(evt, 0);
    }

    if (verdict == VERDICT_DENY)
        return -1;
    return 0;
}
