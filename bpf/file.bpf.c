// SPDX-License-Identifier: GPL-2.0
//
// Filename access observability + enforcement.
//
//   lsm.s/file_open  — sleepable LSM hook so we can call bpf_d_path()
//
// Reference: vendor/tetragon/bpf/process/bpf_generic_lsm_ima_file.c.
// Tetragon walks the dentry chain manually; we lean on bpf_d_path on
// kernel 6.8+ (decision D-001, bug B-003).

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int path_allowed(struct policy *pol, const char *path)
{
    for (int i = 0; i < MAX_PATHS; i++) {
        if (i >= pol->n_paths)
            break;
        if (has_prefix(path, pol->paths[i].prefix))
            return 1;
    }
    return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(asb_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u32 pol_id = lookup_policy_id();
    struct policy *pol = lookup_policy(pol_id);
    if (!pol)
        return 0;

    struct {
        struct event_hdr  hdr;
        struct file_event f;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    long n = bpf_d_path(&file->f_path, evt->f.path, MAX_PATH);
    if (n < 0) {
        // Path resolution failed — emit a stub event, allow.
        evt->f.path[0] = 0;
        evt->f.flags   = BPF_CORE_READ(file, f_flags);
        fill_hdr(&evt->hdr, EVT_FILE_OPEN, VERDICT_AUDIT);
        bpf_ringbuf_submit(evt, 0);
        return 0;
    }
    evt->f.flags = BPF_CORE_READ(file, f_flags);

    int allowed = path_allowed(pol, evt->f.path);
    int verdict = allowed ? VERDICT_ALLOW
                          : (pol->mode ? VERDICT_DENY : VERDICT_AUDIT);
    fill_hdr(&evt->hdr, EVT_FILE_OPEN, verdict);
    bpf_ringbuf_submit(evt, 0);

    if (verdict == VERDICT_DENY)
        return -1;   // -EPERM
    return 0;
}
