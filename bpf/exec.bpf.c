// SPDX-License-Identifier: GPL-2.0
//
// Privileged execution observability + enforcement.
//
//   tp/sched/sched_process_exec  — observe every exec
//   lsm/bprm_check_security      — deny disallowed binaries
//
// Reference: vendor/tetragon/bpf/process/bpf_execve_event.c is the
// gold standard for execve tracing. We keep just the filename +
// parent PID; argv/env handling is intentionally out of scope.

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int binary_allowed(struct policy *pol, const char *filename)
{
    if (pol->n_bins == 0)
        return 1;   // empty list -> allow all
    for (int i = 0; i < MAX_BINARIES; i++) {
        if (i >= pol->n_bins)
            break;
        if (has_prefix(filename, pol->bins[i].path))
            return 1;
    }
    return 0;
}

SEC("tp/sched/sched_process_exec")
int asb_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pol_id = lookup_policy_id();
    if (pol_id == 0)
        return 0;

    struct {
        struct event_hdr  hdr;
        struct exec_event e;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_hdr(&evt->hdr, EVT_EXEC, VERDICT_AUDIT);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->e.ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->e._pad = 0;

    // The tracepoint format places filename at ctx->__data + ctx->filename_loc&0xFFFF.
    unsigned int loc = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(evt->e.filename, MAX_PATH,
                              (char *)ctx + loc);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(asb_bprm_check, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    __u32 pol_id = lookup_policy_id();
    struct policy *pol = lookup_policy(pol_id);
    if (!pol)
        return 0;

    // Stage the filename inside the ringbuf-reserved buffer rather
    // than on the BPF stack: a 256-byte local would blow the 512-byte
    // stack limit (bug B-013). We discard the reservation later if
    // the policy allows the binary so we don't emit noise.
    struct {
        struct event_hdr  hdr;
        struct exec_event e;
    } *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    const char *fn = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(evt->e.filename, MAX_PATH, fn);

    if (binary_allowed(pol, evt->e.filename)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    int verdict = pol->mode ? VERDICT_DENY : VERDICT_AUDIT;
    fill_hdr(&evt->hdr, EVT_EXEC, verdict);
    evt->e.ppid = 0;
    evt->e._pad = 0;
    bpf_ringbuf_submit(evt, 0);

    if (verdict == VERDICT_DENY)
        return -1;
    return 0;
}
