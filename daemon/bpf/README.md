# `daemon/bpf/` — vendored eBPF reference (read-only)

This directory contains a **read-only mirror** of the C-side contract that
this daemon's loader, policy compiler, and event decoder are compiled
against. We do not author, modify, or compile any C here — that is owned
by the eBPF engineer (P1, branch `Mehul`).

## Files

| file | source |
|---|---|
| [`common.h.reference`](common.h.reference) | `bpf/common.h` from `JesonRamesh/agent-sandbox-runtime@Mehul` (SHA `8e16c8218d7b0b7a70e9c9ac95b67b2c65dbc103`) |

## Why it's vendored

Our Go code mirrors three things from `common.h`:

1. The **map names** the loader looks up (`events`, `cgroup_policy`, `policies`).
2. The **field order and sizes** of `struct policy`, `struct host_rule`, `struct path_rule`, `struct binary_rule`, `struct event_hdr`, `struct net_event`, `struct file_event`, `struct creds_event`, `struct exec_event`.
3. The **enum values** for `event_kind` and `verdict`.

All three must stay byte-for-byte identical between this header and
`internal/bpf/loader.go` + `internal/policy/policy.go` +
`internal/events/decoder.go`. Vendoring the header here means a
reviewer can diff the C against the Go in one PR rather than chasing
across two branches.

## How to refresh

When the team merges and Mehul's `bpf/` lives at the repo root, this
directory becomes redundant — delete `common.h.reference` and add a
note in `docs/integration-with-mehul-ebpf.md`. Until then:

```bash
gh api 'repos/JesonRamesh/agent-sandbox-runtime/contents/bpf/common.h?ref=Mehul' \
  --jq .content | base64 -d > daemon/bpf/common.h.reference
```

If anything in the file changes meaningfully (struct field added,
enum value renumbered, map renamed), the Go side must be updated in
the same commit — ABI drift here corrupts every event we decode.

## What this directory does NOT contain

- No `.bpf.c` programs.
- No `.bpf.o` artifacts.
- No `Makefile` for compiling BPF.
- No `vmlinux.h`.

The four `.bpf.o` files our loader expects at runtime (`network.bpf.o`,
`file.bpf.o`, `creds.bpf.o`, `exec.bpf.o`) are produced by Mehul's
`bpf/Makefile` on the Vagrant VM and installed to
`/usr/lib/agent-sandbox/bpf/` by the deploy scripts.
