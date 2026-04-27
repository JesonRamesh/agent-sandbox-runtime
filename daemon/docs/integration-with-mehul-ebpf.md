# Daemon ↔ eBPF integration (with `Mehul` branch)

> **Audience:** Mehul (P1, eBPF) and whoever does the merge tomorrow.
> **TL;DR:** This daemon has been ported off its own `cgroup/connect4`
> design onto the BPF LSM contract you've already authored on the
> `Mehul` branch. The Go code consumes your `bpf/common.h` verbatim.
> One small ask is at the bottom; read on for context.

## What I did

Branched `Harrish/sandbox-daemon` from `main` (so we don't touch your
work-in-progress). Dropped my own eBPF stubs (`internal/bpf/programs/`,
the bpf2go pipeline, `vmlinux.h`) and rewired the daemon's
`internal/bpf/`, `internal/policy/`, and event decoder to:

- **Load four prebuilt `.bpf.o` objects** at startup
  (`network`, `file`, `creds`, `exec`) from `--bpf-dir` (default
  `/usr/lib/agent-sandbox/bpf`). One `*ebpf.Collection` per object,
  shared `events`/`cgroup_policy`/`policies` maps pinned at
  `/sys/fs/bpf/agent-sandbox/`.

- **Attach all eight programs** (the LSM hooks plus the two tracepoints)
  exactly the way your `daemon/internal/loader/loader.go:attachAll()`
  does. Program names are matched verbatim:
  `asb_socket_connect`, `asb_sendto`, `asb_file_open`, `asb_setuid`,
  `asb_setgid`, `asb_capset`, `asb_sched_exec`, `asb_bprm_check`.

- **Allocate per-agent `policy_id`s** from a free-list (1..32). On
  `RunAgent`, the daemon compiles the manifest into a `struct policy`
  Go-mirror, writes `policies[id]` first then `cgroup_policy[cg]→id`.
  On agent exit, both entries are cleared and the id returns to the
  pool. This preserves the daemon's per-agent IPC model on top of your
  system-wide BPF runtime.

- **Decode `event_hdr` + per-pillar payloads** from the shared `events`
  ringbuf, fan out by `cgroup_id` to per-agent channels, and emit each
  one via the existing `events.Pipeline` (slog + per-agent log file +
  WebSocket subscribers).

A vendored copy of your `bpf/common.h` lives at
[`../bpf/common.h.reference`](../bpf/common.h.reference) (SHA
`8e16c8218d7b0b7a70e9c9ac95b67b2c65dbc103` from `Mehul`). All Go
struct mirrors are validated against it — see
`internal/policy/policy.go` (`Compiled`, `HostRule`, `PathRule`,
`BinaryRule`) and `internal/bpf/event.go` (`rawHeader`, `rawNet`,
`rawFile`, `rawCreds`, `rawExec`).

## Frozen C-side contract

The Go side depends on these staying byte-identical:

### Map names

| name | type | key → value | purpose |
|---|---|---|---|
| `events` | RINGBUF (1 MiB) | — | one channel for all four pillars; `event_hdr` + payload |
| `cgroup_policy` | HASH (1024) | `__u64 cgroup_id` → `__u32 policy_id` | bind a cgroup to a policy |
| `policies` | ARRAY (32) | `__u32 policy_id` → `struct policy` | the actual rules |

### Struct field order

`struct policy`, `struct host_rule`, `struct path_rule`,
`struct binary_rule`, `struct event_hdr`, `struct net_event`,
`struct file_event`, `struct creds_event`, `struct exec_event`. Field
*order* matters more than field *count*: adding a field at the end is
ABI-compatible if we bump the Go mirror in the same commit; reordering
or replacing existing fields silently corrupts every record.

### Enum values

`enum event_kind` (1..7) and `enum verdict` (0..2) — the Go decoder
switches on these exact integers.

### Hook attach points

The eight `SEC()` strings on your programs:
`lsm/socket_connect`, `tp/syscalls/sys_enter_sendto`,
`lsm.s/file_open`, `lsm/task_fix_setuid`, `lsm/task_fix_setgid`,
`lsm/capset`, `tp/sched/sched_process_exec`,
`lsm/bprm_check_security`. The daemon doesn't care about the SEC()
strings directly — it cares about the program names listed in
`internal/bpf/loader.go:attachTable`.

## What the daemon expects at runtime

- `bpffs` mounted at `/sys/fs/bpf`. (`deploy/install.sh` mounts it and
  adds an `/etc/fstab` entry.)
- Kernel boot with `lsm=…,bpf` in the cmdline. Your `setup-vm.sh` does
  this via the GRUB drop-in; that's compatible.
- The four `.bpf.o` files at `--bpf-dir`. Default
  `/usr/lib/agent-sandbox/bpf/{network,file,creds,exec}.bpf.o`.
- `cgroup` v2 unified hierarchy (Ubuntu 24.04 default).
- `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` (matches
  your systemd unit's ambient set).

## Asks for merge day

Small list. None of these are blockers for our branches living
side-by-side; they're refinements to make the merged repo work
end-to-end without per-host tweaks.

1. **Bump `MAX_POLICIES` from 32 to 64** in `bpf/common.h`. The
   `policies` ARRAY map sets the concurrent-agent ceiling for the
   whole host. 32 is fine for a demo; 64 gives us breathing room for
   anyone running a small fleet of test agents in parallel. Trivial
   header change, recompile of the four `.bpf.o`.

2. **Confirm `struct policy` and `struct event_hdr` field order is
   final.** Adding fields at the end is fine (we'll match in the same
   commit); reordering or shrinking existing fields breaks the daemon
   silently. If any reordering is planned, ping me before the merge so
   the Go mirrors land in lockstep.

3. **Provide a `make install` target (or document the path)** that
   lands the four `.bpf.o` files at a stable location. The daemon's
   `--bpf-dir` defaults to `/usr/lib/agent-sandbox/bpf/`. Either match
   that, or tell me the path and I'll update the default. (Your
   top-level `Makefile` already does
   `install -m 0644 bpf/*.bpf.o $(DESTDIR)/usr/lib/agentsandbox/bpf/`
   — close, just a different parent dir.)

4. **(Optional) coexistence note.** Your branch contains a daemon stub
   under `daemon/cmd/agentd/` that does the same job differently
   (HTTP+SSE, system-wide). Mine is at `daemon/cmd/daemon/` after
   merge, so the two won't collide on path. Pick whichever architecture
   the team wants at merge time — see
   [`docs/daemon-model-comparison.md`](daemon-model-comparison.md) for
   why mine is per-agent IPC. **No code change needed on your side
   for this.** It's a team-decision question, not an integration ask.

## What I did NOT change

- Your `bpf/*.bpf.c` files. None of them. The vendored
  `daemon/bpf/common.h.reference` is read-only — see
  [`../bpf/README.md`](../bpf/README.md).
- Your `daemon/` stub. It still exists on the `Mehul` branch. Tomorrow's
  merge will need to pick which daemon wins (or rename one).
- Your `Vagrantfile` / `setup-vm.sh` / `systemd/agentsandbox.service`.
  These are runtime concerns and your install path is fine.
- Your CLI (`cli/agentctl/`). My branch ships `cmd/test-client` for
  development; the real CLI is whichever P3 ends up shipping.

## How to verify on the Vagrant VM at merge time

```bash
cd ~/agent-sandbox-runtime

# 1. Build Mehul's BPF objects
make -C bpf

# 2. Build my daemon
cd daemon && make build

# 3. Install BPF objects where the daemon expects them
sudo install -d /usr/lib/agent-sandbox/bpf
sudo install -m 0644 ../bpf/*.bpf.o /usr/lib/agent-sandbox/bpf/

# 4. Run the daemon (foreground, stderr log)
sudo bin/agent-sandbox-daemon

# 5. In another terminal: send a manifest
sudo bin/test-client --socket /run/agent-sandbox.sock run examples/curl-blocked.json

# Expect: curl exits non-zero; daemon log shows
#   net.connect verdict=deny daddr=1.1.1.1
#   agent.exited exit_code=<nonzero>
```

If anything fails at step 4, the most common causes are (in order):

1. `bpffs` not mounted → `mount -t bpf bpf /sys/fs/bpf`.
2. Kernel cmdline missing `lsm=…,bpf` → reboot after `setup-vm.sh`.
3. `.bpf.o` files at the wrong path → `--bpf-dir=/path/to/bpf`.

That's the whole integration. Ping me on slack if anything in the
"asks" list above is unclear.
