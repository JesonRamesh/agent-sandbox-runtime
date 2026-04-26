# Agent Sandbox Runtime

A Linux-based sandbox / "guardrailed Ubuntu" that watches and contains
prompt-injected AI agents. Enforced at the kernel level using eBPF on
**four pillars**: network, filename access, credentials, and privileged
execution. Ships as an Ubuntu 24.04 VM today, with a built-in web GUI
to customize the guardrails.

## What it does

When an AI agent gets tricked via prompt injection, it might try to
exfiltrate data, read secret files, drop privileges, or execute new
binaries. Python-level guardrails can be bypassed. This runtime moves
enforcement *below* the agent — into the kernel itself — so the bad
syscall is blocked regardless of what the agent was told to do.

```
┌──────────────────────────────────┐
│   agentctl run my-agent.yaml     │
└───────────────┬──────────────────┘
                │
       ┌────────▼─────────┐         ┌────────────────────┐
       │      agentd       │ ──────▶│  Web GUI (vanilla) │
       │  (Go control      │  /api   │  127.0.0.1:9000    │
       │   plane + ringbuf)│         └────────────────────┘
       └────────┬──────────┘
                │ loads & maps
       ┌────────▼──────────┐
       │   eBPF programs    │
       │   network / file / │
       │   creds / exec     │
       └────────┬───────────┘
                │ kernel hooks
       ┌────────▼───────────┐
       │   AI agent (cgroup) │ ──── tries to connect to evil.com
       │                     │       → BLOCKED at ring 0
       └─────────────────────┘
```

## Quickstart

### Already on Ubuntu 24.04? Run it directly — no VM needed.

```bash
bash setup-vm.sh all          # deps + build + install + enable service
xdg-open http://127.0.0.1:9000/ui/
sudo agentctl run examples/demo-agent.yaml
```

### On macOS / Windows / a different Linux?

```bash
vagrant up        # Ubuntu 24.04 + kernel 6.8 + everything pre-built
vagrant ssh
open http://127.0.0.1:9000/ui/    # port-forwarded to the host
sudo agentctl run /home/vagrant/agentsandbox/examples/demo-agent.yaml
```

The first `vagrant up` (or first `setup-vm.sh all`) builds the eBPF
objects, builds `agentd`, installs the systemd unit, and starts it.
See `setup-vm.sh` for what gets installed and `decision.md` for *why*
it works the way it does.

## Manifest format

```yaml
name: my-agent
command: ["python3", "agent.py"]
mode: enforce        # or "audit" — audit-only emits events, never blocks
allowed_hosts:
  - api.openai.com:443
  - api.anthropic.com:443
allowed_paths:
  - /tmp/agent-workdir
allowed_bins:
  - /usr/bin/python3
forbidden_caps:
  - CAP_SYS_ADMIN
  - CAP_BPF
```

`agentctl run` creates a cgroup at `/sys/fs/cgroup/agentsandbox/<name>/`,
PUTs the policy to the daemon, binds the cgroup, then `exec`s the
command — so by the time your agent's first syscall hits the kernel,
the guardrails are already loaded and scoped to it.

## Layout

```
bpf/          eBPF C programs, one per pillar
daemon/       Go control-plane (agentd) — loads bpf, exposes API+SSE
gui/          Vanilla-JS web UI for editing policies & live events
cli/agentctl/ HTTP client + cgroup launcher
policies/    YAML guardrail policies loaded at boot
systemd/     unit file for the agentd service
iso/         placeholder for future bootable ISO build (decision D-008)
vendor/      Tetragon clone — read-only reference (decision D-006)
decision.md  architectural decision log
bug_report.md running list of known bugs / limits
```

## The four pillars

| Pillar | Hook(s) | Source | Default mode |
|---|---|---|---|
| Network observability | `lsm/socket_connect`, `tp/sys_enter_sendto` | `bpf/network.bpf.c` | enforce v4 connect, audit sendto (B-005) |
| Filename access | `lsm.s/file_open` (sleepable, uses `bpf_d_path`) | `bpf/file.bpf.c` | enforce, prefix match |
| Credential monitoring | `lsm/task_fix_setuid`, `task_fix_setgid`, `capset` | `bpf/creds.bpf.c` | enforce, configurable cap deny-list |
| Privileged execution | `tp/sched_process_exec`, `lsm/bprm_check_security` | `bpf/exec.bpf.c` | enforce binary allow-list |

See `decision.md#D-005` for the per-pillar split rationale.

## Requirements

- Ubuntu 24.04 (kernel 6.8+, BTF, BPF LSM enabled)
- cgroup v2 unified hierarchy
- `clang` ≥ 14, `libbpf-dev`, `bpftool`, Go 1.22

`setup-vm.sh` checks all of these and patches GRUB if BPF LSM is not
in the active LSM list.

## License

Apache 2.0 — see [LICENSE](LICENSE). The eBPF objects under `bpf/`
are GPL-2.0 (kernel ABI requirement). The vendored
`vendor/tetragon/` tree retains its dual BSD-2/GPL-2 license; we
do not link any Tetragon code into our binaries (decision D-006).
