# Threat Model

This document describes what the agent-sandbox runtime defends
against, what it does *not* defend against, and the assumptions an
operator must accept for the defence to hold.

## In scope

The system's primary purpose is to make **prompt injection of an LLM
agent unable to cause unauthorised side effects on the host**. The
sandbox is the trust boundary. We assume the agent's reasoning can be
hijacked at any time; we do not assume it cannot.

Concretely we protect against:

- **Outbound network exfiltration.** A hijacked agent attempts to
  `connect()` to an attacker-controlled host. Our `lsm/socket_connect`
  hook denies any connection whose destination IP+port doesn't match
  `allowed_hosts`.
- **Sensitive file read/write.** A hijacked agent attempts to open a
  file outside its working set (`/etc/shadow`, `~/.aws/credentials`,
  another agent's workdir). `lsm.s/file_open` denies anything outside
  `allowed_paths`.
- **Privilege escalation.** A hijacked agent tries to `setuid(0)`,
  `capset(CAP_BPF)`, etc. The credentials hooks reject any change that
  would grant the agent a capability listed in `forbidden_caps`.
- **Lateral exec.** A hijacked agent tries to `execve("/bin/sh")` to
  drop into an interactive shell. `lsm/bprm_check_security` denies if
  the binary's path doesn't match `allowed_bins`.
- **Sandbox escape via the BPF or cgroup machinery.** The daemon holds
  `CAP_BPF` and `CAP_SYS_ADMIN`; the agent is launched without them.
  Our shared maps are pinned with mode 0600 owned by the daemon user.
  An agent without `CAP_BPF` cannot read or modify them.

## Not in scope (yet)

These are real attacks the runtime does **not** currently prevent.
Operators should layer additional controls if the threat applies.

- **Kernel zero-days.** A bug in the LSM dispatcher, in cgroup, or in
  eBPF itself could let a sufficiently sophisticated attacker bypass
  hooks. We mitigate by minimising attack surface (only six LSM
  hooks, no custom kernel module), but we do not eliminate the risk.
  Keep the kernel patched.
- **IPv6.** `network.bpf.c` only handles AF_INET (IPv4). IPv6
  connections currently fall through to allow. v0.2 will add v6.
- **DNS exfiltration.** The agent can encode data in DNS queries to a
  resolver it's allowed to talk to. `allowed_hosts` accepts hostnames
  but resolves them at policy-compile time; the resolver itself is a
  legitimate connection. Defence: limit `allowed_hosts` to *IP*
  literals, not names, when paranoid.
- **Side channels.** Timing, cache, or filesystem-metadata side
  channels between the agent and other processes on the same host.
  Out of scope; this is the kernel's job and we do not improve on it.
- **A misconfigured manifest.** If you allow the agent to talk to a
  proxy that itself talks to the open internet, you've allowed the
  open internet. The runtime cannot distinguish "your CDN" from "an
  attacker's HTTP server" — they're both just `connect()` calls.
- **Confidentiality of the LLM's own context.** An attacker who
  reads the agent's stdout (e.g. via the orchestrator's logs) sees
  the model's reasoning, including any secrets that leaked into
  context. We protect *actions*, not *thought*.
- **Compromise of the daemon process itself.** The daemon is the
  trusted user-space root. If it's compromised, all bets are off.
  Keep its install path immutable, run it as a dedicated user, and
  audit its dependencies.

## Operator-side assumptions

For the protection to hold:

1. The daemon is started **before** any agent. There is no path to
   apply policy retroactively; an unsandboxed agent that runs before
   the daemon launches does so without any policy.
2. The kernel boots with `bpf` in `lsm=`. `setup-vm.sh` patches GRUB
   if needed and prints a `REBOOT REQUIRED` banner; ignoring it
   leaves enforcement silently disabled.
3. The agent process is launched **only** through `RunAgent` (CLI
   `agentctl run`, or the orchestrator's daemon mode). Anything the
   operator launches outside the daemon — a regular `python3` shell
   — is unsandboxed.
4. Manifests are reviewed before being submitted. The runtime
   enforces what the manifest says; if a human approves an
   over-broad manifest, the runtime will faithfully execute it.
5. The daemon's binary, the BPF objects, and the systemd unit are on
   read-only filesystem partitions or otherwise tamper-resistant.
   `deploy/install.sh` puts them under `/usr/local/bin` and
   `/usr/lib/agent-sandbox` with mode 0755 owned by root.

## What we record

Every kernel-level decision (allow, deny, audit) emits a ringbuf
event with: timestamp, pid/tgid/uid/gid, cgroup_id, agent_id (via
the daemon's enrichment), comm, the action-specific payload (dest
IP+port, file path, etc.), and the verdict.

Events are written to:

1. The daemon's text log (slog handler — stderr by default, JSON
   structured on `--log-json`).
2. A per-agent JSON log file at `/var/log/agent-sandbox/<agent_id>.log`,
   one event per line. Rotated by the daemon at 10 MB.
3. The localhost WebSocket at `:7443/events` for live consumers.
4. A per-agent fanout channel for `StreamEvents` IPC subscribers.

A SIEM that can tail JSON files (Splunk, Loki, Vector, Fluentd) gets
full structured access to every decision the kernel makes about every
agent.

## Failure modes

- **BPF load fails at startup.** Daemon refuses to come up. No agent
  can be launched. This is the "fail closed" path: if we can't
  enforce, we don't pretend to.
- **A `RunAgent` request hits the policy slot limit (`MaxPolicies`,
  currently 32).** Daemon returns `BPF_LOAD_FAILED` and refuses to
  spawn. Stop a finished agent first.
- **Ringbuf reader cannot keep up.** Events are dropped at the
  kernel side; we log a counter of drops. Verdict enforcement is
  unaffected — only the audit trail thins.
- **Daemon crashes.** The agents it spawned remain in their cgroups
  with their BPF policies attached. They continue to be enforced
  until they exit. The next daemon start will reconcile and either
  re-attach or kill orphaned agents per `--keep-crashed`.

## Reporting

If you find a security issue, please email security@agent-sandbox.dev
(planned) or open a private GitHub Security Advisory. Please *do not*
file a public issue.
