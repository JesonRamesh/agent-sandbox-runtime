# Architectural Decision Log

A running log of design choices made for the agent-sandbox-runtime
("guardrailed Ubuntu") project. New entries go at the top. Each entry
follows: **Decision / Why / Alternatives considered / Owner / Date**.

---

## D-011 — VM unit binds daemon to `0.0.0.0`; binary default stays loopback
**Decision:** The `agentd` binary defaults `--listen` to
`127.0.0.1:9000`. The systemd unit shipped under `systemd/` (used
inside the Vagrant VM) overrides this to `--listen=0.0.0.0:9000`.
**Why:** VirtualBox's NAT port-forwarding cannot reach a service
bound to the guest's loopback (see B-015). For a single-tenant
VM that's fine; for a host-direct install on a developer's
machine, defaulting to loopback is the safer choice.
**Alternatives considered:** Always bind to `0.0.0.0` — rejected,
exposes the daemon's policy-mutation API to anyone on the host's
network. Run an SSH tunnel from host to VM instead — works but
adds friction every session.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-010 — Activate BPF LSM via a `/etc/default/grub.d/` drop-in
**Decision:** When the kernel cmdline lacks `bpf` in `lsm=`,
`setup-vm.sh` installs `/etc/default/grub.d/99-agentsandbox.cfg`
that re-defines `GRUB_CMDLINE_LINUX_DEFAULT` to a known-clean
value (`net.ifnames=0 biosdevname=0 lsm=lockdown,yama,integrity,apparmor,bpf`).
It does **not** edit `/etc/default/grub` in place.
**Why:** The bento `bento/ubuntu-24.04` box ships an
autoinstall-cruft cmdline containing a literal `;` (see B-012).
GRUB splits the kernel cmdline at `;`, silently truncating
anything we appended. A drop-in is sourced after the main file by
`update-grub`, so a clean override wins regardless of what's in
the base file.
**Alternatives considered:** sed-patching the existing line —
brittle; we tried it first and it failed because of the `;`.
Forcing users to manually edit grub — friction we can avoid.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-009 — `agentctl` is a thin HTTP client, not a privileged binary
**Decision:** The CLI talks to the daemon over the local HTTP API on
`127.0.0.1:9000`. It does not load eBPF, open ringbuffers, or touch
`/sys/fs/bpf` directly.
**Why:** Keeps the privileged surface in one place (the daemon),
makes the CLI trivially portable, and means the same API powers the
web GUI and the CLI.
**Alternatives considered:** A setuid `agentctl` that loads programs
itself — rejected because it doubles the attack surface and forces
two copies of the policy logic.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-008 — Distribution target is a Vagrant box first, ISO second
**Decision:** Ship the project as a Vagrant-provisioned Ubuntu 24.04
VM in v0. A bootable ISO via `live-build` is a v1 stretch goal and
scaffolded under `iso/` but not built in CI.
**Why:** `vagrant up` already gives users a reproducible Ubuntu VM
that boots like a real OS. Building/signing an ISO is weeks of CI
infra work that adds little to the core thesis (kernel-level
guardrails). We can promote to ISO once the runtime is stable.
**Alternatives considered:** Building a custom ISO from day one —
rejected as out of scope. Docker image only — rejected because eBPF
LSM hooks need a real kernel and unrestricted capabilities.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-007 — GUI is a local web app served by the daemon
**Decision:** The "guardrail customization GUI" is a static SPA
(HTML + vanilla JS, no build step) served by the daemon at
`http://127.0.0.1:9000/ui/`. No GTK, no Electron.
**Why:** Confirmed with user. Web UI is portable across desktop
environments, works headlessly over SSH port-forward, and avoids
pulling GTK/Qt into the VM image. Vanilla JS (no React/Vite) keeps
the whole UI under ~500 lines and removes a Node toolchain from the
runtime image.
**Alternatives considered:** GTK desktop app (matches "real OS"
feel but ~10x the code and a hard dependency on the desktop session
running); Electron (huge image bloat); React + Vite (build
toolchain in the runtime path).
**Owner:** runtime
**Date:** 2026-04-26

---

## D-006 — eBPF programs are written from scratch, not vendored
**Decision:** Author our own eBPF C programs under `bpf/`, organized
by guardrail pillar (network, file, creds, exec). Tetragon is cloned
into `vendor/tetragon/` and used as a reference for hook points,
struct field reads, and event encoding — but no Tetragon `.c` is
compiled into our binaries.
**Why:** Confirmed with user. Writing our own programs makes them
small (~150 lines each vs Tetragon's 400+), easy to audit, and
trivially customizable from the policy YAML. Tetragon's programs
are coupled to its `vmlinux.h`, `api.h`, `bpf_event.h`, rate
limiters, mbset, ktime helpers, and a TracingPolicy compiler we
don't need.
**Alternatives considered:** Vendor and link Tetragon's BPF objects
directly — rejected: faster to ship but we inherit a generic-kprobe
runtime designed for arbitrary user-supplied policies, which is
more surface than we need.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-005 — Four guardrail pillars, one eBPF object per pillar
**Decision:** Ship four independent eBPF objects:
| Pillar | Hooks | Programs |
|---|---|---|
| Network observability | `lsm/socket_connect`, `tp/syscalls/sys_enter_sendto` | `bpf/network.bpf.c` |
| File / filename access | `lsm.s/file_open` (sleepable, calls `bpf_d_path`) | `bpf/file.bpf.c` |
| Credential monitoring | `lsm/task_fix_setuid`, `lsm/task_fix_setgid`, `lsm/capset` | `bpf/creds.bpf.c` |
| Privileged execution | `tp/sched/sched_process_exec`, `lsm/bprm_check_security` | `bpf/exec.bpf.c` |
**Why:** Mirrors the four use cases the user named. One object per
pillar means each can be loaded/unloaded independently from the GUI
toggles, and a verifier failure in one pillar does not take down
the others.
**Alternatives considered:** A single monolithic `agentsandbox.bpf.o`
— rejected because every config change would require reattaching
all programs. Per-syscall objects (~20 of them) — rejected as
over-decomposed.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-004 — Enforcement is *observe-and-deny*, driven by BPF LSM hooks
**Decision:** Where a BPF LSM hook exists, use it and return a
non-zero error code to deny. Where no LSM hook exists (e.g.
`sendto` payload inspection), use a tracepoint and emit an event;
the daemon may then send a signal (`SIGKILL`) to the offending PID.
**Why:** LSM hooks are the only kernel-supported way to *block*
syscalls from eBPF without resorting to `bpf_send_signal`-after-
the-fact. Tracepoints are observe-only but are guaranteed stable
ABI. Mixing them lets us be authoritative on the four pillars
without losing visibility on syscalls without LSM coverage.
**Alternatives considered:** kprobe-based override via
`bpf_override_return` — rejected because it needs
`CONFIG_BPF_KPROBE_OVERRIDE` and is fragile across kernel versions.
seccomp-bpf — rejected because it can't read pathnames or socket
addresses, only syscall numbers and register values.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-003 — Policy schema is YAML, hot-reloadable, scoped by cgroup
**Decision:** Policies are YAML documents listing `allowed_hosts`,
`allowed_paths`, `forbidden_caps`, and `allowed_binaries` per agent.
Each agent runs in its own cgroup v2 directory under
`/sys/fs/cgroup/agentsandbox/<agent-id>/`. eBPF programs read a
`cgroup_id -> policy_id` hash map and a `policy_id -> ruleset`
array map; the daemon updates these maps on policy change without
reloading the programs.
**Why:** Cgroup-scoped policy is how every modern container
runtime does it (Docker, k8s, systemd). Hot-reload via map updates
avoids reattaching LSM hooks (which is expensive and briefly leaves
the system unprotected).
**Alternatives considered:** PID-based scoping — rejected, fragile
across fork/exec. Namespace-based scoping — works but less
expressive than cgroups for nested process trees.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-002 — Daemon is Go, eBPF loader is `cilium/ebpf`
**Decision:** The control-plane daemon is a single Go binary
(`agentd`) using `github.com/cilium/ebpf` for object loading and
map manipulation. Events stream from kernel via `BPF_MAP_TYPE_RINGBUF`
into the daemon, then out to the GUI via Server-Sent Events (SSE).
**Why:** `cilium/ebpf` is the most mature pure-Go BPF library, has
no libbpf C dependency at runtime, and is what Tetragon itself uses.
Go is already specified in the existing Vagrantfile / setup-vm.sh.
**Alternatives considered:** `libbpfgo` (cgo wrapper around libbpf)
— rejected, cgo cross-compilation is painful. Rust + Aya — viable
but the team toolchain is already Go.
**Owner:** runtime
**Date:** 2026-04-26

---

## D-001 — Target Ubuntu 24.04 (kernel 6.8) with BPF LSM
**Decision:** Ubuntu 24.04 LTS is the only supported host. Required
kernel features: `CONFIG_BPF_LSM=y`, cgroup v2 unified hierarchy,
ringbuf support (5.8+), BTF in `/sys/kernel/btf/vmlinux`.
**Why:** Stock 24.04 ships with all of the above enabled. BPF LSM
needs to be added to `/etc/default/grub` via
`lsm=...,bpf` on some kernels — `setup-vm.sh` does this if missing.
**Alternatives considered:** Debian 12 (kernel 6.1, BPF LSM not
default-enabled); RHEL 9 (BTF lags); Alpine (musl + missing BTF).
**Owner:** runtime
**Date:** 2026-04-26
