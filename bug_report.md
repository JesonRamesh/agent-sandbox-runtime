# Bug Log

Running list of bugs, rough edges, and known limitations encountered
while building agent-sandbox-runtime. Newest at the top. Each entry:
**Component / Symptom / Root cause (if known) / Workaround / Status**.

For new bugs, copy the template at the bottom of the file.

---

## B-015 — Web UI unreachable from host: daemon bound to 127.0.0.1
**Component:** Daemon, VM provisioning
**Symptom:** `curl http://127.0.0.1:9000/api/healthz` from the host
returned exit 56 (`Recv failure: Connection reset by peer`), even
though the same call inside the VM returned `ok` and the systemd
service was active.
**Root cause:** VirtualBox NAT port-forwarding rewrites the
destination address to the guest's NAT interface (`10.0.2.15` by
default), not to loopback. A guest service bound to
`127.0.0.1:9000` is invisible to the NAT-side forwarder, so the
host's TCP attempt is rejected by the guest kernel.
**Workaround:** Systemd unit now passes `--listen=0.0.0.0:9000`.
Daemon binary's default is still `127.0.0.1` (safer for direct
host runs); only the VM unit overrides it.
**Status:** Resolved.

---

## B-014 — `#pragma unroll` exceeded clang's transform budget on nested loops
**Component:** eBPF (exec, file)
**Symptom:** `clang -target bpf` rejected `exec.bpf.c:21` and
similar lines with
`loop not unrolled: the optimizer was unable to perform the
requested transformation`. Specifically the outer loop in
`binary_allowed` (32 entries) wrapping `has_prefix` (256 chars)
asked clang to fully unroll 8192 ops.
**Root cause:** Cargo-culted `#pragma unroll` from older eBPF
patterns where the verifier required unrolled loops. Modern
verifiers (≥ kernel 5.3) accept bounded `for (i = 0; i < N; i++)`
loops natively as long as the bound is constant — so the pragma
isn't needed *and* it pushes clang past its instantiation limit
when the inner body is itself an unrolled loop.
**Workaround:** Removed `#pragma unroll` from all four outer
loops (`host_allowed`, `path_allowed`, `binary_allowed`,
`has_prefix`). Verifier accepts them; binaries are smaller too.
**Status:** Resolved.

---

## B-013 — `asb_bprm_check` blew the 512-byte BPF stack limit
**Component:** eBPF (exec)
**Symptom:** `clang` rejected `exec.bpf.c` with
`Looks like the BPF stack limit is exceeded. Please move large
on stack variables into BPF per-cpu array map.`
**Root cause:** I had a local `char filename[MAX_PATH]` (256 B)
*plus* the ringbuf-reserved struct on the stack (~330 B), plus
compiler temporaries. BPF programs get 512 bytes of stack total.
**Workaround:** Removed the local staging buffer. The kernel
filename is read directly into `evt->e.filename` — i.e. into the
ringbuf reservation, not the BPF stack — and the reservation is
`bpf_ringbuf_discard()`'d if the policy ends up allowing the
binary so we don't emit noise on the happy path.
**Status:** Resolved.

---

## B-012 — GRUB silently truncates kernel cmdline at `;` on bento box
**Component:** VM provisioning
**Symptom:** After `setup-vm.sh` patched
`GRUB_CMDLINE_LINUX_DEFAULT` to append `lsm=…,bpf`, ran
`update-grub`, and rebooted — `cat /sys/kernel/security/lsm` still
showed no `bpf`, even though `/boot/grub/grub.cfg` contained the
correct linux line with `lsm=…,bpf`.
**Root cause:** The bento `bento/ubuntu-24.04` box ships with
`GRUB_CMDLINE_LINUX_DEFAULT="autoinstall ds=nocloud-net;s=http://10.0.2.2:8648/ubuntu/"`
(autoinstall cruft from box creation). GRUB splits the kernel
cmdline at the literal `;`, so everything after — including any
flag we appended — never reaches the kernel. `/proc/cmdline`
showed only `autoinstall ds=nocloud-net`.
**Workaround:** Stop trying to edit the existing line. Instead
write a drop-in at `/etc/default/grub.d/99-agentsandbox.cfg` that
unconditionally re-defines the variable to a clean value
(`net.ifnames=0 biosdevname=0 lsm=…,bpf`). Ubuntu's `update-grub`
sources `/etc/default/grub.d/*.cfg` *after* the main file, so the
drop-in wins. Verified end-to-end inside the VM.
**Status:** Resolved.

---

## B-011 — `bash set -e` is suppressed inside functions called from an && chain
**Component:** VM provisioning
**Symptom:** `setup-vm.sh all` printed `✔ bpf/*.bpf.o built` immediately
after `make: *** [...] Error 1`. The clang compile failed but the
script kept going (build → install → systemctl), pretending each
step had succeeded.
**Root cause:** Bash spec: when a function (or compound command)
is part of an `&&` / `||` list, `set -e` is *suppressed for the
duration of that command*. The script had
`do_deps && do_build && do_install` so a make failure inside
`do_build` did not propagate out.
**Workaround:** Switched to sequential statements
(`do_deps; do_build; do_install`). Now any failure inside a
function aborts the whole script, as you'd expect from the
`set -euo pipefail` at the top.
**Status:** Resolved.

---

## B-010 — Go modules had no `go.sum`, fresh build aborted
**Component:** Daemon, CLI
**Symptom:** `go build` failed with `missing go.sum entry for
module providing package github.com/cilium/ebpf` (and four other
imports) on a fresh clone.
**Root cause:** I committed `go.mod` but never ran `go mod tidy`
locally, so `go.sum` (the integrity manifest) didn't exist. With
a missing `go.sum`, `go build` refuses to download dependencies in
non-`-mod=mod` mode by default since Go 1.16.
**Workaround:** Top-level Makefile now runs `go mod tidy` before
`go build` for both `daemon/` and `cli/agentctl/`. That will
fetch + checksum dependencies on first build and is a no-op
afterward.
**Status:** Resolved.

---

## B-009 — eBPF compile failed: `bpf_ntohs` undeclared
**Component:** eBPF (network)
**Symptom:** `clang -target bpf` rejected `network.bpf.c:54` —
`call to undeclared function 'bpf_ntohs'`.
**Root cause:** `bpf_ntohs` lives in `<bpf/bpf_endian.h>` (libbpf),
not in `bpf_helpers.h` or `bpf_core_read.h`. I forgot to include
that header in `bpf/common.h`. Tetragon's `bpf/lib/bpf_endian.h`
is its own copy of the same upstream file — easy to overlook.
**Workaround:** Added `#include <bpf/bpf_endian.h>` to
`bpf/common.h` so every pillar gets it transitively.
**Status:** Resolved.

---

## B-008 — `setup-vm.sh` patched grub for BPF LSM but kept going
**Component:** VM provisioning
**Symptom:** On a fresh `bento/ubuntu-24.04` VM, `bpf` is not in
`/sys/kernel/security/lsm` by default. The script correctly patched
`/etc/default/grub` and ran `update-grub`, but then continued to
build, install, and `systemctl enable --now agentsandbox.service`.
The service would fail at runtime because `link.AttachLSM` returns
`-ENOENT` until the kernel actually boots into the new cmdline.
**Root cause:** Treating "reboot required" as a warning rather than
a hard stop. Apt also brought in a newer kernel package during
`deps`, which compounds the issue — the running kernel and the
installed kernel diverge.
**Workaround:** Script now `exit 0`s after patching grub with a
clear "reboot and re-run" message. Build/install only happen on
runs where BPF LSM is already active.
**Status:** Resolved.

---

## B-007 — Vagrantfile inline provisioner duplicated setup-vm.sh and tried `apt-get install bpftool`
**Component:** VM provisioning
**Symptom:** `vagrant up` aborted with
`E: Package 'bpftool' has no installation candidate` on Ubuntu 24.04.
**Root cause:** The original Vagrantfile carried a hand-rolled
`apt-get install` block that ran *before* delegating to
`setup-vm.sh`. That block listed `bpftool` as a top-level package
— but on noble, bpftool is only shipped via `linux-tools-generic`
(or `linux-tools-$(uname -r)` when the version-matched package
exists; see B-001). `setup-vm.sh` already gets this right; the
duplicated block did not.
**Workaround:** Removed the duplicated `apt-get` block from the
Vagrantfile. The provisioner is now a one-liner that just calls
`bash setup-vm.sh all`, so there is one source of truth for what
gets installed and bug fixes propagate to host-direct runs too.
**Status:** Resolved.

---

## B-006 — `ubuntu/noble64` returns 404 on Vagrant Cloud
**Component:** VM provisioning
**Symptom:** `vagrant up` on a fresh checkout fails with
`The box 'ubuntu/noble64' could not be found ... 404`.
**Root cause:** Canonical stopped publishing official Ubuntu
images to Vagrant Cloud during 2024 (HashiCorp licensing change).
The Apple Silicon path always used `bento/ubuntu-24.04-arm64`; the
Intel/AMD path was the only one still pointing at the dead URL.
**Workaround:** Switched to `bento/ubuntu-24.04` (kernel 6.8,
unprivileged-userns + BPF LSM enabled, drop-in replacement). Also,
on a Linux host you can skip Vagrant entirely and run
`bash setup-vm.sh all` directly — no VM needed.
**Status:** Resolved — Vagrantfile updated.

---

## B-005 — `sendto` tracepoint cannot deny, only observe
**Component:** eBPF (network)
**Symptom:** `bpf/network.bpf.c` can record outbound UDP via
`tp/syscalls/sys_enter_sendto`, but returning non-zero from a
tracepoint does not block the syscall — the packet still goes out.
**Root cause:** Tracepoint programs are observe-only by design.
There is no LSM hook for `sendto` payload inspection.
**Workaround:** When a tracepoint event matches a deny rule, the
daemon `SIGKILL`s the offending PID. This is racy: one packet may
escape before the signal is delivered. See decision D-004.
**Status:** Accepted limitation, documented in policy schema.

---

## B-004 — Path read from `dentry` is truncated at MAX_PATH=256
**Component:** eBPF (file)
**Symptom:** Pathnames longer than 256 bytes are silently truncated
when emitted to userspace, producing false-negatives against
`allowed_paths` rules with long prefixes.
**Root cause:** Stack-allocated buffer in `bpf/file.bpf.c` capped
at 256 to stay under the BPF stack limit (512 B). Walking the full
dentry chain inside the verifier's loop budget is the canonical
hard problem.
**Workaround:** Daemon-side: reject any policy `allowed_paths`
entry > 240 chars at load time with a clear error. Long-term:
emit dentry chain in chunks via per-cpu scratch map and reassemble
in userspace (see Tetragon's `prepend_name` for reference).
**Status:** Open — tracked.

---

## B-003 — `bpf_d_path` requires kernel ≥ 5.10 *and* a sleepable LSM context
**Component:** eBPF (file)
**Symptom:** Build fails or program rejected by verifier on Ubuntu
22.04 hosts when targeting `lsm/file_open` without `SEC("lsm.s/...")`
(sleepable variant).
**Root cause:** `bpf_d_path` is only callable from sleepable
programs. Non-sleepable LSM programs must walk the dentry manually.
**Workaround:** Use `SEC("lsm.s/file_open")` (sleepable). Ubuntu
24.04 (kernel 6.8) supports this; earlier kernels are unsupported
per decision D-001.
**Status:** Resolved by minimum-kernel decision.

---

## B-002 — `ip link` inside Vagrant VM sometimes shows no eth0 on first boot
**Component:** VM provisioning
**Symptom:** Occasional first-boot failures of `setup-vm.sh` at the
`apt-get update` step because DNS hasn't come up.
**Root cause:** systemd-networkd race with `cloud-init` on the
bento/ubuntu-24.04 base box.
**Workaround:** `setup-vm.sh` retries `apt-get update` up to 5x
with 3-second backoff (`for i in 1..5; do sudo apt-get update -qq
&& break; sleep 3; done`). Verified: end-to-end Vagrant boot on
2026-04-26 succeeded on the first attempt without retries kicking
in, but the loop is there as insurance.
**Status:** Mitigated.

---

## B-001 — `linux-tools-$(uname -r)` package missing on bento box
**Component:** VM provisioning
**Symptom:** `setup-vm.sh` step 2 fails with
`E: Unable to locate package linux-tools-6.8.0-31-generic`.
**Root cause:** The bento base box ships a kernel whose matching
`linux-tools-<version>` package isn't in the default Ubuntu repos
yet — there's a lag between kernel releases and tooling packages
landing.
**Workaround:** Fall back to `linux-tools-generic`, which provides
a `bpftool` that works for our needs even if it's not exactly
version-matched.
**Status:** Mitigated in `setup-vm.sh`.

---

## Template

```
## B-XXX — <one-line summary>
**Component:** <eBPF (pillar) / Daemon / GUI / CLI / VM provisioning>
**Symptom:** <what the user sees>
**Root cause:** <why it happens, or "unknown — investigating">
**Workaround:** <what to do until fixed; "none" if no workaround>
**Status:** <Open / Mitigated / Resolved / Won't fix>
```
