# P4 Engineering Handoff

Remaining work to make the project genuinely usable. In priority order.
Not demos — real bugs and gaps a developer will hit.

---

## 1. Codespaces devcontainer does not support kernel enforcement (CRITICAL)

**The problem:** The README (as of the last P4 session) tells Windows users to use
GitHub Codespaces for full kernel enforcement. But `.devcontainer/devcontainer.json`
uses `python:3.11-bullseye` (Debian 11, kernel ~5.10) and explicitly sets
`AGENT_SANDBOX_LOCAL_MODE=1`. The post-create script says:

```
[devcontainer] Ready. Running in LOCAL MODE (no kernel enforcement).
```

So we are sending Windows users to Codespaces for kernel enforcement, and
Codespaces gives them local mode. This is misleading.

**What to investigate:**
- Does GitHub Codespaces expose a machine type with kernel 6.8+ and BPF LSM?
  (Codespaces "large" machines run on Azure VMs — kernel version varies)
- Can the devcontainer be changed to a Ubuntu 24.04 base image and have
  `setup-vm.sh` run as part of `postCreateCommand`?

**Two valid resolutions:**
- A: Fix the devcontainer to actually support enforcement (change base image,
  run `setup-vm.sh`, verify BPF LSM is active after container creation)
- B: Revert the README claim — tell Windows users Codespaces gives local mode
  only, and that full enforcement requires a cloud Linux VM (EC2, Azure, etc.)

**Files:**
- `.devcontainer/devcontainer.json`
- `.devcontainer/post-create.sh`
- `README.md` (Windows section)

---

## 2. `allowed_hosts` port-suffix causes false-positive warnings

**The problem:** `missing_provider_hosts()` in `manifest.py` extracts a bare
hostname from the provider's base URL (e.g., `api.anthropic.com`) and checks
whether it appears in `allowed_hosts`. But the README's own examples show
entries with port suffixes:

```yaml
allowed_hosts:
  - api.anthropic.com:443
```

`"api.anthropic.com" in ["api.anthropic.com:443"]` is `False` — so the warning
fires even though the host is correctly configured. A developer who copies the
README example exactly will see a spurious warning on every agent start.

**The fix:** In `missing_provider_hosts()`, strip the port from each
`allowed_hosts` entry before comparing:

```python
allowed_bare = {h.split(":")[0] for h in self.allowed_hosts}
if host in allowed_bare:
    return []
```

Also update the tests in `test_orchestrator.py` to cover the `:443` case.

**Files:**
- `orchestrator/orchestrator/manifest.py` — `missing_provider_hosts()`
- `orchestrator/tests/test_orchestrator.py` — add `:443` test cases

---

## 3. `agentctl validate` does not check provider hosts

**The problem:** `orchestrator/orchestrator/cli.py` has a `validate` subcommand
that loads and schema-checks every manifest in a scenario. It does not call
`missing_provider_hosts()`, so a developer who runs `agentctl validate` before
deploying gets no warning about a provider host missing from `allowed_hosts`.
They only see the warning at runtime when `AgentProcess.start()` is called.

**The fix:** In `_validate_referenced_manifests()` (cli.py ~line 235), after
loading each manifest call `manifest.missing_provider_hosts()` and add any
findings to the validate output — as a warning, not a hard error, since the
manifest is still structurally valid.

**Files:**
- `orchestrator/orchestrator/cli.py` — `_validate_referenced_manifests()`
- `orchestrator/tests/test_orchestrator.py` — test that validate output
  includes the provider-host warning

---

## 4. Vagrantfile provisions Go 1.22, `setup-vm.sh` installs Go 1.23

**The problem:** `Vagrantfile` (line 88) installs Go 1.22.2 via its inline
provisioner. `scripts/setup-vm.sh` (step 3) installs Go 1.23.4. After
`scripts/setup-vagrant.sh` runs, the VM has both versions; whichever appears
first on `PATH` wins. If 1.22 wins, `make all` may build against the wrong
version and produce subtle incompatibilities.

**The fix:** Either pin the Vagrantfile to Go 1.23.4 to match `setup-vm.sh`,
or remove the Go install from the Vagrantfile entirely and let `setup-vm.sh`
own it (the Vagrantfile's inline provisioner is redundant now that
`setup-vagrant.sh` runs `setup-vm.sh` as a second pass anyway).

**Files:**
- `Vagrantfile` — Go version in inline provisioner (line ~88)

---

## 5. No automated reboot for native Linux users

**The problem:** `setup-lima.sh` and `setup-vagrant.sh` both handle the
"REBOOT REQUIRED" case automatically (they stop and restart the VM). But a
developer on a native Linux machine (or in Codespaces, if that path is fixed)
who runs `bash scripts/setup-vm.sh` directly still sees the yellow banner and
has to manually reboot, then re-run a verification step. There is no guidance
on what to run after the reboot to confirm BPF LSM is active.

**The fix:** At the end of `setup-vm.sh`, when `REBOOT_NEEDED=1`, print a
one-liner the developer can copy-paste to verify after reboot:

```
After rebooting, run to verify:
  cat /sys/kernel/security/lsm | grep bpf && echo OK
Then run: make all
```

This is a docs/UX fix, not a code fix.

**Files:**
- `scripts/setup-vm.sh` — summary block at the bottom

---

## Progress tracker

| # | Issue | Priority | Status |
|---|-------|----------|--------|
| 1 | Codespaces devcontainer — local mode only, README claim wrong | Critical | 🔲 |
| 2 | `allowed_hosts` `:443` suffix causes false-positive warnings | High | 🔲 |
| 3 | `agentctl validate` doesn't check provider hosts | Medium | 🔲 |
| 4 | Vagrantfile / setup-vm.sh Go version drift | Low | 🔲 |
| 5 | No post-reboot guidance for native Linux users | Low | 🔲 |
