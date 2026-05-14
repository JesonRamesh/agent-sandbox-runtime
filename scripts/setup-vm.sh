#!/usr/bin/env bash
# =============================================================================
# Agent Sandbox Runtime — VM setup script
#
# Run this once inside a fresh Linux VM (Lima, Vagrant/UTM, or any Ubuntu 24.04
# host) to install all build- and run-time dependencies.
#
# Usage:
#   bash scripts/setup-vm.sh
#
# What it does (idempotent — safe to re-run):
#   1.  Verifies kernel version (≥ 6.8 required for the LSM hooks we use).
#   2.  Installs apt packages: clang/llvm, libbpf-dev, linux-tools, jq, etc.
#   3.  Installs Go 1.23 if not present.
#   4.  Installs Node.js 20 if not present.
#   5.  Verifies BPF LSM is **runtime-active** (not just compiled-in) and patches
#       the bootloader's lsm= kernel parameter if needed. Cloud-image VMs hide
#       a `GRUB_CMDLINE_LINUX_DEFAULT` override in
#       /etc/default/grub.d/50-cloudimg-settings.cfg that silently clobbers
#       /etc/default/grub — handle that case explicitly.
#   6.  Creates /run/agent-sandbox so the daemon can bind its IPC socket.
#   7.  Prints a summary + REBOOT-IF-NEEDED banner.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo; printf "${BOLD}[ %s ]${NC} %s\n" "$1" "$2"; }
ok()   { printf "${GREEN}  ✔ %s${NC}\n" "$1"; }
warn() { printf "${YELLOW}  ⚠ %s${NC}\n" "$1"; }
fail() { printf "${RED}  ✘ %s${NC}\n" "$1"; exit 1; }

REBOOT_NEEDED=0

# -----------------------------------------------------------------------------
# 1. Kernel sanity
# -----------------------------------------------------------------------------
step "1/7" "Checking kernel version (need ≥ 6.8 for sleepable LSM + bpf_d_path)"
KERNEL=$(uname -r)
MAJOR=$(echo "$KERNEL" | cut -d. -f1)
MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$MAJOR" -gt 6 ] || { [ "$MAJOR" -eq 6 ] && [ "$MINOR" -ge 8 ]; }; then
  ok "Kernel $KERNEL"
else
  fail "Kernel $KERNEL is too old. Use Ubuntu 24.04 (kernel 6.8+) or newer."
fi

# -----------------------------------------------------------------------------
# 2. APT packages
# -----------------------------------------------------------------------------
step "2/7" "Installing system packages via apt"
sudo apt-get update -qq
sudo apt-get install -y -qq \
  git curl wget jq \
  build-essential make \
  python3 python3-pip python3-venv \
  clang llvm libbpf-dev \
  linux-tools-generic linux-tools-common "linux-tools-$(uname -r)" \
  linux-headers-generic \
  net-tools iproute2
ok "apt packages installed"

# -----------------------------------------------------------------------------
# 3. Go toolchain
# -----------------------------------------------------------------------------
step "3/7" "Installing Go 1.23 (required for the unified runtime module)"
GO_VERSION="1.23.4"
ARCH=$(dpkg --print-architecture) # amd64 or arm64
GO_BIN=/usr/local/go/bin/go
need_go=1
if [ -x "$GO_BIN" ]; then
  installed=$("$GO_BIN" version | awk '{print $3}' | sed 's/^go//')
  # crude semver check: require exactly the prefix we asked for
  if [ "${installed%.*}" = "${GO_VERSION%.*}" ] || [ "$installed" = "$GO_VERSION" ]; then
    need_go=0
    ok "Go $installed already installed at $GO_BIN"
  fi
fi
if [ "$need_go" -eq 1 ]; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
    | sudo tar -C /usr/local -xz
  ok "Go ${GO_VERSION} extracted to /usr/local/go"
fi
# Ensure /etc/profile.d/go.sh sets PATH for new shells
if ! grep -q "/usr/local/go/bin" /etc/profile.d/go.sh 2>/dev/null; then
  echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
  sudo chmod +x /etc/profile.d/go.sh
  ok "Added Go to /etc/profile.d/go.sh (re-login or source it)"
fi

# -----------------------------------------------------------------------------
# 4. Node.js (for the viewer)
# -----------------------------------------------------------------------------
step "4/7" "Installing Node.js 20 (viewer dashboard)"
if command -v node >/dev/null 2>&1 && [[ "$(node --version)" == v20* ]]; then
  ok "Node.js $(node --version) already installed"
else
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - 2>/dev/null
  sudo apt-get install -y -qq nodejs
  ok "Node.js $(node --version) installed"
fi

# -----------------------------------------------------------------------------
# 5. BPF LSM runtime activation (the trap that hides enforcement bugs)
# -----------------------------------------------------------------------------
step "5/7" "Verifying BPF LSM is runtime-active (lsm= boot parameter)"

# Detect WSL — the Microsoft kernel has no GRUB and the lsm= cmdline cannot
# be changed without building a custom kernel. Local mode (orchestrator, tool
# tracing, dashboard) works fully in WSL; kernel enforcement does not.
IS_WSL=0
if grep -qi "microsoft" /proc/version 2>/dev/null || [ -e /proc/sys/fs/binfmt_misc/WSLInterop ]; then
  IS_WSL=1
fi

ACTIVE_LSMS=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
if echo ",$ACTIVE_LSMS," | grep -q ',bpf,'; then
  ok "BPF LSM is active: $ACTIVE_LSMS"
elif [ "$IS_WSL" -eq 1 ]; then
  warn "Running inside WSL — the BPF LSM kernel parameter cannot be set via GRUB."
  warn "Kernel enforcement (eBPF policy, EPERM on denied syscalls) is unavailable."
  warn "Everything else works: orchestrator, tool tracing, multi-agent runs, dashboard."
  warn "For kernel enforcement, use a native Linux machine or a full Linux VM."
else
  warn "BPF LSM is NOT active (active LSMs: ${ACTIVE_LSMS:-unknown})"
  warn "Without 'bpf' in lsm=…, all of our LSM hooks load but never fire — "
  warn "every connect/file/exec policy decision silently allows."

  # Cloud-images (Lima ubuntu-lts, Multipass, EC2, etc.) ship a grub override
  # that clobbers GRUB_CMDLINE_LINUX_DEFAULT from /etc/default/grub. Patch the
  # right file: prefer the cloudimg override if it exists, else /etc/default/grub.
  GRUB_FILE="/etc/default/grub"
  if [ -f /etc/default/grub.d/50-cloudimg-settings.cfg ]; then
    GRUB_FILE="/etc/default/grub.d/50-cloudimg-settings.cfg"
  fi

  if grep -q 'lsm=' "$GRUB_FILE" && grep -q 'lsm=[^"]*\bbpf\b' "$GRUB_FILE"; then
    ok "$GRUB_FILE already has lsm=…,bpf — boot order may need a reboot to apply"
    REBOOT_NEEDED=1
  else
    warn "Patching $GRUB_FILE with lsm=lockdown,capability,landlock,yama,apparmor,bpf"
    sudo cp -n "$GRUB_FILE" "$GRUB_FILE.bak.$(date +%s)" || true
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE"; then
      # Replace the existing line atomically, preserving any other args.
      sudo sed -i -E \
        's|^GRUB_CMDLINE_LINUX_DEFAULT="([^"]*)"|GRUB_CMDLINE_LINUX_DEFAULT="\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf"|' \
        "$GRUB_FILE"
    else
      echo 'GRUB_CMDLINE_LINUX_DEFAULT="lsm=lockdown,capability,landlock,yama,apparmor,bpf"' \
        | sudo tee -a "$GRUB_FILE" >/dev/null
    fi
    sudo update-grub >/dev/null 2>&1
    ok "Patched $GRUB_FILE and ran update-grub"
    REBOOT_NEEDED=1
  fi
fi

# cgroup v2 sanity (process placement uses CLONE_INTO_CGROUP)
if mount | grep -q "cgroup2"; then
  ok "cgroup v2 mounted at /sys/fs/cgroup"
else
  warn "cgroup v2 is not mounted (the daemon needs the unified hierarchy)"
fi

# -----------------------------------------------------------------------------
# 6. Daemon socket directory
# -----------------------------------------------------------------------------
step "6/7" "Creating /run/agent-sandbox (where agentd binds its IPC socket)"
sudo mkdir -p /run/agent-sandbox
sudo chown "$USER":"$USER" /run/agent-sandbox
ok "/run/agent-sandbox ready"

# -----------------------------------------------------------------------------
# 7. Summary
# -----------------------------------------------------------------------------
step "7/7" "Summary"
echo "  Kernel  : $(uname -r)"
echo "  Go      : $($GO_BIN version 2>/dev/null || echo 'not on PATH yet — re-login or source /etc/profile.d/go.sh')"
echo "  Node    : $(node --version 2>/dev/null || echo 'not found')"
echo "  Python  : $(python3 --version 2>/dev/null || echo 'not found')"
echo "  bpftool : $(bpftool version 2>/dev/null | head -1 || echo 'not found')"
echo "  LSMs    : $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'unknown')"

echo
if [ "$REBOOT_NEEDED" -eq 1 ]; then
  printf "${YELLOW}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}\n"
  printf "${YELLOW}${BOLD}║  REBOOT REQUIRED                                              ║${NC}\n"
  printf "${YELLOW}${BOLD}║  The kernel cmdline was updated to enable BPF LSM.            ║${NC}\n"
  printf "${YELLOW}${BOLD}║                                                               ║${NC}\n"
  printf "${YELLOW}${BOLD}║  1. Reboot now:                                               ║${NC}\n"
  printf "${YELLOW}${BOLD}║       sudo reboot                                             ║${NC}\n"
  printf "${YELLOW}${BOLD}║                                                               ║${NC}\n"
  printf "${YELLOW}${BOLD}║  2. After reboot, verify BPF LSM is active:                   ║${NC}\n"
  printf "${YELLOW}${BOLD}║       cat /sys/kernel/security/lsm | grep bpf && echo OK      ║${NC}\n"
  printf "${YELLOW}${BOLD}║                                                               ║${NC}\n"
  printf "${YELLOW}${BOLD}║  3. Then build the runtime:                                   ║${NC}\n"
  printf "${YELLOW}${BOLD}║       make all                                                ║${NC}\n"
  printf "${YELLOW}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}\n"
else
  ok "Setup complete — you're ready to build and run the runtime."
fi
