#!/usr/bin/env bash
# =============================================================================
# setup-vagrant.sh — Vagrant → full-stack Agent Sandbox in one command
#
# Works on Intel Mac, Linux, and Windows (Git Bash or WSL).
# Apple Silicon Mac users should use setup-lima.sh instead.
#
# Takes you from a fresh checkout to kernel enforcement running:
#   check Vagrant + hypervisor → vagrant up → setup-vm.sh inside VM →
#   reboot VM if BPF LSM needed → make all → next-step guide
#
# Usage (from the repo root):
#   bash scripts/setup-vagrant.sh
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
fail() { printf "${RED}  ✘ %s${NC}\n" "$1" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The Vagrantfile syncs the repo here inside the VM (see Vagrantfile line 54).
VM_REPO="/home/vagrant/agentsandbox"

# ── 0. Windows guard ─────────────────────────────────────────────────────────
# On Windows, WSL 2 is the recommended path — simpler, no VirtualBox/Hyper-V
# conflict, and ports forward to your browser automatically.
#
#   wsl --install          (PowerShell as Administrator)
#   # then inside WSL:
#   bash scripts/setup-vm.sh && make all
#
# This script is kept for anyone who specifically wants VirtualBox, or for
# Intel Mac users who prefer Vagrant over Lima.

# ── 1. Platform ───────────────────────────────────────────────────────────────
step "1/5" "Checking platform and hypervisor"

IS_APPLE_SILICON=0
if [[ "$(uname -s)" == "Darwin" ]] && [[ "$(uname -m)" == "arm64" ]]; then
  IS_APPLE_SILICON=1
fi

if [[ "$IS_APPLE_SILICON" -eq 1 ]]; then
  warn "Apple Silicon detected. Lima is the recommended path:"
  warn "  bash scripts/setup-lima.sh"
  warn "Continuing with Vagrant/UTM — make sure you have 'vagrant plugin install vagrant-utm'."
fi

# Check Vagrant
if ! command -v vagrant >/dev/null 2>&1; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    fail "Vagrant not found. Install it with: brew install --cask vagrant"
  else
    fail "Vagrant not found. Download it from https://developer.hashicorp.com/vagrant/downloads"
  fi
fi
ok "Vagrant $(vagrant --version | awk '{print $2}')"

# Check hypervisor
if [[ "$IS_APPLE_SILICON" -eq 1 ]]; then
  if ! vagrant plugin list 2>/dev/null | grep -q "vagrant-utm"; then
    fail "vagrant-utm plugin not installed. Run: vagrant plugin install vagrant-utm"
  fi
  ok "vagrant-utm plugin present"
else
  if ! command -v VBoxManage >/dev/null 2>&1; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      fail "VirtualBox not found. Install it with: brew install --cask virtualbox"
    else
      fail "VirtualBox not found. Download it from https://www.virtualbox.org/wiki/Downloads"
    fi
  fi
  ok "VirtualBox $(VBoxManage --version)"
fi

# ── 2. Boot and provision the VM ─────────────────────────────────────────────
step "2/5" "Booting VM with 'vagrant up' (first run takes ~5 minutes)"
cd "$REPO_ROOT"
vagrant up
ok "VM is running"

# ── 3. Install deps + activate BPF LSM ───────────────────────────────────────
step "3/5" "Running setup-vm.sh inside the VM"
# Run as root because setup-vm.sh uses sudo internally; vagrant ssh already
# has passwordless sudo, but some commands need to run as the vagrant user.
vagrant ssh -c "bash $VM_REPO/scripts/setup-vm.sh" || true
ok "setup-vm.sh finished"

# ── 4. Reboot if BPF LSM needs activating ────────────────────────────────────
step "4/5" "Verifying BPF LSM is active"
BPF_ACTIVE=$(vagrant ssh -c "cat /sys/kernel/security/lsm 2>/dev/null || echo ''" 2>/dev/null | tr -d '\r')
if echo ",$BPF_ACTIVE," | grep -q ',bpf,'; then
  ok "BPF LSM is active: $BPF_ACTIVE"
else
  warn "BPF LSM not yet active (active LSMs: ${BPF_ACTIVE:-unknown})"
  warn "Rebooting the VM to apply the updated kernel parameter — this takes ~30 seconds"
  vagrant reload --no-provision
  BPF_ACTIVE=$(vagrant ssh -c "cat /sys/kernel/security/lsm 2>/dev/null || echo ''" 2>/dev/null | tr -d '\r')
  if echo ",$BPF_ACTIVE," | grep -q ',bpf,'; then
    ok "BPF LSM is active after reboot: $BPF_ACTIVE"
  else
    fail "BPF LSM still not active after reboot (LSMs: ${BPF_ACTIVE:-unknown}).\nInside the VM check: sudo cat /etc/default/grub.d/50-cloudimg-settings.cfg"
  fi
fi

# ── 5. Build ──────────────────────────────────────────────────────────────────
step "5/5" "Building daemon and eBPF programs (make all)"
vagrant ssh -c "export PATH=\$PATH:/usr/local/go/bin && cd $VM_REPO && make all"
ok "Build complete — bin/agentd, bin/agentctl, bpf/*.bpf.o are ready"

# ── Next steps ────────────────────────────────────────────────────────────────
echo
printf "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗\n${NC}"
printf "${GREEN}${BOLD}║  All done! Open 3 terminals and run:                         ║\n${NC}"
printf "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════════╣\n${NC}"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  In each terminal, first open a VM shell:                    ║\n${NC}"
printf "${GREEN}${BOLD}║    vagrant ssh                                               ║\n${NC}"
printf "${GREEN}${BOLD}║    cd %s                           ║\n${NC}" "$VM_REPO"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  Terminal 1 — start the daemon:                              ║\n${NC}"
printf "${GREEN}${BOLD}║    sudo ./bin/agentd -bpf-dir=./bpf \\                        ║\n${NC}"
printf "${GREEN}${BOLD}║      -socket=/run/agent-sandbox.sock -ws-addr=127.0.0.1:7443 ║\n${NC}"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  Terminal 2 — start the dashboard (optional):                ║\n${NC}"
printf "${GREEN}${BOLD}║    bash viewer/scripts/start-viewer.sh                       ║\n${NC}"
printf "${GREEN}${BOLD}║    → open http://127.0.0.1:8765 in your browser              ║\n${NC}"
printf "${GREEN}${BOLD}║      (Vagrant forwards port 8765 to your host automatically) ║\n${NC}"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  Terminal 3 — run the smoke test:                            ║\n${NC}"
printf "${GREEN}${BOLD}║    sudo bash examples/test-it.sh                             ║\n${NC}"
printf "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝\n${NC}"
echo
