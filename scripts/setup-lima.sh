#!/usr/bin/env bash
# =============================================================================
# setup-lima.sh — Mac → full-stack Agent Sandbox in one command
#
# Takes you from a fresh Mac checkout to kernel enforcement running:
#   install Lima (if needed) → boot Ubuntu VM → install deps →
#   reboot VM if BPF LSM needed → make all → print next-step guide
#
# Usage (run from the repo root on macOS):
#   bash scripts/setup-lima.sh
#
# Requires: macOS, Homebrew (https://brew.sh)
# The repo must be under your home directory (Lima mounts $HOME inside the VM).
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
VM_NAME="agentsandbox"

# ── 1. Platform ───────────────────────────────────────────────────────────────
step "1/6" "Checking platform"
if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "This script is for macOS only. On Linux run 'bash scripts/setup-vm.sh' then 'make all' directly."
fi
ok "macOS $(sw_vers -productVersion)"

# Warn if the repo is not under $HOME (Lima only mounts $HOME by default).
if [[ "$REPO_ROOT" != "$HOME"* ]]; then
  warn "Repo is outside \$HOME ($REPO_ROOT). Lima may not see it inside the VM."
  warn "Move the repo under your home directory and re-run, or add a custom Lima mount."
  exit 1
fi

# ── 2. Lima ───────────────────────────────────────────────────────────────────
step "2/6" "Checking Lima"
if command -v limactl >/dev/null 2>&1; then
  ok "Lima $(limactl --version 2>/dev/null | awk '{print $NF}') already installed"
else
  warn "Lima not found — installing via Homebrew"
  if ! command -v brew >/dev/null 2>&1; then
    fail "Homebrew is required to install Lima. Install it from https://brew.sh then re-run this script."
  fi
  brew install lima
  ok "Lima $(limactl --version 2>/dev/null | awk '{print $NF}') installed"
fi

# ── 3. VM ─────────────────────────────────────────────────────────────────────
step "3/6" "Creating or resuming Lima VM '$VM_NAME'"
if limactl list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$VM_NAME"; then
  VM_STATUS=$(limactl list 2>/dev/null | awk -v name="$VM_NAME" '$1==name{print $2}')
  if [[ "$VM_STATUS" == "Running" ]]; then
    ok "VM '$VM_NAME' is already running"
  else
    warn "VM '$VM_NAME' exists but is stopped — starting it"
    limactl start "$VM_NAME"
    ok "VM '$VM_NAME' started"
  fi
else
  warn "VM '$VM_NAME' not found — creating it (this takes ~2 minutes on first run)"
  limactl start \
    --name="$VM_NAME" \
    --cpus=4 --memory=4 --disk=30 \
    --mount-writable \
    template:ubuntu-lts
  ok "VM '$VM_NAME' created and running"
fi

# ── 4. Dependencies inside the VM ─────────────────────────────────────────────
step "4/6" "Running setup-vm.sh inside the VM"
# Lima mounts $HOME at the same path inside the VM, so REPO_ROOT is reachable.
limactl shell "$VM_NAME" bash "$REPO_ROOT/scripts/setup-vm.sh" || true
ok "setup-vm.sh finished"

# ── 5. Reboot VM if BPF LSM needs activating ──────────────────────────────────
step "5/6" "Verifying BPF LSM is active"
BPF_ACTIVE=$(limactl shell "$VM_NAME" cat /sys/kernel/security/lsm 2>/dev/null || echo "")
if echo ",$BPF_ACTIVE," | grep -q ',bpf,'; then
  ok "BPF LSM is active: $BPF_ACTIVE"
else
  warn "BPF LSM not yet active (active LSMs: ${BPF_ACTIVE:-unknown})"
  warn "Rebooting the VM to apply the updated kernel parameter — this takes ~30 seconds"
  limactl stop "$VM_NAME"
  limactl start "$VM_NAME"
  BPF_ACTIVE=$(limactl shell "$VM_NAME" cat /sys/kernel/security/lsm 2>/dev/null || echo "")
  if echo ",$BPF_ACTIVE," | grep -q ',bpf,'; then
    ok "BPF LSM is active after reboot: $BPF_ACTIVE"
  else
    fail "BPF LSM is still not active after reboot (LSMs: ${BPF_ACTIVE:-unknown}).\nInside the VM check: sudo cat /etc/default/grub.d/50-cloudimg-settings.cfg"
  fi
fi

# ── 6. Build ───────────────────────────────────────────────────────────────────
step "6/6" "Building daemon and eBPF programs (make all)"
limactl shell "$VM_NAME" bash -c "
  export PATH=\$PATH:/usr/local/go/bin
  cd '$REPO_ROOT'
  make all
"
ok "Build complete — bin/agentd, bin/agentctl, bpf/*.bpf.o are ready"

# ── Next steps ─────────────────────────────────────────────────────────────────
echo
printf "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗\n${NC}"
printf "${GREEN}${BOLD}║  All done! Open 3 terminals and run:                         ║\n${NC}"
printf "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════════╣\n${NC}"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  In each terminal, first open a VM shell:                    ║\n${NC}"
printf "${GREEN}${BOLD}║    limactl shell agentsandbox                                ║\n${NC}"
printf "${GREEN}${BOLD}║    cd %s\n${NC}" "$REPO_ROOT"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  Terminal 1 — start the daemon:                              ║\n${NC}"
printf "${GREEN}${BOLD}║    sudo ./bin/agentd -bpf-dir=./bpf \\                        ║\n${NC}"
printf "${GREEN}${BOLD}║      -socket=/run/agent-sandbox.sock -ws-addr=127.0.0.1:7443 ║\n${NC}"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  Terminal 2 — start the dashboard (optional):                ║\n${NC}"
printf "${GREEN}${BOLD}║    bash viewer/scripts/start-viewer.sh                       ║\n${NC}"
printf "${GREEN}${BOLD}║    → open http://127.0.0.1:8765 in your browser              ║\n${NC}"
printf "${GREEN}${BOLD}║                                                              ║\n${NC}"
printf "${GREEN}${BOLD}║  Terminal 3 — run the smoke test:                            ║\n${NC}"
printf "${GREEN}${BOLD}║    sudo bash examples/test-it.sh                             ║\n${NC}"
printf "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝\n${NC}"
echo
