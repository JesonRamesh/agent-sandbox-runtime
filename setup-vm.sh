#!/usr/bin/env bash
# =============================================================
# Agent Sandbox Runtime — VM setup script
# Run this once inside the Lima VM to install all dependencies.
#
# Usage:
#   bash setup-vm.sh
# =============================================================

set -euo pipefail
# set -e  → stop immediately if any command fails
# set -u  → stop if you use an undefined variable
# set -o pipefail → stop if any command inside a pipe fails

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No colour

ok()   { echo -e "${GREEN}  ✔ $1${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $1${NC}"; }
fail() { echo -e "${RED}  ✘ $1${NC}"; exit 1; }

echo ""
echo "================================================"
echo " Agent Sandbox Runtime — environment setup"
echo " $(date)"
echo "================================================"
echo ""

# ── 1. Basic sanity checks ───────────────────────────────────
echo "[ 1/6 ] Checking kernel version..."
KERNEL=$(uname -r)
MAJOR=$(echo "$KERNEL" | cut -d. -f1)
MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$MAJOR" -gt 6 ] || ([ "$MAJOR" -eq 6 ] && [ "$MINOR" -ge 8 ]); then
  ok "Kernel $KERNEL (6.8+ required)"
else
  fail "Kernel $KERNEL is too old. Need 6.8+. Ask P1 for help."
fi

# ── 2. System packages ───────────────────────────────────────
echo ""
echo "[ 2/6 ] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
  git \
  curl \
  python3 \
  python3-pip \
  python3-venv \
  build-essential \
  linux-tools-generic \
  linux-tools-common \
  linux-tools-$(uname -r) \
  libbpf-dev \
  clang \
  llvm \
  linux-headers-generic \
  net-tools \
  iproute2 \
  jq
ok "System packages installed"

# ── 3. Node.js 20 ────────────────────────────────────────────
echo ""
echo "[ 3/6 ] Installing Node.js 20..."
if command -v node &>/dev/null && [[ "$(node --version)" == v20* ]]; then
  ok "Node.js $(node --version) already installed"
else
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - 2>/dev/null
  sudo apt-get install -y -qq nodejs
  ok "Node.js $(node --version) installed"
fi

# ── 4. eBPF checks ───────────────────────────────────────────
echo ""
echo "[ 4/6 ] Checking eBPF requirements (needed by P1)..."

# BPF LSM
if grep -q "CONFIG_BPF_LSM=y" /boot/config-$(uname -r) 2>/dev/null; then
  ok "BPF_LSM is enabled"
else
  warn "BPF_LSM not found in kernel config — P1 should investigate"
fi

# cgroup v2
if mount | grep -q "cgroup2"; then
  ok "cgroup v2 is mounted"
else
  warn "cgroup v2 not mounted — P2 should investigate"
fi

# bpftool
if command -v bpftool &>/dev/null; then
  ok "bpftool $(bpftool version | head -1)"
else
  warn "bpftool not found — run: sudo apt-get install linux-tools-\$(uname -r)"
fi

# ── 5. Daemon socket directory ───────────────────────────────
echo ""
echo "[ 5/6 ] Creating daemon socket directory (needed by P2 + P3)..."
sudo mkdir -p /run/agentsandbox
sudo chown "$USER":"$USER" /run/agentsandbox
ok "/run/agentsandbox created"

# ── 6. Final summary ─────────────────────────────────────────
echo ""
echo "[ 6/6 ] Final check..."
echo ""
echo "  Kernel  : $(uname -r)"
echo "  Node    : $(node --version 2>/dev/null || echo 'not found')"
echo "  Python  : $(python3 --version 2>/dev/null || echo 'not found')"
echo "  Git     : $(git --version 2>/dev/null || echo 'not found')"
echo "  bpftool : $(bpftool version 2>/dev/null | head -1 || echo 'not found')"
echo ""
echo "================================================"
ok "Setup complete! You're ready to work."
echo "================================================"
echo ""
