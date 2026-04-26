#!/usr/bin/env bash
# =============================================================
# Agent Sandbox Runtime — VM bootstrap
# Run this once inside the Vagrant/Lima VM to install all
# dependencies, build everything, and enable the systemd service.
#
# Usage:
#   bash setup-vm.sh             # full install + build + enable
#   bash setup-vm.sh deps        # just install deps
#   bash setup-vm.sh build       # build (deps must already be there)
# =============================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✔ $1${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $1${NC}"; }
fail() { echo -e "${RED}  ✘ $1${NC}"; exit 1; }

STAGE="${1:-all}"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "================================================"
echo " Agent Sandbox Runtime — environment setup"
echo " stage=$STAGE  repo=$REPO_DIR  $(date)"
echo "================================================"

# ── stage: deps ──────────────────────────────────────────────
do_deps() {
  echo "[deps 1/5] kernel version"
  KERNEL=$(uname -r)
  MAJOR=${KERNEL%%.*}
  MINOR=$(echo "$KERNEL" | cut -d. -f2)
  if [ "$MAJOR" -gt 6 ] || ([ "$MAJOR" -eq 6 ] && [ "$MINOR" -ge 8 ]); then
    ok "kernel $KERNEL (≥ 6.8 required)"
  else
    fail "kernel $KERNEL too old; need 6.8+. See decision D-001."
  fi

  echo "[deps 2/5] system packages"
  # Retry apt-get update — flaky on first boot (bug B-002)
  for i in 1 2 3 4 5; do
    if sudo apt-get update -qq; then break; fi
    warn "apt-get update failed (try $i/5); sleeping 3s"
    sleep 3
  done
  sudo apt-get install -y -qq \
    git curl jq make build-essential \
    python3 python3-pip python3-venv \
    clang llvm libbpf-dev linux-headers-generic \
    linux-tools-generic \
    net-tools iproute2

  # Try the version-matched bpftool, fall back to generic (bug B-001)
  if sudo apt-get install -y -qq "linux-tools-$(uname -r)" 2>/dev/null; then
    ok "linux-tools-$(uname -r) installed"
  else
    warn "linux-tools-$(uname -r) unavailable — using linux-tools-generic (B-001)"
  fi

  echo "[deps 3/5] Go 1.22"
  if command -v go &>/dev/null && [[ "$(go version)" == *go1.22* ]]; then
    ok "Go already installed: $(go version)"
  else
    GO_VERSION=1.22.2
    ARCH=$(dpkg --print-architecture)
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
      | sudo tar -C /usr/local -xz
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
    export PATH="$PATH:/usr/local/go/bin"
    ok "Go $(go version)"
  fi

  echo "[deps 4/5] kernel feature checks"
  if grep -q "CONFIG_BPF_LSM=y" "/boot/config-$(uname -r)" 2>/dev/null; then
    ok "BPF_LSM compiled in"
  else
    warn "BPF_LSM not in kernel config — see decision D-001"
  fi
  if mount | grep -q "cgroup2"; then
    ok "cgroup v2 mounted"
  else
    warn "cgroup v2 not mounted"
  fi
  # Ensure 'bpf' is in the LSM list — Ubuntu 24.04's bento box does
  # not enable it by default. If it's missing we patch grub and stop:
  # build/install would superficially succeed but the daemon would
  # fail to attach LSM hooks until the system actually reboots into
  # the new cmdline.
  if ! cat /sys/kernel/security/lsm 2>/dev/null | grep -q bpf; then
    warn "bpf LSM not active — installing /etc/default/grub.d drop-in"
    # The bento Ubuntu box has stale autoinstall cruft like
    # `ds=nocloud-net;s=http://10.0.2.2:8648/...` in
    # GRUB_CMDLINE_LINUX_DEFAULT. GRUB itself splits the kernel
    # cmdline at the `;`, dropping everything after — which would
    # silently drop our `lsm=` flag (see bug B-012). Override the
    # whole var via a drop-in so update-grub uses our value.
    echo 'GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=0 biosdevname=0 lsm=lockdown,yama,integrity,apparmor,bpf"' \
      | sudo tee /etc/default/grub.d/99-agentsandbox.cfg >/dev/null
    sudo update-grub
    cat <<'EOF'

================================================================
 BPF LSM is required but not active in the running kernel.
 GRUB has been updated. Reboot the VM, then re-run setup:

     vagrant reload          # from the host
     vagrant ssh
     cd agentsandbox
     bash setup-vm.sh all    # picks up where we left off

 (apt also pulled in a newer kernel during 'deps'; the reboot
  will activate that too.)
================================================================
EOF
    exit 0
  else
    ok "bpf LSM active"
  fi

  echo "[deps 5/5] daemon directories"
  sudo mkdir -p /sys/fs/bpf/agentsandbox
  sudo mkdir -p /sys/fs/cgroup/agentsandbox
  sudo mkdir -p /var/log/agentsandbox
  sudo mkdir -p /etc/agentsandbox/policies
  ok "runtime dirs created"
}

# ── stage: build ─────────────────────────────────────────────
do_build() {
  export PATH="$PATH:/usr/local/go/bin"
  echo "[build 1/3] eBPF objects"
  make -C "$REPO_DIR/bpf"
  ok "bpf/*.bpf.o built"

  echo "[build 2/3] daemon (agentd)"
  ( cd "$REPO_DIR/daemon" && go mod tidy && go build -o agentd ./cmd/agentd )
  ok "daemon/agentd built"

  echo "[build 3/3] CLI (agentctl)"
  ( cd "$REPO_DIR/cli/agentctl" && go mod tidy && go build -o agentctl . )
  ok "cli/agentctl/agentctl built"
}

# ── stage: install ───────────────────────────────────────────
do_install() {
  echo "[install] copying artifacts into the system"
  sudo make -C "$REPO_DIR" install
  sudo cp "$REPO_DIR/policies/"*.yaml /etc/agentsandbox/policies/
  sudo systemctl daemon-reload
  sudo systemctl enable --now agentsandbox.service
  ok "agentsandbox.service enabled & started"
  ok "GUI: http://127.0.0.1:9000/ui/  (forwarded to host:9000 via Vagrant)"
}

case "$STAGE" in
  deps)    do_deps ;;
  build)   do_build ;;
  install) do_install ;;
  # Sequential, not '&&' chained: bash suppresses set -e inside
  # functions called from an && list, so a make failure inside
  # do_build would silently get skipped over (see B-009).
  all)     do_deps; do_build; do_install ;;
  *)       fail "unknown stage: $STAGE (deps|build|install|all)" ;;
esac

echo
echo "================================================"
ok " setup stage '$STAGE' complete"
echo " kernel : $(uname -r)"
echo " open   : http://127.0.0.1:9000/ui/"
echo "================================================"
