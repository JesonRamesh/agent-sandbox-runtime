# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Agent Sandbox Runtime — shared development VM
# Ubuntu 24.04 with kernel 6.8, eBPF tools, Go, Node.js
#
# -------------------------------------------------------
# APPLE SILICON (M1/M2/M3/M4) USERS — READ THIS:
#   1. Install UTM:         brew install --cask utm
#   2. Install plugin:      vagrant plugin install vagrant-utm
#   3. Then run:            vagrant up --provider=utm
#
# INTEL MAC / LINUX / WINDOWS USERS:
#   1. Install VirtualBox:  brew install --cask virtualbox  (Mac)
#   2. Then run:            vagrant up
# -------------------------------------------------------

# Detect Apple Silicon automatically
def apple_silicon?
  RUBY_PLATFORM.include?("arm64") && RUBY_PLATFORM.include?("darwin")
end

Vagrant.configure("2") do |config|

  if apple_silicon?
    # ── Apple Silicon path (UTM) ──────────────────────────
    config.vm.box      = "bento/ubuntu-24.04-arm64"
    config.vm.provider :utm do |utm|
      utm.name   = "agentsandbox-dev"
      utm.memory = 4096
      utm.cpus   = 3
    end
  else
    # ── Intel / AMD path (VirtualBox) ────────────────────
    config.vm.box        = "ubuntu/noble64"
    config.vm.box_version = ">= 20240401"
    config.vm.provider "virtualbox" do |vb|
      vb.name   = "agentsandbox-dev"
      vb.memory = 4096
      vb.cpus   = 2
      vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
    end
  end

  config.vm.hostname = "agentsandbox-dev"

  # Port forwarding — these ports in the Linux VM become
  # accessible at the same port on your Mac (localhost:XXXX)
  config.vm.network "forwarded_port", guest: 3000, host: 3000, host_ip: "127.0.0.1"  # Web UI
  config.vm.network "forwarded_port", guest: 8765, host: 8765, host_ip: "127.0.0.1"  # WebSocket
  config.vm.network "forwarded_port", guest: 9000, host: 9000, host_ip: "127.0.0.1"  # Daemon debug

  # Sync the project repo folder into the VM at this path
  config.vm.synced_folder ".", "/home/vagrant/agentsandbox"

  # Everything below runs INSIDE the Linux VM on first boot
  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    echo "==> Updating package list..."
    apt-get update -qq

    echo "==> Installing eBPF toolchain (P1's tools)..."
    apt-get install -y -qq \
      clang llvm \
      linux-tools-generic \
      libbpf-dev \
      bpftool \
      linux-headers-generic

    echo "==> Checking BPF LSM availability..."
    if bpftool feature probe 2>/dev/null | grep -q "bpf_lsm"; then
      echo "    BPF LSM: OK"
    else
      echo "    WARNING: BPF LSM not detected. P1 should verify kernel config."
    fi

    echo "==> Checking cgroup v2..."
    if mount | grep -q "cgroup2"; then
      echo "    cgroup v2: OK"
    else
      echo "    WARNING: cgroup v2 not mounted."
    fi

    echo "==> Installing Go 1.22 (P2's daemon language)..."
    GO_VERSION="1.22.2"
    ARCH=$(dpkg --print-architecture)
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
      | tar -C /usr/local -xz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
    echo 'export GOPATH=/home/vagrant/go'       >> /etc/profile.d/go.sh

    echo "==> Installing Node.js 20 (P5's process viewer)..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null
    apt-get install -y -qq nodejs

    echo "==> Installing Python 3 (P4's orchestrator + demo agent)..."
    apt-get install -y -qq python3 python3-pip python3-venv

    echo "==> Installing general dev tools..."
    apt-get install -y -qq \
      git curl wget jq \
      make build-essential \
      net-tools iproute2 \
      strace

    echo "==> Creating daemon socket directory (P2 + P3 need this)..."
    mkdir -p /run/agentsandbox
    chown vagrant:vagrant /run/agentsandbox

    echo ""
    echo "================================================"
    echo " Setup complete!"
    echo " Kernel : $(uname -r)"
    echo " Node   : $(node --version)"
    echo " Python : $(python3 --version)"
    echo " Go     : $(/usr/local/go/bin/go version || echo 're-login to activate')"
    echo ""
    echo " cd /home/vagrant/agentsandbox to start working"
    echo "================================================"
  SHELL
end
