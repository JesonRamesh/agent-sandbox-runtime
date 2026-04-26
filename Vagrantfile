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
    # Was `ubuntu/noble64` — Canonical no longer publishes that box
    # to Vagrant Cloud (404). Bento ships an equivalent kernel-6.8
    # image and is the de-facto replacement. See bug B-006.
    config.vm.box = "bento/ubuntu-24.04"
    config.vm.provider "virtualbox" do |vb|
      vb.name   = "agentsandbox-dev"
      vb.memory = 4096
      vb.cpus   = 2
      vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
    end
  end

  config.vm.hostname = "agentsandbox-dev"

  # Port forwarding — port 9000 in the VM (the agentd HTTP+SSE
  # API and the web GUI at /ui/) is reachable on the host at the
  # same port (http://127.0.0.1:9000/ui/).
  config.vm.network "forwarded_port", guest: 9000, host: 9000, host_ip: "127.0.0.1"

  # Sync the project repo folder into the VM at this path
  config.vm.synced_folder ".", "/home/vagrant/agentsandbox"

  # Everything below runs INSIDE the Linux VM on first boot.
  # All install/build/enable logic lives in setup-vm.sh so the same
  # script works whether the user is in the VM or running directly
  # on an Ubuntu host. Run as the vagrant user (script uses sudo).
  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    set -euo pipefail
    cd /home/vagrant/agentsandbox
    bash setup-vm.sh all

    echo ""
    echo "================================================"
    echo " Agent Sandbox Runtime is up."
    echo " Kernel : $(uname -r)"
    echo " GUI    : http://127.0.0.1:9000/ui/  (port-forwarded to your host)"
    echo " Logs   : journalctl -u agentsandbox.service -f"
    echo "================================================"
  SHELL
end
