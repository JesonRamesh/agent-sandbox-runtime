#!/usr/bin/env bash
# Removes the agent-sandbox systemd unit and binaries. Deliberately does
# NOT remove the user, log directory, /etc config, or bpffs mount — those
# may contain operator data or be shared with other services.
set -euo pipefail

UNIT_NAME="agent-sandbox.service"
UNIT_DEST="/etc/systemd/system/${UNIT_NAME}"
INSTALL_BIN_DIR="/usr/local/bin"

step() { echo "==> step $1: $2"; }

require_root() {
  step 0 "checking privileges"
  if [[ "${EUID}" -ne 0 ]]; then
    echo "uninstall.sh must be run as root (use 'sudo make uninstall')" >&2
    exit 1
  fi
}

stop_and_disable() {
  step 1 "stopping and disabling ${UNIT_NAME}"
  # Both can fail benignly if the unit was never installed; swallow.
  systemctl disable --now "${UNIT_NAME}" 2>/dev/null || true
}

remove_unit() {
  step 2 "removing unit file"
  rm -f "${UNIT_DEST}"
  systemctl daemon-reload
}

remove_binaries() {
  step 3 "removing binaries from ${INSTALL_BIN_DIR}"
  rm -f "${INSTALL_BIN_DIR}/agent-sandbox-daemon"
  rm -f "${INSTALL_BIN_DIR}/test-client"
}

final_notice() {
  cat <<'EOF'
==> uninstall complete

The following were intentionally LEFT IN PLACE — remove manually if you
are sure no other service depends on them:

  - /var/log/agent-sandbox/   (per-agent log files; may contain forensic data)
  - /etc/agent-sandbox/       (operator-managed config)
  - user/group 'agent-sandbox' (shared system user)
  - /sys/fs/bpf mount         (used by other BPF-using software)
  - /etc/fstab line for bpffs (other software may rely on it)

To remove the user:
    sudo userdel agent-sandbox
To remove logs:
    sudo rm -rf /var/log/agent-sandbox /etc/agent-sandbox
EOF
}

main() {
  require_root
  stop_and_disable
  remove_unit
  remove_binaries
  final_notice
}

main "$@"
