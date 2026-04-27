#!/usr/bin/env bash
# Idempotent installer for agent-sandbox-daemon on Ubuntu 22.04 (HWE) / 24.04.
# Re-running is a no-op except for binary refresh and unit reload.
set -euo pipefail

# Resolve the repo root from this script's location so `make install`
# works regardless of cwd.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"

USER_NAME="agent-sandbox"
GROUP_NAME="agent-sandbox"
INSTALL_BIN_DIR="/usr/local/bin"
DAEMON_BIN_SRC="${REPO_ROOT}/bin/agent-sandbox-daemon"
TEST_CLIENT_SRC="${REPO_ROOT}/bin/test-client"
ETC_DIR="/etc/agent-sandbox"
LOG_DIR="/var/log/agent-sandbox"
UNIT_SRC="${SCRIPT_DIR}/systemd/agent-sandbox.service"
UNIT_DEST="/etc/systemd/system/agent-sandbox.service"
BPFFS_MOUNTPOINT="/sys/fs/bpf"
FSTAB_LINE="bpffs ${BPFFS_MOUNTPOINT} bpf defaults 0 0"

step() { echo "==> step $1: $2"; }

require_root() {
  step 0 "checking privileges"
  if [[ "${EUID}" -ne 0 ]]; then
    echo "install.sh must be run as root (use 'sudo make install')" >&2
    exit 1
  fi
}

check_binaries_exist() {
  step 1 "checking build artifacts"
  if [[ ! -x "${DAEMON_BIN_SRC}" ]]; then
    echo "missing ${DAEMON_BIN_SRC} — run 'make build' first" >&2
    exit 1
  fi
  if [[ ! -x "${TEST_CLIENT_SRC}" ]]; then
    echo "missing ${TEST_CLIENT_SRC} — run 'make build' first" >&2
    exit 1
  fi
}

ensure_user() {
  step 2 "ensuring ${USER_NAME} system user exists"
  if id "${USER_NAME}" >/dev/null 2>&1; then
    echo "    user already exists; skipping"
    return
  fi
  # --system: low UID, no aging; --no-create-home: daemon never reads $HOME;
  # nologin shell because nobody should `su - agent-sandbox`.
  useradd --system --no-create-home --shell /usr/sbin/nologin "${USER_NAME}"
}

install_binaries() {
  step 3 "installing binaries to ${INSTALL_BIN_DIR}"
  install -m 0755 -o root -g root "${DAEMON_BIN_SRC}"  "${INSTALL_BIN_DIR}/agent-sandbox-daemon"
  install -m 0755 -o root -g root "${TEST_CLIENT_SRC}" "${INSTALL_BIN_DIR}/test-client"
}

ensure_dirs() {
  step 4 "creating ${ETC_DIR} and ${LOG_DIR}"
  install -d -m 0750 -o "${USER_NAME}" -g "${GROUP_NAME}" "${ETC_DIR}"
  install -d -m 0750 -o "${USER_NAME}" -g "${GROUP_NAME}" "${LOG_DIR}"
}

ensure_bpffs() {
  step 5 "ensuring ${BPFFS_MOUNTPOINT} is mounted (bpf fs)"
  if mountpoint -q "${BPFFS_MOUNTPOINT}"; then
    echo "    already mounted; skipping"
  else
    mkdir -p "${BPFFS_MOUNTPOINT}"
    mount -t bpf bpf "${BPFFS_MOUNTPOINT}"
  fi
  # fstab persistence — only append if missing.
  if grep -qE "^[^#]*[[:space:]]${BPFFS_MOUNTPOINT}[[:space:]]+bpf[[:space:]]" /etc/fstab; then
    echo "    fstab entry already present; skipping"
  else
    echo "${FSTAB_LINE}" >> /etc/fstab
    echo "    appended fstab entry"
  fi
}

install_unit() {
  step 6 "installing systemd unit to ${UNIT_DEST}"
  install -m 0644 -o root -g root "${UNIT_SRC}" "${UNIT_DEST}"
}

reload_systemd() {
  step 7 "reloading systemd"
  systemctl daemon-reload
}

enable_and_start() {
  step 8 "enabling and starting agent-sandbox.service"
  systemctl enable --now agent-sandbox.service
}

verify_active() {
  step 9 "verifying service is active"
  # Brief delay before is-active: systemd has to spawn the binary,
  # bind the socket, and the daemon has to load BPF programs.
  sleep 2
  if systemctl is-active --quiet agent-sandbox.service; then
    echo "    agent-sandbox is active"
    echo "==> install complete"
    return 0
  fi

  echo "    agent-sandbox failed to become active. Recent journal:" >&2
  journalctl -u agent-sandbox -n 30 --no-pager >&2 || true
  exit 1
}

main() {
  require_root
  check_binaries_exist
  ensure_user
  install_binaries
  ensure_dirs
  ensure_bpffs
  install_unit
  reload_systemd
  enable_and_start
  verify_active
}

main "$@"
