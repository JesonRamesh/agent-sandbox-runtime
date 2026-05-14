#!/usr/bin/env bash
# =============================================================================
# Agent Sandbox — install a sudoers fragment so the (unprivileged) viewer
# relay can spawn `agentctl run` without a password prompt.
#
# Why this is needed: the agentd IPC socket lives at /run/agent-sandbox.sock
# and is mode 0600 root:root. Without this fragment, the relay's
# /api/scenarios/run endpoint can't talk to the daemon — every request would
# fail with "permission denied".
#
# Scope of the grant: ONLY `agentctl run -f /…/playground/<scenario>.yaml`,
# and only on the well-known socket. No other agentctl subcommand and no
# arbitrary path. The Cmnd_Alias glob in the fragment matches the exact argv
# the viewer's runner.js produces.
#
# Usage:
#   sudo bash scripts/install-viewer-sudoers.sh                # default config
#   sudo USER=ubuntu BIN=/opt/agentd/bin/agentctl bash …       # overrides
#
# Reverse it with:
#   sudo rm /etc/sudoers.d/agentsandbox-viewer
# =============================================================================

set -euo pipefail

# These four are everything the fragment depends on. Everything else is
# derived. Keep the BIN + DIR + SOCK in lockstep with viewer/server/server.js
# defaults; if you change one, update the other.
USER_NAME="${TARGET_USER:-vagrant}"
BIN="${AGENTCTL_BIN:-/home/vagrant/agentsandbox/bin/agentctl}"
SOCK="${SOCKET_PATH:-/run/agent-sandbox.sock}"
DIR="${PLAYGROUND_DIR:-/home/vagrant/agentsandbox/examples/playground}"
DST="${SUDOERS_FILE:-/etc/sudoers.d/agentsandbox-viewer}"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: must run as root (try: sudo bash $0)" >&2
  exit 2
fi

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  echo "error: user '$USER_NAME' not found on this host" >&2
  exit 2
fi

if [ ! -x "$BIN" ]; then
  echo "error: agentctl binary not found at $BIN — build first with 'make all'" >&2
  exit 2
fi

if [ ! -d "$DIR" ]; then
  echo "error: playground directory not found at $DIR" >&2
  exit 2
fi

# Use a tmp file + visudo -cf for syntax check before atomic install. A
# malformed sudoers can lock you out of sudo entirely.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
# Installed by scripts/install-viewer-sudoers.sh
# Grants the viewer's relay process permission to spawn agentctl run -f
# against the daemon's IPC socket, ONLY for manifests under the playground
# directory. Do not edit by hand — re-run the script if the paths change.

Cmnd_Alias AGENTSANDBOX_RUN = $BIN --socket=$SOCK run -f $DIR/*

$USER_NAME ALL=(root) NOPASSWD: AGENTSANDBOX_RUN
EOF

if ! visudo -cf "$TMP" >/dev/null; then
  echo "error: generated sudoers fragment failed visudo -cf" >&2
  cat "$TMP" >&2
  exit 3
fi

install -m 0440 -o root -g root "$TMP" "$DST"

echo "installed: $DST"
echo "grant:     $USER_NAME may run \`sudo -n agentctl run -f $DIR/*\`"
echo "verify:    sudo -n -u $USER_NAME -l $BIN"
