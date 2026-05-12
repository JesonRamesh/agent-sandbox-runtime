#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOCKET="${SOCKET:-/tmp/agent-sandbox-demo.sock}"
DAEMON_WS="${DAEMON_WS:-ws://127.0.0.1:7443/events}"
VIEWER_PORT="${VIEWER_PORT:-8765}"
DAEMON_LOG_DIR="${DAEMON_LOG_DIR:-$ROOT/.demo/daemon-logs}"
ORCH_LOG_DIR="${ORCH_LOG_DIR:-$ROOT/.demo/orchestrator-logs}"
PID_DIR="$ROOT/.demo"

mkdir -p "$DAEMON_LOG_DIR" "$ORCH_LOG_DIR" "$PID_DIR"

say() { printf '[quickstart] %s\n' "$*"; }
die() { printf '[quickstart] error: %s\n' "$*" >&2; exit 1; }

if [[ "$(uname -s)" != "Linux" ]]; then
  die "quickstart requires Linux (for the sandbox daemon)"
fi

if [[ ! -x "$ROOT/bin/agentd" ]]; then
  die "bin/agentd not found; run 'make all' first"
fi

cleanup() {
  if [[ -f "$PID_DIR/viewer.pid" ]]; then
    kill "$(cat "$PID_DIR/viewer.pid")" 2>/dev/null || true
  fi
  if [[ -f "$PID_DIR/daemon.pid" ]]; then
    sudo kill "$(cat "$PID_DIR/daemon.pid")" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

rm -f "$SOCKET"

say "starting daemon on $SOCKET"
sudo "$ROOT/bin/agentd" \
  -bpf-dir="$ROOT/bpf" \
  -socket="$SOCKET" \
  -log-dir="$DAEMON_LOG_DIR" \
  -ws-addr=127.0.0.1:7443 \
  >"$PID_DIR/agentd.out" 2>&1 &
echo $! >"$PID_DIR/daemon.pid"

for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.1
done
[[ -S "$SOCKET" ]] || die "daemon socket did not appear"

say "starting viewer on http://127.0.0.1:$VIEWER_PORT"
(
  export PORT="$VIEWER_PORT"
  export DAEMON_WS="$DAEMON_WS"
  bash "$ROOT/viewer/scripts/start-viewer.sh"
) >"$PID_DIR/viewer.out" 2>&1 &
echo $! >"$PID_DIR/viewer.pid"

say "running orchestrator two-agent scenario"
(
  cd "$ROOT/orchestrator"
  export AGENT_SANDBOX_ORCH_LOG_DIR="$ORCH_LOG_DIR"
  python -m orchestrator run \
    -f examples/two_agent/scenario.yaml \
    --daemon-socket="$SOCKET" \
    --json
)

say "done"
