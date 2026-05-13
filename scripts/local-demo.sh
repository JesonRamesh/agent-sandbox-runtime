#!/usr/bin/env bash
# Run the orchestrator in LOCAL MODE — no daemon, no Linux VM required.
# Works on Mac, Windows (WSL/Git Bash), Linux, and GitHub Codespaces.
#
# What works in local mode:
#   - model/provider selection (MODEL, API_BASE_URL injected as env vars)
#   - tool_tracer event streaming
#   - live dashboard at http://127.0.0.1:8765
#   - multi-agent scenarios with dependencies
#
# What does NOT work (requires Linux 6.8+ + daemon):
#   - kernel-level sandbox enforcement (eBPF LSM, EPERM on denied syscalls)
#   - per-syscall observability of kernel decisions
#
# For the full stack: bash scripts/quickstart.sh (Linux only)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VIEWER_PORT="${VIEWER_PORT:-8765}"
VIEWER_PID=""

say()  { printf '\033[1;34m[local-demo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[local-demo]\033[0m %s\n' "$*"; }

cleanup() {
  [[ -n "$VIEWER_PID" ]] && kill "$VIEWER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

say "LOCAL MODE — no kernel enforcement, works on any OS"
say "For full sandbox enforcement: bash scripts/quickstart.sh (Linux 6.8+ required)"
echo ""

# Start viewer if Node.js is available
if command -v node &>/dev/null && [[ -f "$ROOT/viewer/server/server.js" ]]; then
  if [[ ! -d "$ROOT/viewer/server/node_modules" ]]; then
    say "Installing viewer deps (first run)..."
    cd "$ROOT/viewer/server" && npm install --silent
    cd "$ROOT"
  fi
  say "Starting viewer dashboard at http://127.0.0.1:$VIEWER_PORT"
  PORT="$VIEWER_PORT" node "$ROOT/viewer/server/server.js" &
  VIEWER_PID=$!
  sleep 1
else
  warn "Node.js not found — skipping viewer. Install Node 20+ to enable the dashboard."
fi

# Run the quickstart scenario
say "Running quickstart scenario..."
echo ""
cd "$ROOT/orchestrator"
python -m orchestrator run -f examples/quickstart/scenario.yaml

echo ""
if [[ -n "$VIEWER_PID" ]]; then
  say "Done. Dashboard is at http://127.0.0.1:$VIEWER_PORT — Ctrl-C to stop."
  wait "$VIEWER_PID"
else
  say "Done."
fi
