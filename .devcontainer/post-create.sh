#!/usr/bin/env bash
# Runs once after the devcontainer is created.
# Sets up Python deps and the viewer for local-mode development.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[devcontainer] Installing Python dependencies..."
pip install --quiet pyyaml websocket-client openai anthropic python-dotenv

echo "[devcontainer] Installing orchestrator package..."
pip install --quiet -e "$ROOT"

echo "[devcontainer] Installing viewer dependencies..."
if [[ -f "$ROOT/viewer/server/package.json" ]]; then
  cd "$ROOT/viewer/server" && npm install --silent
fi
if [[ -f "$ROOT/viewer/viewer-app/package.json" ]]; then
  cd "$ROOT/viewer/viewer-app" && npm install --silent
fi

echo ""
echo "[devcontainer] Ready. Running in LOCAL MODE (no kernel enforcement)."
echo "  Try it: cd orchestrator && python -m orchestrator run -f examples/quickstart/scenario.yaml"
echo "  Dashboard: bash scripts/local-demo.sh"
echo "  For full kernel enforcement, use Linux 6.8+ via Lima, Vagrant, or another VM."
