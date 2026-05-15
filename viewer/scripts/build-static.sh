#!/usr/bin/env bash
# Build viewer/static/main.ts → main.js for the standalone viewer/index.html demo.
# Run from the repo root or anywhere — paths are resolved relative to this script.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VIEWER="$(cd "${HERE}/.." && pwd)"
ESBUILD="${VIEWER}/server/node_modules/.bin/esbuild"

if [[ ! -x "${ESBUILD}" ]]; then
  echo "error: esbuild not found at ${ESBUILD}" >&2
  echo "       run 'npm install' in viewer/server first" >&2
  exit 1
fi

"${ESBUILD}" "${VIEWER}/static/main.ts" \
  --bundle \
  --outfile="${VIEWER}/static/main.js" \
  --target=es2020
