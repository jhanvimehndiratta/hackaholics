#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cleanup() {
  kill "${ENGINE_PID:-}" "${CLIENT_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cd "$ROOT"
python3 -m uvicorn engine.app:app --host 127.0.0.1 --port 8787 &
ENGINE_PID=$!
python3 -m http.server 4173 --bind 127.0.0.1 --directory demo-client &
CLIENT_PID=$!

printf '\nSentinel is ready:\n'
printf '  Workspace: http://127.0.0.1:4173\n'
printf '  Engine:    http://127.0.0.1:8787\n'
printf '  Extension: load unpacked from %s/extension\n\n' "$ROOT"
printf 'Press Ctrl+C to stop both local services.\n'
wait
