#!/usr/bin/env bash
# Scan compatibility entry; writes require a server-issued plan over IPC.
set -euo pipefail
case "${1:-}" in
  scan) exec node "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/worker.js" scan ;;
  *) printf '%s\n' '{"code":"PLAN_REQUIRED","error":"Use the application preview and confirmation workflow"}' >&2; exit 2 ;;
esac