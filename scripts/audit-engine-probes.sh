#!/usr/bin/env bash
# Read-only source-function probes; no real Docker or filesystem mutation commands.
set -uo pipefail
ENGINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/app/app/server/bin/docker-perm-fix.sh"
if ! sed -n '/^is_protected_path()/p' "$ENGINE" | read -r _historical_function; then
  printf "%s\n" "Historical 1.0.0 function probe only; use tests/ for 1.1.0" >&2
  exit 2
fi
source <(sed -n '/^is_protected_path()/,/^}/p' "$ENGINE")
source <(sed -n '/^effective_bits()/,/^}/p' "$ENGINE")
source <(sed -n '/^get_container_identity()/,/^}/p' "$ENGINE")
for test_path in /etc /etc/ssh /var/lib/docker /var/lib/docker/volumes /vol1; do
  if is_protected_path "$test_path"; then status=protected; else status=unprotected; fi
  printf 'protected_path %s => %s\n' "$test_path" "$status"
done
printf 'effective_bits owner=999:999 identity=999:999 mode=2750 => %s (ordinary owner bits should be 7)\n' "$(effective_bits 999 999 2750 999 999)"
MOCK_CONFIG='1000:1000'
docker() {
  case "$1" in
    inspect) printf '%s\n' "$MOCK_CONFIG" ;;
    exec) printf '1000\n' ;;
    top) printf 'PID UID GID\n1 0 0\n2 1000 1000\n3 1001 1001\n' ;;
    *) return 1 ;;
  esac
}
identity="$(get_container_identity demo yes)"; result=$?
printf 'configured identity with multiple nonroot worker identities => identity=%s rc=%s\n' "$identity" "$result"
MOCK_CONFIG=''
identity="$(get_container_identity demo yes)"; result=$?
printf 'unconfigured identity with same worker identities => identity=%s rc=%s\n' "$identity" "$result"
IFS='|' read -r source target rw <<< '/workspace/data|name|/app/data|true'
printf 'mount delimiter sample => source=%s target=%s rw=%s\n' "$source" "$target" "$rw"
