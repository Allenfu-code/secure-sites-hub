#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
port="${SITES_HUB_SMOKE_PORT:-9620}"
case "$port" in
  ''|*[!0-9]*) printf 'invalid smoke-test port\n' >&2; exit 2 ;;
esac
if (( port < 1024 || port > 65535 )); then
  printf 'smoke-test port must be between 1024 and 65535\n' >&2
  exit 2
fi

smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/secure-sites-hub-smoke.XXXXXX")"
case "$smoke_dir" in
  */secure-sites-hub-smoke.*) ;;
  *) printf 'unexpected temporary directory\n' >&2; exit 2 ;;
esac
log_file="$smoke_dir/origin.log"
health_file="$smoke_dir/health.json"
api_file="$smoke_dir/sites.json"
index_file="$smoke_dir/index.html"
detail_file="$smoke_dir/detail.html"

TMPDIR="$smoke_dir" \
SITES_HUB_DATA_DIR="$smoke_dir/data" \
SITES_HUB_REGISTRY="$(pwd)/sites.example.yaml" \
SITES_HUB_DISCOVERY_ENABLED=false \
SITES_HUB_EXPOSE_INTERNALS=false \
SITES_HUB_PROBES_ENABLED=false \
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$port" >"$log_file" 2>&1 &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  rm -f "$log_file" "$health_file" "$api_file" "$index_file" "$detail_file"
  rm -f \
    "$smoke_dir/data/history.sqlite3" \
    "$smoke_dir/data/history.sqlite3-shm" \
    "$smoke_dir/data/history.sqlite3-wal"
  rmdir "$smoke_dir/data" 2>/dev/null || true
  rmdir "$smoke_dir" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 35); do
  if curl --fail --silent --max-time 2 \
    "http://127.0.0.1:${port}/healthz" >"$health_file"; then
    break
  fi
  sleep 1
done

if ! kill -0 "$server_pid" 2>/dev/null; then
  cat "$log_file"
  exit 1
fi

curl --fail --silent --max-time 5 "http://127.0.0.1:${port}/healthz"
printf '\n'
curl --fail --silent --max-time 5 "http://127.0.0.1:${port}/api/v1/summary"
printf '\n'
curl --fail --silent --max-time 5 \
  "http://127.0.0.1:${port}/api/v1/sites" >"$api_file"
curl --fail --silent --max-time 5 \
  "http://127.0.0.1:${port}/" >"$index_file"
curl --fail --silent --max-time 5 \
  "http://127.0.0.1:${port}/sites/example-storefront" >"$detail_file"
grep -q '網站總控中心' "$index_file"
if grep -Eq \
  '/srv/|example-storefront\.service|9123|source_paths|"target"|"detail"' \
  "$api_file" "$index_file" "$detail_file"; then
  printf 'public response exposed an internal field\n' >&2
  exit 1
fi
if curl --silent --output /dev/null --max-time 5 --write-out '%{http_code}' \
  "http://127.0.0.1:${port}/api/v1/candidates" | grep -qv '^404$'; then
  printf 'candidate endpoint should be disabled\n' >&2
  exit 1
fi
printf 'index-ok\n'
