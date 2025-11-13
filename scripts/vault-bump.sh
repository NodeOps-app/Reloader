#!/usr/bin/env bash
set -euo pipefail

# Simple KV v2 bump to trigger reloader via Vault watcher
# Requires: VAULT_ADDR, VAULT_TOKEN (or VAULT_TOKEN_FILE)
# Optional: VAULT_MOUNT (default: secret), VAULT_PATH (default: app/config)

VAULT_ADDR=${VAULT_ADDR:-}
VAULT_TOKEN=${VAULT_TOKEN:-}
VAULT_TOKEN_FILE=${VAULT_TOKEN_FILE:-}
VAULT_MOUNT=${VAULT_MOUNT:-secret}
VAULT_PATH=${VAULT_PATH:-app/config}

if [[ -z "$VAULT_ADDR" ]]; then
  echo "VAULT_ADDR not set (e.g., http://127.0.0.1:8200)" >&2
  exit 1
fi

if [[ -z "$VAULT_TOKEN" && -n "$VAULT_TOKEN_FILE" && -f "$VAULT_TOKEN_FILE" ]]; then
  VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
fi

if [[ -z "$VAULT_TOKEN" ]]; then
  echo "VAULT_TOKEN or VAULT_TOKEN_FILE must be set" >&2
  exit 1
fi

now=$(date +%s)
payload=$(cat <<JSON
{"data": {"bump": "${now}"}}
JSON
)

url="${VAULT_ADDR%/}/v1/${VAULT_MOUNT}/data/${VAULT_PATH}"

echo "Writing KV v2 data to ${url} ..."
http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "$url" \
  -d "$payload")

if [[ "$http_code" != "200" && "$http_code" != "204" ]]; then
  echo "Vault write failed with HTTP ${http_code}" >&2
  exit 2
fi

echo "Vault KV bump succeeded at $(date -Is)"
