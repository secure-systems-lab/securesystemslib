#!/usr/bin/env bash
set -e

VAULT_RUNTIME_DIR="${TOX_ENV_DIR:-${TMPDIR:-/tmp}}"
VAULT_LOG="${VAULT_RUNTIME_DIR}/vault.log"
VAULT_PID_FILE="${VAULT_RUNTIME_DIR}/vault.pid"

nohup vault server -dev -dev-root-token-id="${VAULT_TOKEN}" >"${VAULT_LOG}" 2>&1 </dev/null &
VAULT_PID=$!
echo "${VAULT_PID}" >"${VAULT_PID_FILE}"

until vault status >/dev/null 2>&1
do
    if ! kill -0 "${VAULT_PID}" 2>/dev/null; then
        cat "${VAULT_LOG}"
        exit 1
    fi
    sleep 0.1
done

vault secrets enable transit

vault write -force transit/keys/test-key-ed25519 type=ed25519
