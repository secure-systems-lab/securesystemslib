#!/usr/bin/env bash
set -e

VAULT_RUNTIME_DIR="${TOX_ENV_DIR:-${TMPDIR:-/tmp}}"
VAULT_PID_FILE="${VAULT_RUNTIME_DIR}/vault.pid"

if [[ -f "${VAULT_PID_FILE}" ]]; then
    VAULT_PID=$(cat "${VAULT_PID_FILE}")
    kill "${VAULT_PID}" 2>/dev/null || true
    rm -f "${VAULT_PID_FILE}"
fi
