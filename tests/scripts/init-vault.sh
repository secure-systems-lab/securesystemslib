#!/usr/bin/env bash

vault server -dev \
    -dev-listen-address="${VAULT_ADDR#http://}" \
    -dev-root-token-id="${VAULT_TOKEN}" \
    -dev-no-store-token \
    &

until vault status
do
    sleep 0.1
done

vault secrets enable transit

vault write -force transit/keys/test-key-ed25519 type=ed25519
