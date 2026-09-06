#!/usr/bin/env bash
set -euo pipefail

MODULE_PATH="${ATIBON_PKCS11_MODULE:?Set ATIBON_PKCS11_MODULE to the HSM PKCS#11 library}"
TOKEN_LABEL="${ATIBON_HSM_TOKEN:?Set ATIBON_HSM_TOKEN to the enrolled token label}"

command -v pkcs11-tool >/dev/null || { echo "OpenSC pkcs11-tool is required" >&2; exit 1; }

echo "Available HSM slots:"
pkcs11-tool --module "$MODULE_PATH" --list-slots

echo "Token information:"
pkcs11-tool --module "$MODULE_PATH" --list-token-slots

echo "ATIBON PKCS#11 module is reachable. Object/key operations must be performed with the HSM policy and PIN supplied by the deployment secret manager."
