#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-/var/lib/atibon/tpm}"
mkdir -p "$OUT_DIR"
chmod 0700 "$OUT_DIR"

command -v tpm2_quote >/dev/null || { echo "tpm2-tools is required" >&2; exit 1; }
command -v tpm2_createak >/dev/null || { echo "tpm2-tools is required" >&2; exit 1; }

AK_CTX="$OUT_DIR/ak.ctx"
QUOTE="$OUT_DIR/quote.bin"
SIG="$OUT_DIR/quote.sig"
PCR="$OUT_DIR/pcrs.bin"
NONCE_FILE="$OUT_DIR/nonce.bin"

if [[ ! -s "$NONCE_FILE" ]]; then
  umask 077
  head -c 32 /dev/urandom > "$NONCE_FILE"
fi

if [[ ! -s "$AK_CTX" ]]; then
  tpm2_createak -C o -G ecc -g sha256 -s ecdsa -c "$AK_CTX" -u "$OUT_DIR/ak.pub" -n "$OUT_DIR/ak.name"
fi

tpm2_quote -c "$AK_CTX" -l sha256:0,2,7 -q "$(xxd -p -c 256 "$NONCE_FILE")" -m "$QUOTE" -s "$SIG" -o "$PCR"
echo "ATIBON TPM quote generated in $OUT_DIR"
echo "Verify the quote remotely with the enrolled AK public key and expected PCR policy."
