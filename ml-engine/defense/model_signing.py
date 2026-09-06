"""Strict model artifact integrity verification.

The verifier accepts an Ed25519 public key and detached signature. The private
key must remain in the deployment signing system/HSM and never ship with ATIBON.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_model(path: str | Path, signature: bytes, public_key: bytes) -> bool:
    payload = Path(path).read_bytes()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature:
        return False
    return True
