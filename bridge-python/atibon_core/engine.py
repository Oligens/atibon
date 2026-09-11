"""Fail-closed application facade for the ATIBON native core."""
import json

try:
    from . import _native
except ImportError as exc:
    _native = None
    _native_error = exc


class AtibonEngine:
    def __init__(self, max_packet_size: int = 65535):
        if _native is None:
            raise RuntimeError(f"ATIBON native core unavailable: {_native_error}")
        self.dpi = _native.DpiEngine(max_packet_size)
        self.consensus = _native.HoneyBadgerState(1)
        self.crypto = _native.PqcFacade()

    def inspect(self, packet: bytes) -> dict:
        return json.loads(self.dpi.inspect(packet))

    def ced_observe(self, samples: list[dict]) -> dict:
        """Analyze behavioral telemetry and produce a signed-policy candidate envelope.

        Enforcement remains fail-closed: callers must explicitly scope the candidate to
        trusted network context before applying it.
        """
        return json.loads(_native.ced_observe(json.dumps(samples, separators=(",", ":"))))

    def validate_barrier(
        self,
        envelope: dict,
        now_ms: int,
        current_epoch: int,
        current_version: int,
    ) -> dict:
        """Validate replay/expiry/digest invariants before cryptographic acceptance."""
        return json.loads(
            _native.validate_barrier(
                json.dumps(envelope, separators=(",", ":")),
                now_ms,
                current_epoch,
                current_version,
            )
        )

    def sign_barrier(self, digest_hex: str) -> dict:
        return json.loads(self.crypto.sign_barrier(digest_hex))

    def verify_barrier(self, message: str, public_key_hex: str, signature_hex: str) -> bool:
        return bool(self.crypto.verify_barrier(message, public_key_hex, signature_hex))

    def pqc_health(self) -> dict:
        return json.loads(self.crypto.kem_health())

    def commit_policy(self, payload: bytes, approvals: int = 1) -> bool:
        return bool(self.consensus.propose(payload, approvals))
