"""Fail-closed application facade for the ATIBON native core."""
import json

try:
    from . import _native
except ImportError as exc:
    _native = None
    _native_error = exc

from .poisoning_guard import PoisoningGuard


class AtibonEngine:
    def __init__(self, max_packet_size: int = 65535, quorum: int = 2):
        if _native is None:
            raise RuntimeError(f"ATIBON native core unavailable: {_native_error}")
        self.dpi = _native.DpiEngine(max_packet_size)
        self.consensus = _native.HoneyBadgerState(max(1, quorum))
        self.crypto = _native.PqcFacade()
        self._last_policy_version = 0
        self._learning_guard = PoisoningGuard()

    def inspect(self, packet: bytes) -> dict:
        return json.loads(self.dpi.inspect(packet))

    def ced_observe(self, samples: list[dict]) -> dict:
        """Analyze behavioral telemetry and produce a scoped policy candidate."""
        return json.loads(_native.ced_observe(json.dumps(samples, separators=(",", ":"))))

    def ced_decide(
        self,
        samples: list[dict],
        thresholds: dict | None = None,
        previous_forensic_hash: str = "genesis",
    ) -> dict:
        """Run the multidimensional CED matrix.

        Critical decisions isolate production, freeze the forensic state and emit a
        quorum-gated vaccination candidate. No firewall rule is applied here.
        """
        threshold_payload = thresholds or {}
        return json.loads(
            _native.ced_decide(
                json.dumps(samples, separators=(",", ":")),
                json.dumps(threshold_payload, separators=(",", ":")),
                previous_forensic_hash,
            )
        )

    def forensic_artifact_digest(self, artifact_id: str, kind: str, data: bytes, collected_at_ms: int) -> dict:
        """Create a tamper-evident digest for an authorized local artifact."""
        return json.loads(_native.forensic_artifact_digest(artifact_id, kind, data, collected_at_ms))

    def validate_barrier(self, envelope: dict, now_ms: int, current_epoch: int, current_version: int) -> dict:
        """Validate freshness and digest invariants before cryptographic acceptance."""
        return json.loads(
            _native.validate_barrier(
                json.dumps(envelope, separators=(",", ":")), now_ms, current_epoch, current_version
            )
        )

    def sign_barrier(self, digest_hex: str) -> dict:
        return json.loads(self.crypto.sign_barrier(digest_hex))

    def verify_barrier(self, message: str, public_key_hex: str, signature_hex: str) -> bool:
        return bool(self.crypto.verify_barrier(message, public_key_hex, signature_hex))

    def pqc_health(self) -> dict:
        return json.loads(self.crypto.kem_health())

    def commit_policy(self, payload: bytes, approvals: int = 1) -> bool:
        """Advance consensus only when the configured quorum is reached."""
        return bool(self.consensus.propose(payload, approvals))

    def commit_and_seal_barrier(
        self,
        policy: dict,
        sender_node_id: str,
        recipient_node_id: str,
        key_id: str,
        recipient_kem_public_key_hex: str,
        approvals: int,
        issued_at_ms: int,
    ) -> dict:
        """Commit a barrier through quorum, then seal it for one recipient."""
        candidate = dict(policy)
        candidate["epoch"] = self.consensus.epoch() + 1
        version = int(candidate.get("version", 0))
        if version <= self._last_policy_version:
            raise ValueError("barrier version must increase monotonically")
        if approvals < self.consensus.quorum():
            raise ValueError(f"barrier quorum not reached: {approvals}/{self.consensus.quorum()}")
        payload = json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode()
        if not self.consensus.propose(payload, approvals):
            raise ValueError("ATIBON consensus rejected barrier")
        envelope_json = _native.seal_barrier(
            json.dumps(candidate, separators=(",", ":")),
            sender_node_id,
            recipient_node_id,
            key_id,
            recipient_kem_public_key_hex,
            self.consensus.state_hash(),
            issued_at_ms,
        )
        self._last_policy_version = version
        return json.loads(envelope_json)

    def open_barrier(
        self,
        envelope: dict,
        recipient_kem_private_key_hex: str,
        trusted_signer_public_key_hex: str,
        now_ms: int,
        current_epoch: int,
        current_version: int,
    ) -> dict:
        """Verify, decapsulate and authenticate a received barrier before acceptance."""
        return json.loads(
            _native.open_barrier(
                json.dumps(envelope, separators=(",", ":")),
                recipient_kem_private_key_hex,
                trusted_signer_public_key_hex,
                now_ms,
                current_epoch,
                current_version,
            )
        )

    def governed_learning(
        self,
        event: dict,
        classification: dict,
        decision: dict,
        result: dict,
        feedback: dict,
        shadow_samples: list[tuple[float, bool]],
        approval: bool = False,
    ) -> dict:
        """Run event -> classification -> decision -> result -> feedback ->
        candidate -> validation -> Shadow -> poisoning guard -> approval -> promotion.

        The first native pass is deliberately denied promotion. This lets the
        Python poisoning guard inspect the complete candidate before the only
        promotion-capable native pass is allowed to proceed.
        """
        flow_guard = self._learning_guard.validate_learning_flow(
            event, classification, decision, result, feedback
        )
        if not flow_guard.ok:
            raise ValueError(f"learning poisoning guard rejected flow: {flow_guard.reason}")

        payload = lambda guard_ok: json.loads(
            _native.governed_learning_cycle(
                json.dumps(event, separators=(",", ":")),
                json.dumps(classification, separators=(",", ":")),
                json.dumps(decision, separators=(",", ":")),
                json.dumps(result, separators=(",", ":")),
                json.dumps(feedback, separators=(",", ":")),
                json.dumps(shadow_samples, separators=(",", ":")),
                self._last_policy_version,
                guard_ok,
                approval,
            )
        )

        # Never let the first pass promote: it exists only to materialize the
        # candidate after Rust has performed lineage, validation and Shadow checks.
        cycle = payload(False)
        candidate_guard = self._learning_guard.validate_candidate(
            cycle["candidate"], flow_guard.batch_digest
        )
        if not candidate_guard.ok:
            cycle["promotion"] = {
                "candidate_id": cycle["candidate"]["candidate_id"],
                "poisoning_guard_ok": False,
                "validation_ok": cycle["validation"]["integrity_ok"]
                and cycle["validation"]["safety_ok"]
                and cycle["validation"]["compatible"],
                "shadow_ok": cycle["shadow"]["shadow_ok"],
                "human_or_automatic_approval": approval,
                "promoted": False,
            }
            return cycle

        cycle = payload(True)
        if cycle["promotion"]["promoted"]:
            self._last_policy_version = int(self._last_policy_version) + 1
        return cycle
