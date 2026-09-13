"""Anti-poisoning gate for the governed ATIBON learning pipeline.

This module does not train or mutate a production model. It verifies lineage,
finite/bounded values, replay resistance and digest continuity before a policy
candidate can reach the promotion gate.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


MAX_BATCH = 256
MIN_CONFIDENCE = 0.0
MAX_CONFIDENCE = 1.0
MIN_SCORE = 0.0
MAX_SCORE = 1.0


@dataclass(frozen=True)
class GuardReport:
    ok: bool
    reason: str
    batch_digest: str
    accepted_events: int


class PoisoningGuard:
    """Fail-closed integrity gate for feedback/candidate promotion."""

    def __init__(self, genesis: str = "genesis") -> None:
        self._previous_digest = genesis
        self._seen_events: set[str] = set()

    @staticmethod
    def _digest(payload: object) -> str:
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def validate_learning_flow(
        self,
        event: dict,
        classification: dict,
        decision: dict,
        result: dict,
        feedback: dict,
    ) -> GuardReport:
        """Validate the complete event -> feedback lineage before learning."""
        values = (event, classification, decision, result, feedback)
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            return GuardReport(False, "missing event_id", "", 0)
        if event_id in self._seen_events:
            return GuardReport(False, "replayed event", "", 0)
        if any(item.get("event_id") != event_id for item in values):
            return GuardReport(False, "event lineage mismatch", "", 0)

        score = event.get("anomaly_score")
        confidence = classification.get("confidence")
        if not isinstance(score, (int, float)) or not MIN_SCORE <= score <= MAX_SCORE:
            return GuardReport(False, "anomaly score out of bounds", "", 0)
        if not isinstance(confidence, (int, float)) or not MIN_CONFIDENCE <= confidence <= MAX_CONFIDENCE:
            return GuardReport(False, "classification confidence out of bounds", "", 0)
        if not isinstance(event.get("source_digest"), str) or not event["source_digest"]:
            return GuardReport(False, "missing source digest", "", 0)
        if feedback.get("trusted") is not True:
            return GuardReport(False, "feedback is not trusted", "", 0)

        digest = self._digest({"previous": self._previous_digest, "flow": values})
        self._previous_digest = digest
        self._seen_events.add(event_id)
        return GuardReport(True, "accepted", digest, 1)

    def validate_candidate(self, candidate: dict, flow_digest: str) -> GuardReport:
        """Bind the policy candidate to the verified learning flow."""
        if not flow_digest or candidate.get("training_digest") == "":
            return GuardReport(False, "missing training lineage digest", "", 0)
        if candidate.get("training_digest") is None:
            return GuardReport(False, "candidate has no training digest", "", 0)
        threshold = candidate.get("threshold")
        if not isinstance(threshold, (int, float)) or not MIN_SCORE <= threshold <= MAX_SCORE:
            return GuardReport(False, "candidate threshold out of bounds", "", 0)
        # A candidate must be explicitly bound to the verified flow digest.
        binding = self._digest({"flow_digest": flow_digest, "candidate": candidate})
        return GuardReport(True, "candidate integrity accepted", binding, 1)

    def validate_batch(self, events: list[dict]) -> GuardReport:
        """Pre-screen a batch for duplicates and bounded numeric inputs."""
        if not events or len(events) > MAX_BATCH:
            return GuardReport(False, "invalid learning batch size", "", 0)
        ids = [item.get("event_id") for item in events]
        if any(not isinstance(item, str) or not item for item in ids):
            return GuardReport(False, "invalid event id", "", 0)
        if len(ids) != len(set(ids)) or any(item in self._seen_events for item in ids):
            return GuardReport(False, "duplicate or replayed event", "", 0)
        for item in events:
            score = item.get("anomaly_score")
            if not isinstance(score, (int, float)) or not MIN_SCORE <= score <= MAX_SCORE:
                return GuardReport(False, "batch contains out-of-range score", "", 0)
        return GuardReport(True, "batch accepted", self._digest(events), len(events))
