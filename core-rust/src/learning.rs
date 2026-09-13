use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Learning is deliberately separated from production policy mutation.
/// A raw event can never update an active model/policy: it must traverse every
/// governance stage and finish with an explicit promotion gate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LearningEvent {
    pub event_id: String,
    pub observed_at_ms: u64,
    pub anomaly_score: f64,
    pub source_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Classification {
    pub event_id: String,
    pub label: String,
    pub confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub event_id: String,
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultObservation {
    pub event_id: String,
    pub outcome: String,
    pub blocked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Feedback {
    pub event_id: String,
    pub false_positive: bool,
    pub trusted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyCandidate {
    pub candidate_id: String,
    pub base_policy_version: u64,
    pub threshold: f64,
    pub reason: String,
    pub training_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationReport {
    pub candidate_id: String,
    pub integrity_ok: bool,
    pub safety_ok: bool,
    pub compatible: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowReport {
    pub candidate_id: String,
    pub evaluated_events: u64,
    pub regressions: u64,
    pub shadow_ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromotionGate {
    pub candidate_id: String,
    pub poisoning_guard_ok: bool,
    pub validation_ok: bool,
    pub shadow_ok: bool,
    pub human_or_automatic_approval: bool,
    pub promoted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LearningState {
    pub observations: u64,
    pub blocked: u64,
    pub false_positive_feedback: u64,
    pub adaptive_threshold: f64,
    pub last_profile_digest: String,
    pub active_policy_version: u64,
}

impl Default for LearningState {
    fn default() -> Self {
        Self {
            observations: 0,
            blocked: 0,
            false_positive_feedback: 0,
            adaptive_threshold: 0.68,
            last_profile_digest: String::new(),
            active_policy_version: 0,
        }
    }
}

impl LearningState {
    /// Record telemetry only. This method cannot promote or mutate active policy.
    pub fn observe(
        &mut self,
        anomaly_score: f64,
        blocked: bool,
        false_positive: bool,
        profile_digest: &str,
    ) {
        self.observations = self.observations.saturating_add(1);
        if blocked {
            self.blocked = self.blocked.saturating_add(1);
        }
        if false_positive {
            self.false_positive_feedback = self.false_positive_feedback.saturating_add(1);
        }
        self.last_profile_digest = profile_digest.to_string();
        if false_positive {
            self.adaptive_threshold = (self.adaptive_threshold + 0.01).min(0.90);
        } else if anomaly_score >= self.adaptive_threshold {
            self.adaptive_threshold = (self.adaptive_threshold - 0.002).max(0.50);
        }
    }

    pub fn threshold(&self) -> f64 {
        self.adaptive_threshold
    }

    /// Build a candidate from governed feedback. Raw events are intentionally
    /// not accepted here: classification, decision, result and trusted feedback
    /// must all share the same event lineage.
    pub fn propose_candidate(
        &self,
        classification: &Classification,
        decision: &Decision,
        result: &ResultObservation,
        feedback: &Feedback,
        candidate_id: &str,
    ) -> Result<PolicyCandidate, String> {
        if classification.event_id != decision.event_id
            || decision.event_id != result.event_id
            || result.event_id != feedback.event_id
        {
            return Err("learning lineage mismatch".into());
        }
        if !feedback.trusted {
            return Err("untrusted feedback cannot create a policy candidate".into());
        }
        let material = format!(
            "{}|{}|{}|{}|{}|{}",
            classification.event_id,
            classification.label,
            classification.confidence,
            decision.action,
            result.outcome,
            feedback.false_positive
        );
        let digest = hex_digest(material.as_bytes());
        let threshold = if feedback.false_positive {
            (self.adaptive_threshold + 0.01).min(0.90)
        } else {
            self.adaptive_threshold
        };
        Ok(PolicyCandidate {
            candidate_id: candidate_id.to_string(),
            base_policy_version: self.active_policy_version,
            threshold,
            reason: format!("governed feedback: {} / {}", classification.label, result.outcome),
            training_digest: digest,
        })
    }

    /// Validate a candidate before Shadow Mode. No production mutation occurs.
    pub fn validate_candidate(&self, candidate: &PolicyCandidate) -> ValidationReport {
        let integrity_ok = candidate.threshold.is_finite()
            && (0.50..=0.90).contains(&candidate.threshold)
            && !candidate.training_digest.is_empty();
        let safety_ok = candidate.base_policy_version <= self.active_policy_version
            && (0.50..=0.90).contains(&candidate.threshold);
        ValidationReport {
            candidate_id: candidate.candidate_id.clone(),
            integrity_ok,
            safety_ok,
            compatible: candidate.base_policy_version == self.active_policy_version,
        }
    }

    /// Evaluate a candidate in Shadow Mode. Shadow evaluation never changes active state.
    pub fn shadow_validate(&self, candidate: &PolicyCandidate, samples: &[(f64, bool)]) -> ShadowReport {
        let mut regressions = 0u64;
        for (score, expected_block) in samples {
            let simulated_block = *score >= candidate.threshold;
            if simulated_block != *expected_block {
                regressions = regressions.saturating_add(1);
            }
        }
        ShadowReport {
            candidate_id: candidate.candidate_id.clone(),
            evaluated_events: samples.len() as u64,
            regressions,
            shadow_ok: !samples.is_empty() && regressions == 0,
        }
    }

    /// The only operation that may advance active policy version.
    /// All governance gates must be satisfied; raw events are not accepted.
    pub fn promote(
        &mut self,
        candidate: &PolicyCandidate,
        validation: &ValidationReport,
        shadow: &ShadowReport,
        poisoning_guard_ok: bool,
        human_or_automatic_approval: bool,
    ) -> PromotionGate {
        let validation_ok = validation.integrity_ok && validation.safety_ok && validation.compatible;
        let shadow_ok = shadow.shadow_ok && shadow.candidate_id == candidate.candidate_id;
        let promoted = poisoning_guard_ok
            && validation_ok
            && shadow_ok
            && human_or_automatic_approval
            && candidate.base_policy_version == self.active_policy_version;
        if promoted {
            self.active_policy_version = self.active_policy_version.saturating_add(1);
        }
        PromotionGate {
            candidate_id: candidate.candidate_id.clone(),
            poisoning_guard_ok,
            validation_ok,
            shadow_ok,
            human_or_automatic_approval,
            promoted,
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cycle() -> (LearningState, Classification, Decision, ResultObservation, Feedback) {
        let mut state = LearningState::default();
        state.observe(0.8, true, false, "digest");
        (
            state,
            Classification { event_id: "e1".into(), label: "anomaly".into(), confidence: 0.9 },
            Decision { event_id: "e1".into(), action: "quarantine".into() },
            ResultObservation { event_id: "e1".into(), outcome: "blocked".into(), blocked: true },
            Feedback { event_id: "e1".into(), false_positive: false, trusted: true },
        )
    }

    #[test]
    fn raw_event_cannot_update_active_policy() {
        let (state, ..) = cycle();
        assert_eq!(state.active_policy_version, 0);
    }

    #[test]
    fn promotion_requires_all_gates() {
        let (mut state, c, d, r, f) = cycle();
        let candidate = state.propose_candidate(&c, &d, &r, &f, "c1").unwrap();
        let validation = state.validate_candidate(&candidate);
        let shadow = state.shadow_validate(&candidate, &[(0.8, true)]);
        let denied = state.promote(&candidate, &validation, &shadow, false, true);
        assert!(!denied.promoted);
        assert_eq!(state.active_policy_version, 0);
        let approved = state.promote(&candidate, &validation, &shadow, true, true);
        assert!(approved.promoted);
        assert_eq!(state.active_policy_version, 1);
    }

    #[test]
    fn untrusted_feedback_is_rejected() {
        let (state, c, d, r, mut f) = cycle();
        f.trusted = false;
        assert!(state.propose_candidate(&c, &d, &r, &f, "c1").is_err());
    }

    #[test]
    fn lineage_mismatch_is_rejected() {
        let (state, c, mut d, r, f) = cycle();
        d.event_id = "other".into();
        assert!(state.propose_candidate(&c, &d, &r, &f, "c1").is_err());
    }

    #[test]
    fn learning_remains_bounded_and_passive() {
        let mut state = LearningState::default();
        for _ in 0..100 {
            state.observe(0.8, true, false, "digest");
        }
        assert!((0.50..=0.90).contains(&state.threshold()));
        assert_eq!(state.observations, 100);
        assert_eq!(state.active_policy_version, 0);
    }
}
