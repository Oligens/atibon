use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LearningState {
    pub observations: u64,
    pub blocked: u64,
    pub false_positive_feedback: u64,
    pub adaptive_threshold: f64,
    pub last_profile_digest: String,
}

impl Default for LearningState {
    fn default() -> Self {
        Self {
            observations: 0,
            blocked: 0,
            false_positive_feedback: 0,
            adaptive_threshold: 0.68,
            last_profile_digest: String::new(),
        }
    }
}

impl LearningState {
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
        if false_positive {
            self.adaptive_threshold = (self.adaptive_threshold + 0.01).min(0.90);
        } else if anomaly_score >= self.adaptive_threshold {
            self.adaptive_threshold = (self.adaptive_threshold - 0.002).max(0.50);
        }
        self.last_profile_digest = profile_digest.to_string();
    }

    pub fn threshold(&self) -> f64 {
        self.adaptive_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn learning_remains_bounded_and_passive() {
        let mut state = LearningState::default();
        for _ in 0..100 {
            state.observe(0.8, true, false, "digest");
        }
        assert!((0.50..=0.90).contains(&state.threshold()));
        assert_eq!(state.observations, 100);
    }
}
