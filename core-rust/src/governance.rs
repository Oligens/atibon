use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard upper bounds for the defensive-agent runtime.
/// Values are deliberately conservative; deployments can reject requests that exceed them,
/// but these invariants must not be relaxed by an agent at runtime.
pub const MAX_ACTIVE_AGENTS: usize = 11;
pub const MAX_GENERATION_DEPTH: u64 = 4;
pub const MAX_CPU: u64 = 80;
pub const MAX_MEMORY: u64 = 256 * 1024 * 1024;
pub const MAX_LATENCY: u64 = 2_000;
pub const MAX_REGENERATION_RATE: u64 = 12;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GeneratedAgent {
    pub generation: u64,
    pub agent_id: u8,
    pub parent_agent: Option<u8>,
    pub capability: String,
    pub policy: String,
    pub risk_score: f64,
    pub created_at: u64,
    pub expires_at: u64,
    pub raison: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResourceRequest {
    pub cpu_percent: u64,
    pub memory_bytes: u64,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResourceGovernor {
    pub active_agents: usize,
    pub generation_depth: u64,
    pub regenerations_in_window: u64,
    pub window_started_at: u64,
}

impl Default for ResourceGovernor {
    fn default() -> Self {
        Self {
            active_agents: 0,
            generation_depth: 0,
            regenerations_in_window: 0,
            window_started_at: now_ms(),
        }
    }
}

impl ResourceGovernor {
    pub fn admit(
        &mut self,
        generation: u64,
        request: &ResourceRequest,
        now: u64,
    ) -> Result<(), String> {
        self.reset_window_if_needed(now);
        if self.active_agents >= MAX_ACTIVE_AGENTS {
            return Err("resource governor: MAX_ACTIVE_AGENTS exceeded".into());
        }
        if generation > MAX_GENERATION_DEPTH {
            return Err("resource governor: MAX_GENERATION_DEPTH exceeded".into());
        }
        if request.cpu_percent > MAX_CPU {
            return Err("resource governor: MAX_CPU exceeded".into());
        }
        if request.memory_bytes > MAX_MEMORY {
            return Err("resource governor: MAX_MEMORY exceeded".into());
        }
        if request.latency_ms > MAX_LATENCY {
            return Err("resource governor: MAX_LATENCY exceeded".into());
        }
        self.active_agents += 1;
        self.generation_depth = self.generation_depth.max(generation);
        Ok(())
    }

    pub fn release(&mut self) {
        self.active_agents = self.active_agents.saturating_sub(1);
    }

    pub fn admit_regeneration(
        &mut self,
        generation: u64,
        request: &ResourceRequest,
        now: u64,
    ) -> Result<(), String> {
        self.reset_window_if_needed(now);
        if self.regenerations_in_window >= MAX_REGENERATION_RATE {
            return Err("resource governor: MAX_REGENERATION_RATE exceeded".into());
        }
        self.admit(generation, request, now)?;
        self.regenerations_in_window += 1;
        Ok(())
    }

    fn reset_window_if_needed(&mut self, now: u64) {
        if now.saturating_sub(self.window_started_at) >= 60_000 {
            self.window_started_at = now;
            self.regenerations_in_window = 0;
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ThresholdStage {
    pub agent_id: u8,
    pub name: String,
    pub threshold: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StageEvaluation {
    pub agent_id: u8,
    pub score: f64,
    pub threshold: f64,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BarrierCandidate {
    pub generation: u64,
    pub scope: String,
    pub capability: String,
    pub policy: String,
    pub risk_score: f64,
    pub estimated_cpu: u64,
    pub estimated_memory: u64,
    pub estimated_latency: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BarrierValidation {
    pub security_ok: bool,
    pub cost_ok: bool,
    pub compatibility_ok: bool,
    pub approved: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PipelineResult {
    pub attack_score: f64,
    pub stages: Vec<StageEvaluation>,
    pub barrier: Option<GeneratedAgent>,
    pub barrier_validation: Option<BarrierValidation>,
    pub blocked_reason: Option<String>,
}

pub fn default_thresholds() -> Vec<ThresholdStage> {
    vec![
        ThresholdStage {
            agent_id: 1,
            name: "detection".into(),
            threshold: 0.50,
        },
        ThresholdStage {
            agent_id: 2,
            name: "behavior".into(),
            threshold: 0.55,
        },
        ThresholdStage {
            agent_id: 3,
            name: "reputation".into(),
            threshold: 0.60,
        },
        ThresholdStage {
            agent_id: 4,
            name: "correlation".into(),
            threshold: 0.62,
        },
        ThresholdStage {
            agent_id: 5,
            name: "forensics".into(),
            threshold: 0.65,
        },
        ThresholdStage {
            agent_id: 6,
            name: "integrity".into(),
            threshold: 0.68,
        },
        ThresholdStage {
            agent_id: 7,
            name: "risk".into(),
            threshold: 0.70,
        },
        ThresholdStage {
            agent_id: 8,
            name: "barrier-analysis".into(),
            threshold: 0.72,
        },
        ThresholdStage {
            agent_id: 9,
            name: "containment".into(),
            threshold: 0.75,
        },
        ThresholdStage {
            agent_id: 10,
            name: "validation".into(),
            threshold: 0.78,
        },
        ThresholdStage {
            agent_id: 11,
            name: "learning".into(),
            threshold: 0.80,
        },
    ]
}

fn normalize_score(score: f64) -> f64 {
    if score.is_finite() {
        score.clamp(0.0, 1.0)
    } else {
        1.0
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn evaluate_pipeline(attack_score: f64, stage_scores: &[f64]) -> PipelineResult {
    let attack_score = normalize_score(attack_score);
    let thresholds = default_thresholds();
    let mut stages = Vec::with_capacity(thresholds.len());
    let mut blocked_reason = None;

    for (index, stage) in thresholds.iter().enumerate() {
        let score = normalize_score(*stage_scores.get(index).unwrap_or(&attack_score));
        let passed = score >= stage.threshold;
        stages.push(StageEvaluation {
            agent_id: stage.agent_id,
            score,
            threshold: stage.threshold,
            passed,
        });
        if !passed {
            blocked_reason = Some(format!(
                "agent {} blocked below threshold {:.2}",
                stage.agent_id, stage.threshold
            ));
            break;
        }
    }

    PipelineResult {
        attack_score,
        stages,
        barrier: None,
        barrier_validation: None,
        blocked_reason,
    }
}

pub fn validate_barrier(candidate: &BarrierCandidate) -> BarrierValidation {
    let security_ok = candidate.risk_score.is_finite()
        && candidate.risk_score <= 0.90
        && candidate.policy.len() <= 4096;
    let cost_ok = candidate.estimated_cpu <= MAX_CPU
        && candidate.estimated_memory <= MAX_MEMORY
        && candidate.estimated_latency <= MAX_LATENCY;
    let compatibility_ok = candidate.generation <= MAX_GENERATION_DEPTH
        && !candidate.scope.is_empty()
        && !candidate.capability.is_empty();
    let approved = security_ok && cost_ok && compatibility_ok;
    let reason = if approved {
        "security/cost/compatibility validation passed".into()
    } else if !security_ok {
        "ABR candidate rejected: security validation failed".into()
    } else if !cost_ok {
        "ABR candidate rejected: cost/resource validation failed".into()
    } else if candidate.generation > MAX_GENERATION_DEPTH {
        format!(
            "ABR candidate rejected: MAX_GENERATION_DEPTH exceeded ({} > {})",
            candidate.generation, MAX_GENERATION_DEPTH
        )
    } else {
        "ABR candidate rejected: compatibility validation failed".into()
    };
    BarrierValidation {
        security_ok,
        cost_ok,
        compatibility_ok,
        approved,
        reason,
    }
}

pub fn regenerate_barrier(
    governor: &mut ResourceGovernor,
    candidate: BarrierCandidate,
    parent_agent: Option<u8>,
    now: u64,
) -> Result<GeneratedAgent, String> {
    let validation = validate_barrier(&candidate);
    if !validation.approved {
        return Err(validation.reason);
    }

    governor.admit_regeneration(
        candidate.generation,
        &ResourceRequest {
            cpu_percent: candidate.estimated_cpu,
            memory_bytes: candidate.estimated_memory,
            latency_ms: candidate.estimated_latency,
        },
        now,
    )?;

    Ok(GeneratedAgent {
        generation: candidate.generation,
        agent_id: 9,
        parent_agent,
        capability: candidate.capability,
        policy: candidate.policy,
        risk_score: candidate.risk_score.clamp(0.0, 1.0),
        created_at: now,
        expires_at: now.saturating_add(300_000),
        raison: candidate.reason,
    })
}

/// Strict sequential pipeline: attack -> agents 1..11 -> ABR validation -> activation.
pub fn run_pipeline(
    governor: &mut ResourceGovernor,
    attack_score: f64,
    stage_scores: &[f64],
    candidate: Option<BarrierCandidate>,
    now: u64,
) -> PipelineResult {
    let mut result = evaluate_pipeline(attack_score, stage_scores);
    if result.blocked_reason.is_some() {
        return result;
    }

    let candidate = match candidate {
        Some(value) => value,
        None => {
            result.blocked_reason = Some("ABR requires an explicit candidate".into());
            return result;
        }
    };

    let validation = validate_barrier(&candidate);
    result.barrier_validation = Some(validation.clone());
    if !validation.approved {
        result.blocked_reason = Some(validation.reason);
        return result;
    }

    match regenerate_barrier(governor, candidate, Some(11), now) {
        Ok(agent) => result.barrier = Some(agent),
        Err(reason) => result.blocked_reason = Some(reason),
    }
    result
}

pub fn trim_expired(agents: &mut VecDeque<GeneratedAgent>, now: u64) {
    agents.retain(|agent| agent.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(generation: u64) -> BarrierCandidate {
        BarrierCandidate {
            generation,
            scope: "test".into(),
            capability: "adaptive-isolation".into(),
            policy: "deny-and-observe".into(),
            risk_score: 0.20,
            estimated_cpu: 20,
            estimated_memory: 1024,
            estimated_latency: 50,
            reason: "threshold breach".into(),
        }
    }

    #[test]
    fn governor_rejects_resource_exhaustion() {
        let mut governor = ResourceGovernor::default();
        let request = ResourceRequest {
            cpu_percent: 81,
            memory_bytes: 1024,
            latency_ms: 10,
        };
        assert!(governor.admit(0, &request, 0).is_err());
    }

    #[test]
    fn pipeline_is_sequential_and_bounded() {
        let mut governor = ResourceGovernor::default();
        let scores = vec![0.9; 11];
        let result = run_pipeline(&mut governor, 0.9, &scores, Some(candidate(1)), 1_000);
        assert_eq!(result.stages.len(), 11);
        assert!(result.barrier.is_some());
        assert!(result.barrier_validation.unwrap().approved);
    }

    #[test]
    fn abr_never_activates_unvalidated_barrier() {
        let mut governor = ResourceGovernor::default();
        let mut bad = candidate(1);
        bad.risk_score = 0.99;
        let result = run_pipeline(&mut governor, 0.9, &[0.9; 11], Some(bad), 1_000);
        assert!(result.barrier.is_none());
        assert!(result.blocked_reason.is_some());
        assert_eq!(governor.active_agents, 0);
    }

    #[test]
    fn generation_depth_is_hard_bounded() {
        let mut governor = ResourceGovernor::default();
        let error = regenerate_barrier(
            &mut governor,
            candidate(MAX_GENERATION_DEPTH + 1),
            None,
            1_000,
        )
        .expect_err("generation depth must be rejected");
        assert!(error.contains("MAX_GENERATION_DEPTH"));
    }
}
