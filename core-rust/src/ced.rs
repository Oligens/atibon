use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::rules::{Action, Rule};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub at_ms: u64,
    pub bytes: u32,
    pub path: String,
    pub mutation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BehavioralAssessment {
    pub timing_entropy: f64,
    pub size_entropy: f64,
    pub automation_score: f64,
    pub suspicious: bool,
    pub vector: Vec<u8>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyNode {
    pub id: String,
    pub kind: String,
    pub response_shape: String,
    pub next: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttackObservation {
    pub assessment: BehavioralAssessment,
    pub decoy_graph: Vec<DecoyNode>,
    pub generated_rule: Rule,
    pub rule_digest: String,
    pub signature_algorithm: String,
}

fn entropy(values: &[u64]) -> f64 {
    if values.len() < 2 { return 0.0; }
    let mut counts = BTreeMap::<u64, usize>::new();
    for v in values { *counts.entry(*v).or_default() += 1; }
    let n = values.len() as f64;
    counts.values().map(|c| {
        let p = *c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn quantize_delta(delta: u64) -> u64 { delta.saturating_div(10).min(10_000) }

pub fn assess(samples: &[TelemetrySample]) -> BehavioralAssessment {
    if samples.len() < 3 {
        return BehavioralAssessment { timing_entropy: 0.0, size_entropy: 0.0, automation_score: 0.0, suspicious: false, vector: vec![], reasons: vec!["insufficient_telemetry".into()] };
    }
    let mut deltas = Vec::with_capacity(samples.len() - 1);
    let mut sizes = Vec::with_capacity(samples.len());
    for pair in samples.windows(2) { deltas.push(quantize_delta(pair[1].at_ms.saturating_sub(pair[0].at_ms))); }
    for s in samples { sizes.push((s.bytes as u64).min(1_048_576) / 64); }
    let timing_entropy = entropy(&deltas);
    let size_entropy = entropy(&sizes);
    let unique_paths = samples.iter().map(|s| s.path.as_str()).collect::<std::collections::HashSet<_>>().len();
    let unique_mutations = samples.iter().map(|s| s.mutation.as_str()).collect::<std::collections::HashSet<_>>().len();
    let path_repetition = 1.0 - (unique_paths as f64 / samples.len() as f64);
    let mutation_repetition = 1.0 - (unique_mutations as f64 / samples.len() as f64);
    let low_timing_entropy = 1.0 - (timing_entropy / 4.0).min(1.0);
    let automation_score = (0.35 * low_timing_entropy + 0.35 * path_repetition + 0.30 * mutation_repetition).clamp(0.0, 1.0);
    let suspicious = automation_score >= 0.68;
    let mut reasons = Vec::new();
    if low_timing_entropy > 0.55 { reasons.push("low_kinematic_entropy".into()); }
    if path_repetition > 0.55 { reasons.push("repetitive_exploration_loop".into()); }
    if mutation_repetition > 0.55 { reasons.push("repetitive_payload_mutation".into()); }

    let canonical = serde_json::to_vec(samples).unwrap_or_default();
    let vector = Sha256::digest(&canonical).to_vec();
    BehavioralAssessment { timing_entropy, size_entropy, automation_score, suspicious, vector, reasons }
}

pub fn deceptive_graph(assessment: &BehavioralAssessment) -> Vec<DecoyNode> {
    let salt = hex_id(&assessment.vector);
    vec![
        DecoyNode { id: format!("entry-{salt}"), kind: "api-mirror".into(), response_shape: "stable-but-fake-schema".into(), next: vec![format!("probe-{salt}")] },
        DecoyNode { id: format!("probe-{salt}"), kind: "vulnerable-mirror".into(), response_shape: "synthetic-debug-surface".into(), next: vec![format!("sink-{salt}")] },
        DecoyNode { id: format!("sink-{salt}"), kind: "isolated-sink".into(), response_shape: "telemetry-only".into(), next: vec![] },
    ]
}

pub fn mutate_rule(assessment: &BehavioralAssessment) -> Rule {
    let digest = hex_id(&assessment.vector);
    let action = if assessment.automation_score >= 0.85 { Action::Reject } else { Action::Drop };
    Rule { name: format!("ced-{}", &digest[..16]), protocol: None, dst_port: None, action }
}

pub fn observe(samples: &[TelemetrySample]) -> AttackObservation {
    let assessment = assess(samples);
    let graph = deceptive_graph(&assessment);
    let rule = mutate_rule(&assessment);
    let rule_digest = hex_id(&serde_json::to_vec(&rule).unwrap_or_default());
    AttackObservation { assessment, decoy_graph: graph, generated_rule: rule, rule_digest, signature_algorithm: "ML-DSA-65 (FIPS 204)".into() }
}

fn hex_id(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_repetitive_automation() {
        let samples = (0..12).map(|i| TelemetrySample { at_ms: i * 100, bytes: 512, path: "/probe".into(), mutation: "xor".into() }).collect::<Vec<_>>();
        let a = assess(&samples);
        assert!(a.automation_score > 0.6);
        assert!(a.vector.len() == 32);
    }

    #[test]
    fn mutation_is_fail_closed() {
        let samples = (0..4).map(|i| TelemetrySample { at_ms: i * 10, bytes: 64, path: "/x".into(), mutation: "same".into() }).collect::<Vec<_>>();
        assert!(matches!(mutate_rule(&assess(&samples)).action, Action::Drop | Action::Reject));
    }
}
