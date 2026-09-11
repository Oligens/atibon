use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

use crate::rules::{Action, Rule};

const DEFAULT_LAYER_COUNT: u8 = 3;
const DEFAULT_LAYER_WINDOW_MS: u64 = 5_000;
const DEFAULT_FUZZ_SIMILARITY: f64 = 0.85;
const DEFAULT_CRITICAL_SCORE: f64 = 0.85;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub at_ms: u64,
    pub bytes: u32,
    pub path: String,
    pub mutation: String,
    #[serde(default)]
    pub layer: u8,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub crypto_event: Option<CryptoSecurityEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoSecurityEvent {
    InvalidMlKemCiphertext,
    InvalidMlDsaSignature,
    UnknownKeyId,
    SessionTokenIntegrityFailure,
    RepeatedCryptoProbe,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatThresholdConfig {
    #[serde(default = "default_layer_count")]
    pub critical_layer_count: u8,
    #[serde(default = "default_layer_window_ms")]
    pub critical_layer_window_ms: u64,
    #[serde(default = "default_fuzz_similarity")]
    pub fuzz_similarity_threshold: f64,
    #[serde(default = "default_critical_score")]
    pub critical_score: f64,
}

impl Default for ThreatThresholdConfig {
    fn default() -> Self {
        Self {
            critical_layer_count: DEFAULT_LAYER_COUNT,
            critical_layer_window_ms: DEFAULT_LAYER_WINDOW_MS,
            fuzz_similarity_threshold: DEFAULT_FUZZ_SIMILARITY,
            critical_score: DEFAULT_CRITICAL_SCORE,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatSeverity {
    Normal,
    Elevated,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainmentMode {
    Monitor,
    Adaptive,
    Permanent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainmentPlan {
    pub mode: ContainmentMode,
    pub production_isolated: bool,
    pub sterile_mirror: bool,
    pub manual_release_required: bool,
    pub sandbox_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaccinationCandidate {
    pub rule_digest: String,
    pub source_vector_digest: String,
    pub forensic_record_hash: String,
    pub scope: String,
    pub requires_quorum: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatDecision {
    pub severity: ThreatSeverity,
    pub containment: ContainmentPlan,
    pub forensic_freeze: bool,
    pub vaccination_eligible: bool,
    pub layer_velocity: f64,
    pub max_layer: u8,
    pub layer_velocity_triggered: bool,
    pub fuzz_convergence: f64,
    pub fuzz_convergence_triggered: bool,
    pub pqc_integrity_violation: bool,
    pub cumulative_score: f64,
    pub signals: Vec<String>,
    pub reasons: Vec<String>,
    pub vaccination: Option<VaccinationCandidate>,
    pub forensic_record_hash: String,
}

fn default_layer_count() -> u8 { DEFAULT_LAYER_COUNT }
fn default_layer_window_ms() -> u64 { DEFAULT_LAYER_WINDOW_MS }
fn default_fuzz_similarity() -> f64 { DEFAULT_FUZZ_SIMILARITY }
fn default_critical_score() -> f64 { DEFAULT_CRITICAL_SCORE }

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
    let unique_paths = samples.iter().map(|s| s.path.as_str()).collect::<HashSet<_>>().len();
    let unique_mutations = samples.iter().map(|s| s.mutation.as_str()).collect::<HashSet<_>>().len();
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

fn payload_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    let mut sa = HashSet::<[u8; 3]>::new();
    let mut sb = HashSet::<[u8; 3]>::new();
    for w in aa.windows(3).take(4096) { if w.len() == 3 { sa.insert([w[0], w[1], w[2]]); } }
    for w in bb.windows(3).take(4096) { if w.len() == 3 { sb.insert([w[0], w[1], w[2]]); } }
    if sa.is_empty() || sb.is_empty() { return if aa == bb { 1.0 } else { 0.0 }; }
    let intersection = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    (intersection / union).clamp(0.0, 1.0)
}

fn fuzz_convergence(samples: &[TelemetrySample]) -> f64 {
    let payloads: Vec<&str> = samples.iter().map(|s| s.payload.as_str()).filter(|p| !p.is_empty()).collect();
    if payloads.len() < 2 { return 0.0; }
    let mut total = 0.0;
    let mut count = 0.0;
    for pair in payloads.windows(2) {
        total += payload_similarity(pair[0], pair[1]);
        count += 1.0;
    }
    if count == 0.0 { 0.0 } else { total / count }
}

fn layer_velocity(samples: &[TelemetrySample], cfg: &ThreatThresholdConfig) -> (f64, u8, bool) {
    if samples.len() < 2 { return (0.0, 0, false); }
    let mut layers: Vec<u8> = samples.iter().map(|s| s.layer).filter(|l| *l > 0).collect();
    layers.sort_unstable();
    layers.dedup();
    let max_layer = layers.iter().copied().max().unwrap_or(0);
    if max_layer < cfg.critical_layer_count { return (0.0, max_layer, false); }
    let first = samples.iter().filter(|s| s.layer > 0).map(|s| s.at_ms).min().unwrap_or(0);
    let target_time = samples.iter().filter(|s| s.layer >= cfg.critical_layer_count).map(|s| s.at_ms).min().unwrap_or(first);
    let elapsed = target_time.saturating_sub(first);
    let velocity = if elapsed == 0 { f64::INFINITY } else { (max_layer as f64 - 1.0) / (elapsed as f64 / 1000.0) };
    (velocity, max_layer, elapsed <= cfg.critical_layer_window_ms)
}

fn pqc_violation(samples: &[TelemetrySample]) -> bool {
    samples.iter().any(|s| s.crypto_event.is_some())
}

fn stable_id(bytes: &[u8]) -> String { hex_id(&Sha256::digest(bytes)) }

pub fn decide(samples: &[TelemetrySample], cfg: &ThreatThresholdConfig, previous_forensic_hash: &str) -> ThreatDecision {
    let assessment = assess(samples);
    let (velocity, max_layer, layer_triggered) = layer_velocity(samples, cfg);
    let convergence = fuzz_convergence(samples);
    let fuzz_triggered = convergence >= cfg.fuzz_similarity_threshold && assessment.automation_score >= 0.55;
    let pqc_triggered = pqc_violation(samples);

    let mut signals = Vec::new();
    let mut reasons = assessment.reasons.clone();
    if layer_triggered { signals.push("layer_penetration_velocity".into()); reasons.push("three_or_more_layers_in_critical_window".into()); }
    if fuzz_triggered { signals.push("stochastic_fuzz_convergence".into()); reasons.push("high_payload_similarity_with_low_behavioral_entropy".into()); }
    if pqc_triggered { signals.push("pqc_integrity_violation".into()); reasons.push("trusted_crypto_subsystem_reported_integrity_violation".into()); }
    if assessment.suspicious { signals.push("automation_behavior".into()); }

    let mut score = assessment.automation_score * 0.35;
    if layer_triggered { score += 0.25; }
    if fuzz_triggered { score += 0.25; }
    if pqc_triggered { score += 0.50; }
    let cumulative_score = score.min(1.0);

    let critical = pqc_triggered || (layer_triggered && fuzz_triggered) || cumulative_score >= cfg.critical_score;
    let elevated = !critical && (assessment.suspicious || layer_triggered || fuzz_triggered);
    let severity = if critical { ThreatSeverity::Critical } else if elevated { ThreatSeverity::Elevated } else { ThreatSeverity::Normal };
    let permanent = matches!(severity, ThreatSeverity::Critical);
    let vector_digest = stable_id(&assessment.vector);
    let sandbox_id = format!("sterile-{}", &vector_digest[..16]);
    let containment = ContainmentPlan {
        mode: if permanent { ContainmentMode::Permanent } else if elevated { ContainmentMode::Adaptive } else { ContainmentMode::Monitor },
        production_isolated: permanent,
        sterile_mirror: permanent,
        manual_release_required: permanent,
        sandbox_id,
    };

    let mut record_material = serde_json::to_vec(&(previous_forensic_hash, &severity, &signals, cumulative_score, &vector_digest)).unwrap_or_default();
    record_material.extend_from_slice(&assessment.vector);
    let forensic_record_hash = stable_id(&record_material);
    let vaccination_eligible = permanent && !assessment.vector.is_empty();
    let vaccination = vaccination_eligible.then(|| VaccinationCandidate {
        rule_digest: stable_id(&signals.iter().map(String::as_bytes).flatten().copied().collect::<Vec<_>>()),
        source_vector_digest: vector_digest,
        forensic_record_hash: forensic_record_hash.clone(),
        scope: "observed-telemetry-only; explicit network scope required before enforcement".into(),
        requires_quorum: true,
    });

    ThreatDecision {
        severity,
        containment,
        forensic_freeze: permanent,
        vaccination_eligible,
        layer_velocity: velocity,
        max_layer,
        layer_velocity_triggered: layer_triggered,
        fuzz_convergence: convergence,
        fuzz_convergence_triggered: fuzz_triggered,
        pqc_integrity_violation: pqc_triggered,
        cumulative_score,
        signals,
        reasons,
        vaccination,
        forensic_record_hash,
    }
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

fn hex_id(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(i: u64, layer: u8, payload: &str) -> TelemetrySample {
        TelemetrySample { at_ms: i, bytes: payload.len() as u32, path: "/probe".into(), mutation: "xor".into(), layer, payload: payload.into(), crypto_event: None }
    }

    #[test]
    fn detects_repetitive_automation() {
        let samples = (0..12).map(|i| sample(i * 100, 1, "same-payload")).collect::<Vec<_>>();
        let a = assess(&samples);
        assert!(a.automation_score > 0.6);
        assert!(a.vector.len() == 32);
    }

    #[test]
    fn mutation_is_fail_closed() {
        let samples = (0..4).map(|i| sample(i * 10, 1, "same")).collect::<Vec<_>>();
        assert!(matches!(mutate_rule(&assess(&samples)).action, Action::Drop | Action::Reject));
    }

    #[test]
    fn three_layers_fast_triggers_velocity() {
        let samples = vec![sample(0, 1, "aaa"), sample(100, 2, "aab"), sample(500, 3, "aaa")];
        let d = decide(&samples, &ThreatThresholdConfig::default(), "genesis");
        assert!(d.layer_velocity_triggered);
    }

    #[test]
    fn slow_layers_do_not_trigger_velocity() {
        let samples = vec![sample(0, 1, "aaa"), sample(10_000, 2, "aab"), sample(20_000, 3, "aaa")];
        let d = decide(&samples, &ThreatThresholdConfig::default(), "genesis");
        assert!(!d.layer_velocity_triggered);
    }

    #[test]
    fn high_payload_convergence_is_a_signal_not_identity_proof() {
        let samples = vec![sample(0, 1, "AAAAAA-payload-stable"), sample(100, 1, "AAAAAA-payload-stable"), sample(200, 1, "AAAAAA-payload-stable")];
        let d = decide(&samples, &ThreatThresholdConfig::default(), "genesis");
        assert!(d.fuzz_convergence_triggered);
        assert!(!d.pqc_integrity_violation);
    }

    #[test]
    fn pqc_violation_forces_critical_containment() {
        let mut s = sample(0, 1, "x");
        s.crypto_event = Some(CryptoSecurityEvent::InvalidMlDsaSignature);
        let d = decide(&[s, sample(10, 1, "y"), sample(20, 1, "z")], &ThreatThresholdConfig::default(), "genesis");
        assert_eq!(d.severity, ThreatSeverity::Critical);
        assert!(d.forensic_freeze);
        assert!(d.containment.production_isolated);
        assert!(d.containment.sterile_mirror);
        assert!(d.vaccination_eligible);
    }

    #[test]
    fn cumulative_matrix_creates_permanent_containment() {
        let samples = vec![sample(0, 1, "stable-payload-001"), sample(100, 2, "stable-payload-001"), sample(500, 3, "stable-payload-001")];
        let d = decide(&samples, &ThreatThresholdConfig::default(), "genesis");
        assert_eq!(d.containment.mode, ContainmentMode::Permanent);
        assert!(!d.forensic_record_hash.is_empty());
        assert!(d.vaccination.is_some());
    }
}
