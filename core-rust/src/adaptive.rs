use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RedAction {
    pub action: String,
    pub synthetic_target: String,
    pub risk: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlueAction {
    pub barrier: String,
    pub expected_risk_reduction: f64,
    pub confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarlEpisode {
    pub episode_id: String,
    pub red_action: RedAction,
    pub blue_action: BlueAction,
    pub posterior_risk: f64,
    pub reward: f64,
}

/// Bounded co-evolution engine. The Red agent can only explore synthetic,
/// non-production states; it never emits exploit payloads or executes attacks.
pub fn simulate_episode(seed: &[u8], prior_risk: f64) -> MarlEpisode {
    let digest = Sha256::digest(seed);
    let n = digest[0] as usize % 4;
    let red = [
        "schema_drift_probe",
        "route_sequence_probe",
        "token_boundary_probe",
        "rate_limit_probe",
    ][n];
    let risk = (0.35 + (digest[1] as f64 / 255.0) * 0.65).clamp(0.0, 1.0);
    let posterior = bayesian_update(prior_risk.clamp(0.0, 1.0), risk, 0.72);
    let blue_barrier = if posterior >= 0.75 { "isolate_and_rotate" } else if posterior >= 0.45 { "adaptive_decoy" } else { "observe" };
    let confidence = (0.55 + digest[2] as f64 / 255.0 * 0.45).clamp(0.0, 1.0);
    let reduction = if blue_barrier == "isolate_and_rotate" { 0.75 } else if blue_barrier == "adaptive_decoy" { 0.45 } else { 0.15 };
    let reward = reduction - risk * 0.20;
    MarlEpisode {
        episode_id: hex(&digest[..8]),
        red_action: RedAction { action: red.into(), synthetic_target: "ATIBON-SIMULATION-ONLY".into(), risk },
        blue_action: BlueAction { barrier: blue_barrier.into(), expected_risk_reduction: reduction, confidence },
        posterior_risk: posterior,
        reward,
    }
}

fn bayesian_update(prior: f64, likelihood: f64, reliability: f64) -> f64 {
    let p = prior.clamp(0.001, 0.999);
    let l = likelihood.clamp(0.001, 0.999);
    let r = reliability.clamp(0.0, 1.0);
    let evidence = p * (1.0 - r) + l * r;
    evidence.clamp(0.0, 1.0)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticVariant {
    pub version: u64,
    pub route_alias: String,
    pub field_aliases: BTreeMap<String, String>,
    pub header_aliases: BTreeMap<String, String>,
    pub digest: String,
}

/// Semantic MTD only changes internal/contracted aliases. A compatibility
/// translator can map canonical application fields to the active variant.
pub fn generate_semantic_variant(seed: &[u8], version: u64, canonical_fields: &[String]) -> SemanticVariant {
    let digest = Sha256::digest(seed);
    let prefix = hex(&digest[..6]);
    let mut fields = BTreeMap::new();
    let mut headers = BTreeMap::new();
    for (i, field) in canonical_fields.iter().enumerate() {
        fields.insert(field.clone(), format!("f{}_{}", i, &prefix[..4]));
        headers.insert(format!("x-atibon-{}", field), format!("x-atibon-s{}-{}", i, &prefix[..4]));
    }
    SemanticVariant {
        version,
        route_alias: format!("/s/{}/v{}", &prefix[..8], version),
        field_aliases: fields,
        header_aliases: headers,
        digest: hex(&Sha256::digest(serde_json::to_vec(canonical_fields).unwrap_or_default())),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TopologyCandidate {
    pub rule_set: Vec<String>,
    pub micro_segments: u8,
    pub honeypot_routes: u8,
    pub latency_cost_ms: f64,
    pub confusion_score: f64,
    pub objective: f64,
}

/// Deterministic, bounded simulated annealing over defensive topology choices.
/// It never mutates live nftables/mTLS routes; it returns a candidate for the
/// existing quorum/authorization pipeline.
pub fn optimize_topology(seed: &[u8], iterations: usize) -> TopologyCandidate {
    let digest = Sha256::digest(seed);
    let max_iter = iterations.clamp(1, 4096);
    let mut best = candidate(&digest, 1, 1, 1);
    let mut current = best.clone();
    let mut temperature = 1.0_f64;
    for i in 0..max_iter {
        let idx = (digest[i % digest.len()] as u8).wrapping_add(i as u8);
        let proposal = candidate(&digest, 1 + idx % 6, idx % 8, idx % 6);
        let delta = proposal.objective - current.objective;
        let acceptance = if delta >= 0.0 { true } else { ((delta / temperature.max(0.01)).exp()) > (idx as f64 / 255.0) };
        if acceptance { current = proposal; }
        if current.objective > best.objective { best = current.clone(); }
        temperature *= 0.995;
    }
    best
}

fn candidate(seed: &[u8], segments: u8, honeypots: u8, rules: u8) -> TopologyCandidate {
    let entropy = seed.iter().map(|b| *b as f64).sum::<f64>() / (seed.len() as f64 * 255.0);
    let confusion = (0.30 + segments as f64 * 0.08 + honeypots as f64 * 0.05 + rules as f64 * 0.04 + entropy * 0.10).min(1.0);
    let latency = 0.15 + segments as f64 * 0.18 + honeypots as f64 * 0.07 + rules as f64 * 0.04;
    let objective = confusion - (latency / 10.0);
    TopologyCandidate {
        rule_set: (0..rules).map(|i| format!("candidate-rule-{i}")).collect(),
        micro_segments: segments,
        honeypot_routes: honeypots,
        latency_cost_ms: latency,
        confusion_score: confusion,
        objective,
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marl_is_sandboxed() {
        let e = simulate_episode(b"seed", 0.5);
        assert_eq!(e.red_action.synthetic_target, "ATIBON-SIMULATION-ONLY");
        assert!((0.0..=1.0).contains(&e.posterior_risk));
    }

    #[test]
    fn semantic_variant_is_deterministic() {
        let v = generate_semantic_variant(b"seed", 4, &["id".into(), "payload".into()]);
        assert_eq!(v.version, 4);
        assert_eq!(v, generate_semantic_variant(b"seed", 4, &["id".into(), "payload".into()]));
    }

    #[test]
    fn annealing_is_bounded() {
        let c = optimize_topology(b"seed", 10_000);
        assert!(c.rule_set.len() <= 7);
        assert!(c.latency_cost_ms >= 0.0);
    }
}
