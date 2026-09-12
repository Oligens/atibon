use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentDescriptor {
    pub id: u8,
    pub name: &'static str,
    pub role: &'static str,
}

pub const AGENTS: [AgentDescriptor; 11] = [
    AgentDescriptor { id: 1, name: "sentinel", role: "capture et télémétrie" },
    AgentDescriptor { id: 2, name: "normalizer", role: "normalisation des flux" },
    AgentDescriptor { id: 3, name: "dpi", role: "inspection protocolaire" },
    AgentDescriptor { id: 4, name: "behavior", role: "profilage comportemental" },
    AgentDescriptor { id: 5, name: "correlator", role: "corrélation des signaux" },
    AgentDescriptor { id: 6, name: "forensics", role: "préservation forensique" },
    AgentDescriptor { id: 7, name: "crypto", role: "intégrité cryptographique" },
    AgentDescriptor { id: 8, name: "risk", role: "évaluation du risque" },
    AgentDescriptor { id: 9, name: "barrier", role: "génération de politiques adaptatives" },
    AgentDescriptor { id: 10, name: "containment", role: "isolement et leurres défensifs" },
    AgentDescriptor { id: 11, name: "learning", role: "apprentissage et retour contrôlé" },
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentConsensus {
    pub participating: u8,
    pub anomaly_votes: u8,
    pub confidence: f64,
    pub recommended_mode: String,
}

pub fn descriptors() -> &'static [AgentDescriptor; 11] { &AGENTS }

pub fn consensus(anomaly_score: f64, crypto_violation: bool, repeated_behavior: bool) -> AgentConsensus {
    let mut votes = 0u8;
    if anomaly_score >= 0.68 { votes += 4; }
    if crypto_violation { votes += 3; }
    if repeated_behavior { votes += 2; }
    let confidence = (votes as f64 / 11.0).clamp(0.0, 1.0);
    let recommended_mode = if confidence >= 0.70 { "contain" } else if confidence >= 0.35 { "adaptive" } else { "monitor" };
    AgentConsensus { participating: 11, anomaly_votes: votes, confidence, recommended_mode: recommended_mode.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exposes_exactly_eleven_agents() { assert_eq!(descriptors().len(), 11); }
    #[test]
    fn consensus_is_bounded() {
        let c = consensus(0.9, true, true);
        assert_eq!(c.participating, 11);
        assert!(c.confidence <= 1.0);
    }
}
