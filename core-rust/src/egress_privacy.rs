use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EgressMode {
    Direct,
    PrivacyRelay,
    Quarantine,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub enabled: bool,
    pub suspicious_threshold: u8,
    pub rotate_after_requests: u64,
    pub relay_pool: Vec<String>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_threshold: 70,
            rotate_after_requests: 100,
            relay_pool: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressDecision {
    pub mode: EgressMode,
    pub destination: String,
    pub relay: Option<String>,
    pub identity_token: String,
    pub request_epoch: u64,
    pub reason: String,
    pub source_ip_rewrite: bool,
    pub header_spoofing: bool,
}

fn identity_token(destination: &str, request_epoch: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"atibon-egress-privacy-v1");
    hasher.update(destination.as_bytes());
    hasher.update(request_epoch.to_be_bytes());
    hex::encode(hasher.finalize())
}

fn relay_for(destination: &str, request_epoch: u64, pool: &[String]) -> Option<String> {
    if pool.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(destination.as_bytes());
    hasher.update(request_epoch.to_be_bytes());
    let digest = hasher.finalize();
    let mut index_bytes = [0u8; 8];
    index_bytes.copy_from_slice(&digest[..8]);
    let index = u64::from_be_bytes(index_bytes) as usize % pool.len();
    pool.get(index).cloned()
}

pub fn decide(
    destination: &str,
    reputation_score: u8,
    request_count: u64,
    policy: &EgressPolicy,
) -> EgressDecision {
    let request_epoch = if policy.rotate_after_requests == 0 {
        request_count
    } else {
        request_count / policy.rotate_after_requests
    };
    let suspicious = reputation_score >= policy.suspicious_threshold;

    let (mode, relay, reason) = if !policy.enabled {
        (EgressMode::Direct, None, "egress privacy disabled by policy".to_string())
    } else if suspicious {
        match relay_for(destination, request_epoch, &policy.relay_pool) {
            Some(relay) => (
                EgressMode::PrivacyRelay,
                Some(relay),
                "destination requires privacy-preserving egress".to_string(),
            ),
            None => (
                EgressMode::Quarantine,
                None,
                "suspicious destination has no approved privacy relay".to_string(),
            ),
        }
    } else {
        (EgressMode::Direct, None, "destination allowed by reputation policy".to_string())
    };

    EgressDecision {
        mode,
        destination: destination.to_string(),
        relay,
        identity_token: identity_token(destination, request_epoch),
        request_epoch,
        reason,
        source_ip_rewrite: false,
        header_spoofing: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_destination_uses_approved_relay() {
        let policy = EgressPolicy {
            relay_pool: vec!["relay-a".into(), "relay-b".into()],
            ..Default::default()
        };
        let decision = decide("tracker.example", 90, 101, &policy);
        assert_eq!(decision.mode, EgressMode::PrivacyRelay);
        assert!(decision.relay.is_some());
        assert!(!decision.source_ip_rewrite);
        assert!(!decision.header_spoofing);
    }

    #[test]
    fn suspicious_destination_without_relay_is_quarantined() {
        let decision = decide("bad.example", 90, 1, &EgressPolicy::default());
        assert_eq!(decision.mode, EgressMode::Quarantine);
    }

    #[test]
    fn rotation_changes_identity_epoch() {
        let policy = EgressPolicy {
            rotate_after_requests: 10,
            relay_pool: vec!["relay-a".into()],
            ..Default::default()
        };
        let first = decide("example", 90, 9, &policy);
        let second = decide("example", 90, 10, &policy);
        assert_ne!(first.identity_token, second.identity_token);
        assert_ne!(first.request_epoch, second.request_epoch);
    }
}
