use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical policy material exchanged between ATIBON nodes.
/// The payload is intentionally opaque here; encryption/decryption is performed
/// by the configured transport provider rather than by the policy model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BarrierPolicy {
    pub policy_id: String,
    pub version: u64,
    pub epoch: u64,
    pub expires_at_ms: u64,
    pub action: String,
    pub scope: String,
    pub rule_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BarrierEnvelope {
    pub protocol: String,
    pub node_id: String,
    pub policy: BarrierPolicy,
    pub kem_algorithm: String,
    pub signature_algorithm: String,
    pub kem_ciphertext_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub policy_digest: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BarrierAcceptance {
    pub accepted: bool,
    pub reason: String,
    pub policy_digest: String,
}

pub fn canonical_policy_bytes(policy: &BarrierPolicy) -> Result<Vec<u8>, String> {
    serde_json::to_vec(policy).map_err(|e| format!("policy serialization failed: {e}"))
}

pub fn policy_digest(policy: &BarrierPolicy) -> Result<String, String> {
    let bytes = canonical_policy_bytes(policy)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex(&hasher.finalize()))
}

/// Validates the envelope's structural invariants before cryptographic verification.
/// This function deliberately does not trust attacker-controlled policy metadata.
pub fn validate_envelope(
    envelope: &BarrierEnvelope,
    now_ms: u64,
    current_epoch: u64,
    current_version: u64,
) -> Result<BarrierAcceptance, String> {
    if envelope.protocol != "ATIBON-BARRIER/1" {
        return Err("unsupported barrier protocol".into());
    }
    if envelope.kem_algorithm != "ML-KEM-768" {
        return Err("unsupported KEM".into());
    }
    if envelope.signature_algorithm != "ML-DSA-65" {
        return Err("unsupported signature algorithm".into());
    }
    if envelope.node_id.trim().is_empty() {
        return Err("missing target node id".into());
    }
    if envelope.policy.epoch < current_epoch {
        return Err("stale policy epoch".into());
    }
    if envelope.policy.version <= current_version {
        return Err("stale policy version".into());
    }
    if envelope.policy.expires_at_ms <= now_ms {
        return Err("expired barrier policy".into());
    }
    if !is_hex(&envelope.kem_ciphertext_hex)
        || !is_hex(&envelope.nonce_hex)
        || !is_hex(&envelope.ciphertext_hex)
        || !is_hex(&envelope.signature_hex)
        || !is_hex(&envelope.policy_digest)
    {
        return Err("malformed hexadecimal envelope field".into());
    }

    let expected = policy_digest(&envelope.policy)?;
    if expected != envelope.policy_digest {
        return Err("policy digest mismatch".into());
    }

    Ok(BarrierAcceptance {
        accepted: false,
        reason: "structural validation passed; signature and KEM decryption required".into(),
        policy_digest: expected,
    })
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BarrierPolicy {
        BarrierPolicy {
            policy_id: "ced-test".into(),
            version: 2,
            epoch: 4,
            expires_at_ms: 9_999,
            action: "quarantine".into(),
            scope: "ipv4:203.0.113.10".into(),
            rule_digest: "aa".repeat(32),
        }
    }

    #[test]
    fn digest_is_stable() {
        assert_eq!(policy_digest(&policy()).unwrap().len(), 64);
        assert_eq!(policy_digest(&policy()).unwrap(), policy_digest(&policy()).unwrap());
    }

    #[test]
    fn rejects_stale_policy() {
        let p = policy();
        let digest = policy_digest(&p).unwrap();
        let envelope = BarrierEnvelope {
            protocol: "ATIBON-BARRIER/1".into(),
            node_id: "node-a".into(),
            policy: p,
            kem_algorithm: "ML-KEM-768".into(),
            signature_algorithm: "ML-DSA-65".into(),
            kem_ciphertext_hex: "aa".into(),
            nonce_hex: "bb".into(),
            ciphertext_hex: "cc".into(),
            policy_digest: digest,
            signature_hex: "dd".into(),
        };
        assert!(validate_envelope(&envelope, 1_000, 4, 2).is_err());
    }
}
