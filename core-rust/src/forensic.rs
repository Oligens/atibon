use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicArtifact {
    pub artifact_id: String,
    pub kind: String,
    pub sha256: String,
    pub collected_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicRecord {
    pub event_id: String,
    pub collected_at_ms: u64,
    pub threat_decision_hash: String,
    pub telemetry_digest: String,
    pub previous_record_hash: String,
    pub artifacts: Vec<ForensicArtifact>,
    pub record_hash: String,
    #[serde(default)]
    pub signature_hex: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ForensicLedger {
    pub records: Vec<ForensicRecord>,
}

impl ForensicLedger {
    pub fn append(
        &mut self,
        event_id: &str,
        collected_at_ms: u64,
        threat_decision_hash: &str,
        telemetry_digest: &str,
        artifacts: Vec<ForensicArtifact>,
        signature_hex: Option<String>,
    ) -> ForensicRecord {
        let previous = self.records.last().map(|r| r.record_hash.as_str()).unwrap_or("genesis");
        let material = serde_json::to_vec(&(event_id, collected_at_ms, threat_decision_hash, telemetry_digest, previous, &artifacts)).unwrap_or_default();
        let record_hash = hex(&Sha256::digest(material));
        let record = ForensicRecord {
            event_id: event_id.to_string(),
            collected_at_ms,
            threat_decision_hash: threat_decision_hash.to_string(),
            telemetry_digest: telemetry_digest.to_string(),
            previous_record_hash: previous.to_string(),
            artifacts,
            record_hash,
            signature_hex,
        };
        self.records.push(record.clone());
        record
    }

    pub fn verify(&self) -> bool {
        let mut previous = "genesis".to_string();
        for record in &self.records {
            if record.previous_record_hash != previous { return false; }
            let material = serde_json::to_vec((
                &record.event_id,
                record.collected_at_ms,
                &record.threat_decision_hash,
                &record.telemetry_digest,
                &record.previous_record_hash,
                &record.artifacts,
            )).unwrap_or_default();
            if hex(&Sha256::digest(material)) != record.record_hash { return false; }
            previous = record.record_hash.clone();
        }
        true
    }

    pub fn last_hash(&self) -> &str {
        self.records.last().map(|r| r.record_hash.as_str()).unwrap_or("genesis")
    }
}

pub fn artifact_from_bytes(id: &str, kind: &str, bytes: &[u8], collected_at_ms: u64) -> ForensicArtifact {
    ForensicArtifact {
        artifact_id: id.to_string(),
        kind: kind.to_string(),
        sha256: hex(&Sha256::digest(bytes)),
        collected_at_ms,
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_detects_tampering() {
        let mut ledger = ForensicLedger::default();
        ledger.append("evt-1", 1, "decision-a", "telemetry-a", vec![], None);
        ledger.append("evt-2", 2, "decision-b", "telemetry-b", vec![], None);
        assert!(ledger.verify());
        ledger.records[0].telemetry_digest = "tampered".into();
        assert!(!ledger.verify());
    }

    #[test]
    fn artifact_only_keeps_digest_not_raw_secret() {
        let a = artifact_from_bytes("memory-1", "authorized-sandbox-memory", b"example", 1);
        assert_eq!(a.sha256.len(), 64);
        assert!(!a.sha256.contains("example"));
    }
}
