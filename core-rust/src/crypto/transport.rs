use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROTOCOL: &str = "ATIBON-BARRIER/2";
const KEM_ALGORITHM: &str = "ML-KEM-768";
const AEAD_ALGORITHM: &str = "ChaCha20-Poly1305";
const SIGNATURE_ALGORITHM: &str = "ML-DSA-65";
const CLOCK_SKEW_MS: u64 = 300_000;

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
    pub sender_node_id: String,
    pub recipient_node_id: String,
    pub key_id: String,
    pub policy_id: String,
    pub version: u64,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub kem_algorithm: String,
    pub aead_algorithm: String,
    pub signature_algorithm: String,
    pub kem_ciphertext_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub policy_digest: String,
    pub consensus_hash: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BarrierAcceptance {
    pub accepted: bool,
    pub reason: String,
    pub policy_digest: String,
    pub consensus_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenedBarrier {
    pub accepted: bool,
    pub reason: String,
    pub policy: BarrierPolicy,
    pub policy_digest: String,
    pub consensus_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct BarrierHeader<'a> {
    protocol: &'a str,
    sender_node_id: &'a str,
    recipient_node_id: &'a str,
    key_id: &'a str,
    policy_id: &'a str,
    version: u64,
    epoch: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    kem_algorithm: &'a str,
    aead_algorithm: &'a str,
    signature_algorithm: &'a str,
    policy_digest: &'a str,
    consensus_hash: &'a str,
}

pub fn canonical_policy_bytes(policy: &BarrierPolicy) -> Result<Vec<u8>, String> {
    serde_json::to_vec(policy).map_err(|e| format!("policy serialization failed: {e}"))
}

pub fn policy_digest(policy: &BarrierPolicy) -> Result<String, String> {
    Ok(hex(&Sha256::digest(canonical_policy_bytes(policy)?)))
}

fn header_bytes(envelope: &BarrierEnvelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&BarrierHeader {
        protocol: &envelope.protocol,
        sender_node_id: &envelope.sender_node_id,
        recipient_node_id: &envelope.recipient_node_id,
        key_id: &envelope.key_id,
        policy_id: &envelope.policy_id,
        version: envelope.version,
        epoch: envelope.epoch,
        issued_at_ms: envelope.issued_at_ms,
        expires_at_ms: envelope.expires_at_ms,
        kem_algorithm: &envelope.kem_algorithm,
        aead_algorithm: &envelope.aead_algorithm,
        signature_algorithm: &envelope.signature_algorithm,
        policy_digest: &envelope.policy_digest,
        consensus_hash: &envelope.consensus_hash,
    })
    .map_err(|e| format!("header serialization failed: {e}"))
}

fn transcript(envelope: &BarrierEnvelope) -> Result<Vec<u8>, String> {
    let mut out = header_bytes(envelope)?;
    out.extend_from_slice(envelope.kem_ciphertext_hex.as_bytes());
    out.extend_from_slice(envelope.nonce_hex.as_bytes());
    out.extend_from_slice(envelope.ciphertext_hex.as_bytes());
    Ok(out)
}

pub fn validate_envelope(
    envelope: &BarrierEnvelope,
    now_ms: u64,
    current_epoch: u64,
    current_version: u64,
) -> Result<BarrierAcceptance, String> {
    if envelope.protocol != PROTOCOL { return Err("unsupported barrier protocol".into()); }
    if envelope.kem_algorithm != KEM_ALGORITHM { return Err("unsupported KEM".into()); }
    if envelope.aead_algorithm != AEAD_ALGORITHM { return Err("unsupported AEAD".into()); }
    if envelope.signature_algorithm != SIGNATURE_ALGORITHM { return Err("unsupported signature algorithm".into()); }
    if envelope.sender_node_id.trim().is_empty() { return Err("missing sender node id".into()); }
    if envelope.recipient_node_id.trim().is_empty() { return Err("missing recipient node id".into()); }
    if envelope.key_id.trim().is_empty() { return Err("missing recipient key id".into()); }
    if envelope.policy_id.trim().is_empty() { return Err("missing policy id".into()); }
    if envelope.epoch < current_epoch { return Err("stale policy epoch".into()); }
    if envelope.version <= current_version { return Err("stale policy version".into()); }
    if envelope.issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) { return Err("barrier issued too far in the future".into()); }
    if envelope.expires_at_ms <= now_ms || envelope.expires_at_ms <= envelope.issued_at_ms { return Err("expired or invalid barrier lifetime".into()); }
    if !is_hex(&envelope.kem_ciphertext_hex)
        || !is_hex(&envelope.nonce_hex)
        || !is_hex(&envelope.ciphertext_hex)
        || !is_hex(&envelope.policy_digest)
        || !is_hex(&envelope.consensus_hash)
        || !is_hex(&envelope.signer_public_key_hex)
        || !is_hex(&envelope.signature_hex) { return Err("malformed hexadecimal envelope field".into()); }
    if envelope.policy_digest.len() != 64 || envelope.consensus_hash.len() != 64 { return Err("invalid digest length".into()); }
    if envelope.nonce_hex.len() != 24 { return Err("ChaCha20-Poly1305 nonce must be 12 bytes".into()); }
    if envelope.kem_ciphertext_hex.len() != 2176 { return Err("ML-KEM-768 ciphertext must be 1088 bytes".into()); }
    Ok(BarrierAcceptance {
        accepted: false,
        reason: "structural validation passed; trusted ML-DSA signature and ML-KEM decryption required".into(),
        policy_digest: envelope.policy_digest.clone(),
        consensus_hash: envelope.consensus_hash.clone(),
    })
}

#[cfg(feature = "pqc-native")]
pub fn seal_barrier(
    policy: &BarrierPolicy,
    sender_node_id: &str,
    recipient_node_id: &str,
    key_id: &str,
    recipient_kem_public_key_hex: &str,
    consensus_hash: &str,
    issued_at_ms: u64,
) -> Result<BarrierEnvelope, String> {
    use chacha20poly1305::{aead::{Aead, Generate, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
    use hkdf::Hkdf;
    use ml_dsa::{KeyExport, KeyInit as DsaKeyInit, MlDsa65, Signer, SigningKey};
    use ml_kem::{kem::{Encapsulate, Kem}, Encoded, KemCore, MlKem768};

    let digest = policy_digest(policy)?;
    if !is_fixed_hex(consensus_hash, 32) { return Err("consensus hash must be 32-byte hex".into()); }
    let public_key = decode_hex(recipient_kem_public_key_hex)?;
    if public_key.len() != 1184 { return Err("ML-KEM-768 public key must be 1184 bytes".into()); }
    let encoded = <Encoded<<MlKem768 as KemCore>::EncapsulationKey>>::try_from(public_key.as_slice())
        .map_err(|_| "invalid ML-KEM-768 public key encoding".to_string())?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&encoded);
    let (kem_ct, shared_secret) = ek.encapsulate();

    let mut salt_input = Vec::with_capacity(digest.len() + consensus_hash.len());
    salt_input.extend_from_slice(digest.as_bytes());
    salt_input.extend_from_slice(consensus_hash.as_bytes());
    let salt = Sha256::digest(&salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_ref());
    let mut aead_key = [0u8; 32];
    hk.expand(b"ATIBON-BARRIER/2|ML-KEM-768|CHACHA20-POLY1305", &mut aead_key)
        .map_err(|_| "HKDF expansion failed".to_string())?;

    let nonce = Nonce::generate();
    let mut envelope = BarrierEnvelope {
        protocol: PROTOCOL.into(),
        sender_node_id: sender_node_id.into(),
        recipient_node_id: recipient_node_id.into(),
        key_id: key_id.into(),
        policy_id: policy.policy_id.clone(),
        version: policy.version,
        epoch: policy.epoch,
        issued_at_ms,
        expires_at_ms: policy.expires_at_ms,
        kem_algorithm: KEM_ALGORITHM.into(),
        aead_algorithm: AEAD_ALGORITHM.into(),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        kem_ciphertext_hex: hex(kem_ct.as_ref()),
        nonce_hex: hex(nonce.as_ref()),
        ciphertext_hex: String::new(),
        policy_digest: digest,
        consensus_hash: consensus_hash.into(),
        signer_public_key_hex: String::new(),
        signature_hex: String::new(),
    };
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key).map_err(|_| "invalid AEAD key".to_string())?;
    let aad = header_bytes(&envelope)?;
    let plaintext = canonical_policy_bytes(policy)?;
    let ciphertext = cipher.encrypt(&nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| "authenticated encryption failed".to_string())?;
    envelope.ciphertext_hex = hex(&ciphertext);

    let seed_hex = std::env::var("ATIBON_MLDSA65_SEED_HEX")
        .map_err(|_| "ATIBON_MLDSA65_SEED_HEX is not configured".to_string())?;
    let seed = decode_hex(&seed_hex)?;
    if seed.len() != 32 { return Err("ML-DSA-65 seed must be exactly 32 bytes".into()); }
    let signing_key = SigningKey::<MlDsa65>::new_from_slice(&seed)
        .map_err(|e| format!("invalid ML-DSA seed: {e}"))?;
    let signature = signing_key.sign(&transcript(&envelope)?);
    envelope.signer_public_key_hex = hex(signing_key.verifying_key().to_bytes().as_ref());
    envelope.signature_hex = hex(signature.to_bytes().as_ref());
    Ok(envelope)
}

#[cfg(not(feature = "pqc-native"))]
pub fn seal_barrier(
    _policy: &BarrierPolicy, _sender_node_id: &str, _recipient_node_id: &str,
    _key_id: &str, _recipient_kem_public_key_hex: &str, _consensus_hash: &str, _issued_at_ms: u64,
) -> Result<BarrierEnvelope, String> {
    Err("native PQC transport is disabled; build with --features pqc-native".into())
}

#[cfg(feature = "pqc-native")]
pub fn open_barrier(
    envelope: &BarrierEnvelope,
    recipient_kem_private_key_hex: &str,
    trusted_signer_public_key_hex: &str,
    now_ms: u64,
    current_epoch: u64,
    current_version: u64,
) -> Result<OpenedBarrier, String> {
    use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
    use hkdf::Hkdf;
    use ml_dsa::{KeyInit as DsaKeyInit, MlDsa65, Signature, Verifier, VerifyingKey};
    use ml_kem::{kem::{Decapsulate, Kem}, Encoded, KemCore, MlKem768};

    validate_envelope(envelope, now_ms, current_epoch, current_version)?;
    let trusted = decode_hex(trusted_signer_public_key_hex)?;
    if trusted.is_empty() || hex(&trusted) != envelope.signer_public_key_hex { return Err("untrusted ML-DSA signer key".into()); }
    let verifying_key = VerifyingKey::<MlDsa65>::new_from_slice(&trusted)
        .map_err(|e| format!("invalid trusted ML-DSA key: {e}"))?;
    let signature_bytes = decode_hex(&envelope.signature_hex)?;
    let signature = <Signature<MlDsa65> as TryFrom<&[u8]>>::try_from(signature_bytes.as_slice())
        .map_err(|e| format!("invalid ML-DSA signature: {e}"))?;
    verifying_key.verify(&transcript(envelope)?, &signature)
        .map_err(|_| "ML-DSA signature verification failed".to_string())?;

    let private_key = decode_hex(recipient_kem_private_key_hex)?;
    if private_key.len() != 2400 { return Err("ML-KEM-768 decapsulation key must be 2400 bytes".into()); }
    let dk_encoded = <Encoded<<MlKem768 as KemCore>::DecapsulationKey>>::try_from(private_key.as_slice())
        .map_err(|_| "invalid ML-KEM-768 decapsulation key encoding".to_string())?;
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_encoded);
    let kem_ct_bytes = decode_hex(&envelope.kem_ciphertext_hex)?;
    let kem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes.as_slice())
        .map_err(|_| "invalid ML-KEM-768 ciphertext".to_string())?;
    let shared_secret = dk.decapsulate(&kem_ct);

    let mut salt_input = Vec::with_capacity(envelope.policy_digest.len() + envelope.consensus_hash.len());
    salt_input.extend_from_slice(envelope.policy_digest.as_bytes());
    salt_input.extend_from_slice(envelope.consensus_hash.as_bytes());
    let salt = Sha256::digest(&salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_ref());
    let mut aead_key = [0u8; 32];
    hk.expand(b"ATIBON-BARRIER/2|ML-KEM-768|CHACHA20-POLY1305", &mut aead_key)
        .map_err(|_| "HKDF expansion failed".to_string())?;

    let nonce_bytes = decode_hex(&envelope.nonce_hex)?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| "invalid ChaCha20-Poly1305 nonce".to_string())?;
    let ciphertext = decode_hex(&envelope.ciphertext_hex)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key).map_err(|_| "invalid AEAD key".to_string())?;
    let aad = header_bytes(envelope)?;
    let plaintext = cipher.decrypt(&nonce, Payload { msg: &ciphertext, aad: &aad })
        .map_err(|_| "authenticated decryption failed".to_string())?;
    let policy: BarrierPolicy = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("decrypted policy is invalid: {e}"))?;
    let digest = policy_digest(&policy)?;
    if digest != envelope.policy_digest { return Err("decrypted policy digest mismatch".into()); }
    if policy.policy_id != envelope.policy_id || policy.version != envelope.version
        || policy.epoch != envelope.epoch || policy.expires_at_ms != envelope.expires_at_ms {
        return Err("decrypted policy metadata mismatch".into());
    }
    Ok(OpenedBarrier {
        accepted: true,
        reason: "ML-DSA signature, ML-KEM-768 decapsulation, AEAD authentication and policy binding verified".into(),
        policy,
        policy_digest: digest,
        consensus_hash: envelope.consensus_hash.clone(),
    })
}

#[cfg(not(feature = "pqc-native"))]
pub fn open_barrier(
    _envelope: &BarrierEnvelope, _recipient_kem_private_key_hex: &str,
    _trusted_signer_public_key_hex: &str, _now_ms: u64, _current_epoch: u64, _current_version: u64,
) -> Result<OpenedBarrier, String> {
    Err("native PQC transport is disabled; build with --features pqc-native".into())
}

fn is_fixed_hex(value: &str, bytes: usize) -> bool { is_hex(value) && value.len() == bytes * 2 }
fn is_hex(value: &str) -> bool { !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()) }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 { return Err("hex input must have even length".into()); }
    (0..input.len()).step_by(2).map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|_| "invalid hex".to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BarrierPolicy {
        BarrierPolicy {
            policy_id: "ced-test".into(), version: 2, epoch: 4, expires_at_ms: 9_999,
            action: "quarantine".into(), scope: "ipv4:203.0.113.10".into(), rule_digest: "aa".repeat(32),
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
        let envelope = BarrierEnvelope {
            protocol: PROTOCOL.into(), sender_node_id: "node-a".into(), recipient_node_id: "node-b".into(),
            key_id: "kem-b-v1".into(), policy_id: p.policy_id.clone(), version: p.version, epoch: p.epoch,
            issued_at_ms: 1, expires_at_ms: p.expires_at_ms, kem_algorithm: KEM_ALGORITHM.into(),
            aead_algorithm: AEAD_ALGORITHM.into(), signature_algorithm: SIGNATURE_ALGORITHM.into(),
            kem_ciphertext_hex: "aa".repeat(1088), nonce_hex: "bb".repeat(12), ciphertext_hex: "cc".repeat(32),
            policy_digest: policy_digest(&p).unwrap(), consensus_hash: "dd".repeat(32),
            signer_public_key_hex: "ee".repeat(32), signature_hex: "ff".repeat(32),
        };
        assert!(validate_envelope(&envelope, 1_000, 4, 2).is_err());
    }
}
