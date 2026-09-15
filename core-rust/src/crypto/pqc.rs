use pyo3::prelude::*;

const ML_DSA65_SEED_BYTES: usize = 32;
const ML_DSA65_PUBLIC_KEY_BYTES: usize = 1952;
const ML_DSA65_SIGNATURE_BYTES: usize = 3309;

#[pyclass]
pub struct PqcFacade;

impl Default for PqcFacade {
    fn default() -> Self { Self }
}

#[pymethods]
impl PqcFacade {
    #[new]
    pub fn new() -> Self { Self }
    pub fn backend(&self) -> &'static str { if cfg!(feature = "pqc-native") { "rustcrypto-fips203-fips204" } else { "unconfigured" } }
    pub fn encapsulation_required(&self) -> bool { true }
    pub fn signature_required(&self) -> bool { true }

    pub fn sign_barrier(&self, digest_hex: &str) -> PyResult<String> {
        #[cfg(feature = "pqc-native")]
        {
            use ml_dsa::{MlDsa65, Signer, SigningKey};
            let seed_hex = std::env::var("ATIBON_MLDSA65_SEED_HEX").map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("ATIBON_MLDSA65_SEED_HEX is not configured"))?;
            let seed = decode_hex(&seed_hex).map_err(pyo3::exceptions::PyValueError::new_err)?;
            if seed.len() != ML_DSA65_SEED_BYTES { return Err(pyo3::exceptions::PyValueError::new_err("ML-DSA-65 seed must be exactly 32 bytes")); }
            let seed_array: [u8; ML_DSA65_SEED_BYTES] = seed.as_slice().try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid ML-DSA seed length"))?;
            let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_array.into());
            let sig = signing_key.sign(digest_hex.as_bytes());
            let vk = signing_key.verifying_key();
            Ok(serde_json::json!({"algorithm":"ML-DSA-65","message":digest_hex,"public_key_hex":hex(vk.encode().as_ref()),"signature_hex":hex(sig.encode().as_ref())}).to_string())
        }
        #[cfg(not(feature = "pqc-native"))]
        { let _ = digest_hex; Err(pyo3::exceptions::PyRuntimeError::new_err("native PQC backend is disabled; build with --features pqc-native")) }
    }

    pub fn verify_barrier(&self, message: &str, public_key_hex: &str, signature_hex: &str) -> PyResult<bool> {
        #[cfg(feature = "pqc-native")]
        {
            use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Verifier, VerifyingKey};
            let pk = decode_hex(public_key_hex).map_err(pyo3::exceptions::PyValueError::new_err)?;
            let sig_bytes = decode_hex(signature_hex).map_err(pyo3::exceptions::PyValueError::new_err)?;
            let pk_array: [u8; ML_DSA65_PUBLIC_KEY_BYTES] = pk.as_slice().try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("ML-DSA-65 public key must be exactly 1952 bytes"))?;
            let sig_array: [u8; ML_DSA65_SIGNATURE_BYTES] = sig_bytes.as_slice().try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("ML-DSA-65 signature must be exactly 3309 bytes"))?;
            let encoded_pk: EncodedVerifyingKey<MlDsa65> = pk_array.into();
            let encoded_sig: EncodedSignature<MlDsa65> = sig_array.into();
            let vk = VerifyingKey::<MlDsa65>::decode(&encoded_pk);
            let sig = ml_dsa::Signature::<MlDsa65>::decode(&encoded_sig).ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid ML-DSA signature encoding"))?;
            Ok(vk.verify(message.as_bytes(), &sig).is_ok())
        }
        #[cfg(not(feature = "pqc-native"))]
        { let _ = (message, public_key_hex, signature_hex); Err(pyo3::exceptions::PyRuntimeError::new_err("native PQC backend is disabled")) }
    }

    pub fn kem_health(&self) -> PyResult<String> {
        #[cfg(feature = "pqc-native")]
        {
            use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
            use ml_kem::MlKem768;
            let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
            let (ct, send) = ek.encapsulate();
            let recv = dk.decapsulate(&ct);
            if send != recv { return Err(pyo3::exceptions::PyRuntimeError::new_err("ML-KEM-768 round trip failed")); }
            Ok(serde_json::json!({"algorithm":"ML-KEM-768","status":"ok","ciphertext_bytes":ct.as_slice().len(),"shared_secret_bytes":32}).to_string())
        }
        #[cfg(not(feature = "pqc-native"))]
        Err(pyo3::exceptions::PyRuntimeError::new_err("native PQC backend is disabled"))
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if !input.is_ascii() { return Err("hex input must contain only ASCII hexadecimal characters".into()); }
    if !input.len().is_multiple_of(2) { return Err("hex input must have even length".into()); }
    (0..input.len()).step_by(2).map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|_| "invalid hex".to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_round_trip_is_canonical_lowercase() { let bytes = [0x00, 0xAB, 0xFF, 0x10]; assert_eq!(hex(&bytes), "00abff10"); assert_eq!(decode_hex("00ABff10").unwrap(), bytes); }
    #[test]
    fn malformed_hex_is_rejected_without_panicking() { assert!(decode_hex("abc").is_err()); assert!(decode_hex("zz").is_err()); assert!(decode_hex("éé").is_err()); }
    #[test]
    fn fips203_204_size_constants_match_selected_parameter_sets() { assert_eq!(ML_DSA65_SEED_BYTES, 32); assert_eq!(ML_DSA65_PUBLIC_KEY_BYTES, 1952); assert_eq!(ML_DSA65_SIGNATURE_BYTES, 3309); }
    #[cfg(feature = "pqc-native")]
    #[test]
    fn ml_dsa65_signature_round_trip_and_tamper_rejection() {
        use ml_dsa::{MlDsa65, Signer, SigningKey, Verifier};
        let signing_key = SigningKey::<MlDsa65>::from_seed(&[0x42u8; ML_DSA65_SEED_BYTES].into());
        let message = b"ATIBON PQC integration test";
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &signature).is_ok());
        assert!(verifying_key.verify(b"tampered", &signature).is_err());
        assert_eq!(verifying_key.encode().as_ref().len(), ML_DSA65_PUBLIC_KEY_BYTES);
        assert_eq!(signature.encode().as_ref().len(), ML_DSA65_SIGNATURE_BYTES);
    }
    #[cfg(feature = "pqc-native")]
    #[test]
    fn ml_kem768_round_trip_uses_fips203_sizes() {
        use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
        use ml_kem::MlKem768;
        let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
        let (ciphertext, sender_secret) = ek.encapsulate();
        assert_eq!(sender_secret, dk.decapsulate(&ciphertext));
        assert_eq!(ek.to_bytes().as_ref().len(), 1184);
        assert_eq!(ciphertext.as_ref().len(), 1088);
        assert_eq!(sender_secret.as_ref().len(), 32);
    }
}
