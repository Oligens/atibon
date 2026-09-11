use pyo3::prelude::*;

#[pyclass]
pub struct PqcFacade;

#[pymethods]
impl PqcFacade {
    #[new]
    pub fn new() -> Self { Self }

    pub fn backend(&self) -> &'static str {
        if cfg!(feature = "pqc-native") { "rustcrypto-fips203-fips204" } else { "unconfigured" }
    }

    pub fn encapsulation_required(&self) -> bool { true }
    pub fn signature_required(&self) -> bool { true }

    /// Signs a barrier digest using an operator-managed ML-DSA-65 seed.
    /// The seed is read from ATIBON_MLDSA65_SEED_HEX and is never returned.
    pub fn sign_barrier(&self, digest_hex: &str) -> PyResult<String> {
        #[cfg(feature = "pqc-native")]
        {
            use ml_dsa::{KeyExport, KeyInit, MlDsa65, Signer, SigningKey};
            let seed_hex = std::env::var("ATIBON_MLDSA65_SEED_HEX")
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("ATIBON_MLDSA65_SEED_HEX is not configured"))?;
            let seed = decode_hex(&seed_hex).map_err(pyo3::exceptions::PyValueError::new_err)?;
            if seed.len() != 32 { return Err(pyo3::exceptions::PyValueError::new_err("ML-DSA-65 seed must be exactly 32 bytes")); }
            let sk = SigningKey::<MlDsa65>::new_from_slice(&seed)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid ML-DSA seed: {e}")))?;
            let sig = sk.sign(digest_hex.as_bytes());
            let vk = sk.verifying_key();
            Ok(serde_json::json!({
                "algorithm": "ML-DSA-65",
                "message": digest_hex,
                "public_key_hex": hex(vk.to_bytes().as_ref()),
                "signature_hex": hex(sig.to_bytes().as_ref())
            }).to_string())
        }
        #[cfg(not(feature = "pqc-native"))]
        {
            let _ = digest_hex;
            Err(pyo3::exceptions::PyRuntimeError::new_err("native PQC backend is disabled; build with --features pqc-native"))
        }
    }

    pub fn verify_barrier(&self, message: &str, public_key_hex: &str, signature_hex: &str) -> PyResult<bool> {
        #[cfg(feature = "pqc-native")]
        {
            use ml_dsa::{KeyInit, MlDsa65, Verifier, VerifyingKey};
            let pk = decode_hex(public_key_hex).map_err(pyo3::exceptions::PyValueError::new_err)?;
            let sig_bytes = decode_hex(signature_hex).map_err(pyo3::exceptions::PyValueError::new_err)?;
            let vk = VerifyingKey::<MlDsa65>::new_from_slice(&pk)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid ML-DSA key: {e}")))?;
            let sig = <ml_dsa::Signature<MlDsa65> as core::convert::TryFrom<&[u8]>>::try_from(sig_bytes.as_slice())
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid ML-DSA signature: {e}")))?;
            Ok(vk.verify(message.as_bytes(), &sig).is_ok())
        }
        #[cfg(not(feature = "pqc-native"))]
        {
            let _ = (message, public_key_hex, signature_hex);
            Err(pyo3::exceptions::PyRuntimeError::new_err("native PQC backend is disabled"))
        }
    }

    pub fn kem_health(&self) -> PyResult<String> {
        #[cfg(feature = "pqc-native")]
        {
            use ml_kem::{kem::{Decapsulate, Encapsulate, Kem}, MlKem768};
            let (dk, ek) = MlKem768::generate_keypair();
            let (ct, send) = ek.encapsulate();
            let recv = dk.decapsulate(&ct);
            if send != recv { return Err(pyo3::exceptions::PyRuntimeError::new_err("ML-KEM-768 round trip failed")); }
            Ok(serde_json::json!({
                "algorithm": "ML-KEM-768",
                "status": "ok",
                "ciphertext_bytes": ct.as_ref().len(),
                "shared_secret_bytes": send.as_ref().len()
            }).to_string())
        }
        #[cfg(not(feature = "pqc-native"))]
        Err(pyo3::exceptions::PyRuntimeError::new_err("native PQC backend is disabled"))
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 { return Err("hex input must have even length".into()); }
    (0..input.len()).step_by(2).map(|i| u8::from_str_radix(&input[i..i+2], 16).map_err(|_| "invalid hex".to_string())).collect()
}
