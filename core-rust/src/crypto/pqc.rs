use std::env;

use pyo3::prelude::*;
use thiserror::Error;

#[cfg(feature = "pqc-native")]
use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(feature = "pqc-native")]
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    KeyExport, MlKem768,
};

pub const ML_KEM768_CIPHERTEXT_BYTES: usize = 1088;
pub const ML_KEM768_SHARED_SECRET_BYTES: usize = 32;
pub const ML_KEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const ML_DSA65_SEED_BYTES: usize = 32;
pub const ML_DSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA65_SIGNATURE_BYTES: usize = 3309;

#[pyclass]
#[derive(Debug, Default)]
pub struct PqcFacade;

#[pymethods]
impl PqcFacade {
    #[new]
    fn new() -> Self {
        Self
    }

    fn kem_health(&self) -> bool {
        kem_health()
    }
}

#[derive(Debug, Error)]
pub enum PqcError {
    #[error("PQC native feature is disabled")]
    FeatureDisabled,
    #[error("invalid hexadecimal input")]
    InvalidHex,
    #[error("invalid ML-DSA-65 public key length: expected {expected}, got {actual}")]
    InvalidDsaPublicKeyLength { expected: usize, actual: usize },
    #[error("invalid ML-DSA-65 signature length: expected {expected}, got {actual}")]
    InvalidDsaSignatureLength { expected: usize, actual: usize },
    #[error("invalid ML-DSA-65 seed length: expected {expected}, got {actual}")]
    InvalidDsaSeedLength { expected: usize, actual: usize },
    #[error("missing ATIBON_MLDSA65_SEED_HEX")]
    MissingSigningSeed,
    #[error("invalid ML-DSA-65 signing seed")]
    InvalidSigningSeed,
}

#[allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks)]
fn decode_hex(value: &str) -> Result<Vec<u8>, PqcError> {
    if value.is_empty() || value.len() % 2 != 0 || !value.is_ascii() {
        return Err(PqcError::InvalidHex);
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or(PqcError::InvalidHex)?;
        let lo = (pair[1] as char).to_digit(16).ok_or(PqcError::InvalidHex)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

#[cfg(feature = "pqc-native")]
pub fn sign_barrier(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
    let seed_hex = env::var("ATIBON_MLDSA65_SEED_HEX").map_err(|_| PqcError::MissingSigningSeed)?;
    let seed = decode_hex(&seed_hex)?;
    if seed.len() != ML_DSA65_SEED_BYTES {
        return Err(PqcError::InvalidDsaSeedLength {
            expected: ML_DSA65_SEED_BYTES,
            actual: seed.len(),
        });
    }
    let seed_array: ml_dsa::Seed = seed
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::InvalidSigningSeed)?;
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_array);
    let signature = signing_key.sign(message);
    let public_key = signing_key.verifying_key().encode();
    Ok((signature.encode().to_vec(), public_key.to_vec()))
}

#[cfg(not(feature = "pqc-native"))]
pub fn sign_barrier(_message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
    Err(PqcError::FeatureDisabled)
}

#[cfg(feature = "pqc-native")]
pub fn verify_barrier(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, PqcError> {
    if public_key.len() != ML_DSA65_PUBLIC_KEY_BYTES {
        return Err(PqcError::InvalidDsaPublicKeyLength {
            expected: ML_DSA65_PUBLIC_KEY_BYTES,
            actual: public_key.len(),
        });
    }
    if signature.len() != ML_DSA65_SIGNATURE_BYTES {
        return Err(PqcError::InvalidDsaSignatureLength {
            expected: ML_DSA65_SIGNATURE_BYTES,
            actual: signature.len(),
        });
    }
    let public_key_array: [u8; ML_DSA65_PUBLIC_KEY_BYTES] =
        public_key
            .try_into()
            .map_err(|_| PqcError::InvalidDsaPublicKeyLength {
                expected: ML_DSA65_PUBLIC_KEY_BYTES,
                actual: public_key.len(),
            })?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode((&public_key_array).into());
    let signature_array: [u8; ML_DSA65_SIGNATURE_BYTES] =
        signature
            .try_into()
            .map_err(|_| PqcError::InvalidDsaSignatureLength {
                expected: ML_DSA65_SIGNATURE_BYTES,
                actual: signature.len(),
            })?;
    let signature = ml_dsa::Signature::<MlDsa65>::decode((&signature_array).into())
        .ok_or(PqcError::InvalidHex)?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(not(feature = "pqc-native"))]
pub fn verify_barrier(
    _message: &[u8],
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<bool, PqcError> {
    Err(PqcError::FeatureDisabled)
}

#[cfg(feature = "pqc-native")]
pub fn kem_health() -> bool {
    let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
    let (ciphertext, sender_secret) = ek.encapsulate();
    sender_secret == dk.decapsulate(&ciphertext)
}

#[cfg(not(feature = "pqc-native"))]
pub fn kem_health() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = decode_hex("00aaff10").expect("valid hex");
        assert_eq!(bytes, vec![0, 0xaa, 0xff, 0x10]);
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
        assert!(decode_hex("").is_err());
    }

    #[cfg(feature = "pqc-native")]
    #[test]
    fn ml_dsa65_round_trip_uses_fips204_sizes() {
        let seed = ml_dsa::Seed::default();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let message = b"ATIBON PQC integration test";
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &signature).is_ok());
        assert!(verifying_key.verify(b"tampered", &signature).is_err());
        assert_eq!(
            verifying_key.encode().as_slice().len(),
            ML_DSA65_PUBLIC_KEY_BYTES
        );
        let encoded_sig = signature.encode();
        assert_eq!(encoded_sig.as_slice().len(), ML_DSA65_SIGNATURE_BYTES);
    }

    #[cfg(feature = "pqc-native")]
    #[test]
    fn ml_kem768_round_trip_uses_fips203_sizes() {
        let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
        let (ciphertext, sender_secret) = ek.encapsulate();
        assert_eq!(sender_secret, dk.decapsulate(&ciphertext));
        let encoded_public_key = KeyExport::to_bytes(&ek);
        assert_eq!(
            encoded_public_key.as_slice().len(),
            ML_KEM768_PUBLIC_KEY_BYTES
        );
        assert_eq!(ciphertext.as_slice().len(), ML_KEM768_CIPHERTEXT_BYTES);
        assert_eq!(
            sender_secret.as_slice().len(),
            ML_KEM768_SHARED_SECRET_BYTES
        );
    }
}
