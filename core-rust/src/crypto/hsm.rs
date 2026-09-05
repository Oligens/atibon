use sha2::{Digest, Sha256};

pub fn key_handle(namespace: &str, object: &str) -> String { format!("atibon-hsm:{namespace}:{:x}", Sha256::digest(object.as_bytes())) }

pub fn require_external_hsm(enabled: bool) -> Result<(), &'static str> { if enabled { Ok(()) } else { Err("external HSM/PKCS#11 provider is required for production key custody") } }
