pub fn require_tpm2(enabled: bool) -> Result<(), &'static str> { if enabled { Ok(()) } else { Err("TPM 2.0 attestation is required for hardware trust") } }
