# ATIBON Security Policy

ATIBON is a defensive security component. Production deployments must treat the Rust core, enforcement policy, model artifacts and cryptographic key custody as security-sensitive assets.

Production requirements:
- Review and validate nftables rules before enforcement.
- Explicitly allowlist remote administration and application ports.
- Sign and verify model artifacts before activation.
- Use external HSM/PKCS#11 key custody where the threat model requires it.
- Enable TPM 2.0 attestation on supported hosts.
- Scope and rotate mTLS identities per service.
- Ship audit logs to an integrity-protected destination.
- Start new deployments in shadow mode and measure false positives before blocking.

Common Criteria and FIPS files in this repository are readiness controls, not certifications.
