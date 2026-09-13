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
- For privacy Egress, verify every relay/NAT pool against addresses legitimately assigned by the OS, network operator or relay provider.
- Do not configure or advertise arbitrary source-IP impersonation; ATIBON's Egress policy layer does not rewrite a caller-selected public source IP.

## Egress address model

The privacy path is:

```text
IP interne -> ATIBON -> policy -> relais approuvé -> NAT/proxy
           -> IP d'egress attribuée au relais/fournisseur -> serveur distant
```

ATIBON controls the routing decision and audit record. The actual source-address translation is performed by the network dataplane or relay/provider using its legitimately assigned addresses. The remote server therefore sees the relay/provider egress address; this is not equivalent to making an IP address invisible.

Common Criteria and FIPS files in this repository are readiness controls, not certifications.
