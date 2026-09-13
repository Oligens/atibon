# ATIBON Production Readiness

## Implemented in the repository

- Rust native core packaged through PyO3/Maturin.
- Bounded DPI with fail-closed packet-size limits.
- Bounded connection tracking and a fail-closed flow rule engine.
- Append-only JSONL security audit primitive.
- Governed Egress decision path with Shadow/Enforce modes and approved-relay selection.
- Linux nftables enforcement agent with pre-apply validation.
- Hardened systemd unit and a reviewable host ruleset.
- Kubernetes default-deny network policy and non-root/read-only container hardening.
- Front-end source-probing interception and honeypot presentation.
- CI for Python wheels, Rust tests, formatting, Clippy and front-end type/build checks.
- CodeQL, RustSec dependency audit and dependency-review workflow.
- Strict Ed25519 model artifact verification.
- TPM 2.0 quote generation procedure.
- Strict mTLS policy declaring ML-KEM/ML-DSA requirements.

## Egress network truth

ATIBON does not provide arbitrary public-IP impersonation. The privacy path is:

```text
IP interne -> ATIBON -> Reputation -> Risk/Policy
           -> Approved Relay -> NAT/Proxy
           -> IP d'egress attribuée au relais/fournisseur
           -> serveur distant -> Audit
```

The Egress policy layer does not accept a requested source IP and does not perform source-IP spoofing. The actual NAT/source-address selection must be implemented by the OS/network dataplane or relay provider using addresses legitimately assigned to that environment. See `docs/EGRESS.md`.

## Remaining environment-dependent activation

These items cannot honestly be marked operational without the target environment:

1. eBPF/Aya or AF_XDP packet capture must be compiled and attached on the target kernel/NIC.
2. PKCS#11 must be pointed at the real HSM library, slot and policy.
3. TPM attestation must be enrolled against a trusted verifier and expected PCR profile.
4. A production PQC provider must be selected and validated for the exact platform.
5. The service-mesh implementation must consume the mTLS policy and rotate workload certificates.
6. Model signing keys must be held outside the repository, preferably in the deployment signing/HSM infrastructure.
7. Every server role must have a reviewed nftables allowlist before enforcement.
8. Every production Egress relay/NAT pool must be verified against the provider/OS-assigned addresses before enforcement; Shadow Mode should be used to validate the observed route first.

ATIBON is therefore operational as a Linux enforcement baseline now, but a claim of 100% protection, invisible IP addresses, arbitrary source-IP impersonation, or certification would be incorrect until the environment-specific integrations are exercised and validated.
