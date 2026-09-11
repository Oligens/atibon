# ATIBON Continuous Evolutionary Defense (CED)

ATIBON's CED loop turns observed defensive telemetry into a bounded policy candidate:

1. **Behavioral ingestion** — timing deltas, request sizes, explored paths and mutation classes are converted into entropy/repetition features.
2. **Behavioral assessment** — a bounded automation score identifies repetitive machine-like exploration. The raw telemetry is also hashed into a 32-byte behavioral vector.
3. **Deceptive graph** — a synthetic API mirror is represented as an isolated graph. It is telemetry-only and is not allowed to reach production assets.
4. **Mutation** — a fail-closed candidate rule is generated and assigned a digest.
5. **Cryptographic authorization** — production barrier publication must be signed with the operator-managed ML-DSA-65 key. ATIBON does not generate a new trust root for every event.
6. **Scoped enforcement** — `atibon-agent` can quarantine a separately supplied, administrator/network-observed IPv4 address through the existing nftables abuse set. Telemetry alone never becomes an unrestricted firewall rule.
7. **Distributed transport** — ML-KEM-768 is integrated as the post-quantum key-establishment primitive. A production control plane should encapsulate a per-node symmetric transport key and then use an authenticated symmetric cipher for the policy payload.

## CLI

```text
atibon-agent --ced-telemetry telemetry.json --ced-dry-run
atibon-agent --ced-telemetry telemetry.json --ced-block-ip 203.0.113.10
```

The first command performs analysis without changing firewall state. The second applies a one-hour quarantine only when the behavioral assessment crosses the automation threshold and the IP is supplied separately.

## PQC

Enable the native backend with:

```text
cargo test -p atibon-core --features pqc-native
```

The backend uses RustCrypto `ml-kem` 0.3.x for ML-KEM-768 (NIST FIPS 203) and `ml-dsa` 0.1.x for ML-DSA-65 (NIST FIPS 204).

Set `ATIBON_MLDSA65_SEED_HEX` from a secret-management system before signing barriers. Never commit the seed to Git, telemetry, logs, or frontend code.

## Security boundary

CED is adaptive, but it is intentionally **not self-authorizing**. Detection data can propose a new defense; cryptographic policy authorization, consensus, and scoped network context remain separate controls. This prevents a poisoned telemetry stream from turning into a global deny rule.

PQC protects key establishment/signature operations against currently known classical and anticipated quantum attacks; it does not make the whole firewall automatically quantum-proof, and the selected Rust implementations still require independent security review before a high-assurance production qualification.
