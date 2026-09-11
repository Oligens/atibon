# ATIBON Continuous Evolutionary Defense (CED)

ATIBON's CED loop turns observed defensive telemetry into a bounded policy candidate:

1. **Behavioral ingestion** — timing deltas, request sizes, explored paths and mutation classes are converted into entropy/repetition features.
2. **Behavioral assessment** — a bounded automation score identifies repetitive machine-like exploration. The raw telemetry is also hashed into a 32-byte behavioral vector.
3. **Deceptive graph** — a synthetic API mirror is represented as an isolated graph. It is telemetry-only and is not allowed to reach production assets.
4. **Mutation** — a fail-closed candidate rule is generated and assigned a digest.
5. **Quorum authorization** — the candidate is proposed to `HoneyBadgerState`. The configured quorum must be reached before a transport envelope is created. The resulting consensus state hash is bound into the envelope.
6. **Post-quantum authorization** — the committed barrier is signed with the operator-managed ML-DSA-65 key. The receiver accepts only a configured trusted signing key.
7. **Confidential transport** — the policy is encrypted with ChaCha20-Poly1305 using a fresh AEAD key derived through HKDF-SHA-256 from an ML-KEM-768 shared secret. The ML-KEM ciphertext is per-envelope and targeted to the recipient node's public key.
8. **Receiver validation** — the recipient checks protocol, node IDs, key ID, epoch, monotonically increasing version, clock skew, expiry and digest shape; verifies ML-DSA before decrypting; decapsulates ML-KEM-768; authenticates/decrypts the policy; then recomputes the policy digest and checks all bound metadata.
9. **Scoped enforcement** — `atibon-agent` can quarantine a separately supplied, administrator/network-observed IPv4 address through the existing nftables abuse set. Telemetry alone never becomes an unrestricted firewall rule.

## Multidimensional threat matrix

CED additionally evaluates layer-penetration velocity, payload convergence, behavioral automation and trusted PQC integrity events. Three or more layers reached inside the configured critical window, high payload similarity combined with low-entropy behavior, or a trusted cryptographic integrity violation can escalate a decision to critical containment. A critical decision produces a permanent/manual-release containment plan, freezes forensic evidence and creates a vaccination candidate; it does not directly mutate production firewall state.

## Multi-agent adaptive simulation (MARL)

`adaptive.rs` provides a bounded Red/Blue co-evolution loop for defensive simulation. The Red agent can select only synthetic probe classes (`ATIBON-SIMULATION-ONLY`); it does not generate exploit payloads or execute attacks. The Blue agent updates a bounded posterior risk estimate and selects `observe`, `adaptive_decoy`, or `isolate_and_rotate`. This is a simulation/training primitive, not an autonomous offensive agent.

Python API:

```python
episode = engine.marl_simulate(b"training-seed", prior_risk=0.5)
```

The episode contains the synthetic Red action, Bayesian-style posterior risk, Blue barrier candidate, confidence and bounded reward. A production training system can replay these episodes without exposing production assets to the Red agent.

## Semantic MTD

Semantic Moving Target Defense generates deterministic versioned aliases for internal application routes, JSON fields and internal headers while retaining a canonical-to-variant mapping for a compatibility layer. The generated variant is identified by a digest and version.

```python
variant = engine.semantic_mtd(
    b"rotation-seed",
    version=12,
    fields=["id", "payload", "timestamp"],
)
```

The current implementation generates the variant contract and aliases. Integration with a specific HTTP framework/API gateway should apply the mapping only to internal contracts and preserve a stable public API for legitimate clients.

## Defensive topology optimization

A bounded simulated-annealing routine evaluates candidate combinations of defensive rules, micro-segments and honeypot routes using a confusion-versus-latency objective. The routine is capped at 4096 iterations and returns a candidate topology only; it never writes nftables, routing or mTLS configuration itself.

```python
candidate = engine.optimize_defensive_topology(b"topology-seed", iterations=256)
```

The candidate must pass the existing authorization/quorum pipeline before deployment. The implementation should be benchmarked on target hardware before treating a sub-5 ms objective as a production guarantee.

## Barrier propagation flow

```text
CED telemetry
    |
    v
multidimensional threat matrix
    |
    +---- normal/elevated -> adaptive observation
    |
    +---- critical -> containment + forensic freeze + vaccination candidate
    |
    v
bounded policy candidate
    |
    v
canonical policy JSON -> SHA-256 policy digest
    |
    v
ATIBON quorum (HoneyBadgerState)
    |
    +---- rejected -> STOP
    |
    +---- accepted -> consensus state hash
                         |
                         v
                 ML-DSA-65 signature
                         |
                         v
                 ML-KEM-768 encapsulation
                         |
                         v
              HKDF-SHA-256 -> 32-byte key
                         |
                         v
             ChaCha20-Poly1305 AEAD
                         |
                         v
                  BarrierEnvelope
                         |
                         v
              target ATIBON node
                         |
              signature verification
                         |
              ML-KEM-768 decapsulation
                         |
                 AEAD authentication
                         |
                 policy re-validation
                         |
                         v
                  ACCEPT / ENFORCE
```

## Python API

`AtibonEngine` defaults to a quorum of **2**. A one-node lab deployment can explicitly configure `quorum=1`; production clusters should use a quorum appropriate to the trusted node set.

```python
engine = AtibonEngine(quorum=2)

episode = engine.marl_simulate(b"seed", prior_risk=0.4)
variant = engine.semantic_mtd(b"rotation", 7, ["id", "payload"])
topology = engine.optimize_defensive_topology(b"topology", 256)

# A topology or vaccination candidate must still enter the quorum path.
envelope = engine.commit_and_seal_barrier(
    policy=candidate_policy,
    sender_node_id="atibon-a",
    recipient_node_id="atibon-b",
    key_id="node-b-kem-v1",
    recipient_kem_public_key_hex=node_b_mlkem_public_key,
    approvals=2,
    issued_at_ms=now_ms,
)
```

The important invariant is that `commit_and_seal_barrier()` calls consensus first. If approvals are below the configured quorum, it raises and **does not create a cryptographic envelope**.

## Key handling

- `ATIBON_MLDSA65_SEED_HEX` is used only by the current software signing adapter and must come from a secret-management system. Never commit it to Git, telemetry, logs, or frontend code.
- ML-KEM-768 recipient public keys may be distributed as node registration material.
- ML-KEM decapsulation keys are private node secrets and should be moved to the existing HSM/TPM abstraction before high-assurance production use. The Python API must not persist private keys.
- The receiver must pin the expected ML-DSA public key; an envelope's embedded public key is an identifier, not a trust decision.

## CLI

```text
atibon-agent --ced-telemetry telemetry.json --ced-dry-run
atibon-agent --ced-telemetry telemetry.json --ced-block-ip 203.0.113.10
```

The first command performs analysis without changing firewall state. The second applies a one-hour quarantine only when the behavioral assessment crosses the automation threshold and the IP is supplied separately.

## PQC verification

Enable the native backend with:

```text
cargo test -p atibon-core --features pqc-native
cargo check -p atibon-core --features pqc-native --bin atibon-agent
cargo clippy -p atibon-core --features pqc-native --all-targets -- -D warnings
```

The transport uses RustCrypto `ml-kem` 0.3.2 for ML-KEM-768 (NIST FIPS 203), `ml-dsa` 0.1.1 for ML-DSA-65 (NIST FIPS 204), HKDF-SHA-256 for key derivation, and ChaCha20-Poly1305 for authenticated encryption.

## Security boundary

CED is adaptive, but it is intentionally **not self-authorizing**. Detection data can propose a new defense; cryptographic policy authorization, quorum consensus, and scoped network context remain separate controls. This prevents a poisoned telemetry stream from turning into a global deny rule.

The Red/Blue simulation is intentionally synthetic. It must never be connected directly to production assets or given an unrestricted execution channel. Semantic MTD changes internal contracts through an explicit compatibility layer rather than silently breaking legitimate clients. Topology optimization returns candidates and never directly changes live firewall/routing state.

The cryptographic transport provides confidentiality and authenticity for the barrier payload, while the consensus state hash prevents a valid signature from being detached from the committed ATIBON state. Replay resistance is enforced with epoch/version/expiry checks and a bounded clock-skew window.

The selected Rust cryptographic implementations still require independent security review before a high-assurance production qualification. In particular, HSM/TPM-backed key custody and a real authenticated node-to-node network channel (mTLS/QUIC/HTTPS) should be the next hardening layer around this cryptographic envelope.
