# ATIBON Continuous Evolutionary Defense (CED)

ATIBON's CED loop turns observed defensive telemetry into a bounded policy candidate:

1. **Behavioral ingestion** — timing deltas, request sizes, explored paths and mutation classes are converted into entropy/repetition features.
2. **Behavioral assessment** — a bounded automation score identifies repetitive machine-like exploration. The raw telemetry is also hashed into a 32-byte behavioral vector.
3. **Deceptive graph** — a synthetic API mirror is represented as an isolated graph. It is telemetry-only and is not allowed to reach production assets.
4. **Mutation** — a fail-closed candidate rule is generated and assigned a digest.
5. **Quorum authorization** — the candidate is proposed to `HoneyBadgerState`. The configured quorum must be reached before a transport envelope is created. The resulting consensus state hash is bound into the envelope.
6. **Post-quantum authorization** — the committed barrier is signed with the operator-managed ML-DSA-65 key. The receiver accepts only a configured trusted signing key.
7. **Confidential transport** — the policy is encrypted with ChaCha20-Poly1305 using a fresh AEAD key derived through HKDF-SHA-256 from an ML-KEM-768 shared secret.
8. **Receiver validation** — the recipient checks protocol, node IDs, key ID, epoch, monotonically increasing version, clock skew, expiry and digest shape; verifies ML-DSA before decrypting; decapsulates ML-KEM-768; authenticates/decrypts the policy; then recomputes the policy digest and checks all bound metadata.
9. **Scoped enforcement** — `atibon-agent` can quarantine a separately supplied, administrator/network-observed IPv4 address through the existing nftables abuse set. Telemetry alone never becomes an unrestricted firewall rule.

## Egress and IP-address semantics

ATIBON does not make an IP address « invisible » and does not arbitrarily impersonate a public source address. Privacy-preserving egress is a routing property: an internal source reaches ATIBON, passes reputation and risk/policy checks, optionally uses an approved relay, and then exits through NAT/proxy using an address legitimately assigned to that relay or provider.

```text
IP interne
    |
    v
  ATIBON
    |
    v
Reputation
    |
    v
Risk / Policy
    |
    +---- ALLOW ----------------------> sortie normale
    |
    +---- QUARANTINE -----------------> blocage contrôlé
    |
    +---- PRIVACY ROUTE
              |
              v
       relais approuvé
              |
              v
          NAT / Proxy
              |
              v
      IP d'egress attribuée
      au relais/fournisseur
              |
              v
       serveur distant
              |
              v
             audit
```

The Egress decision layer never accepts an arbitrary source-IP value. It selects from configured approved relays; actual source-address translation belongs to the OS/network dataplane or relay provider. See `docs/EGRESS.md` for the detailed invariants.

## Barrier propagation flow

```text
CED telemetry
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
- ML-KEM decapsulation keys are private node secrets and should be moved to the existing HSM/TPM abstraction before high-assurance production use.
- The receiver must pin the expected ML-DSA public key; an envelope's embedded public key is an identifier, not a trust decision.

## CLI

```text
atibon-agent --ced-telemetry telemetry.json --ced-dry-run
atibon-agent --ced-telemetry telemetry.json --ced-block-ip 203.0.113.10
```

The first command performs analysis without changing firewall state. The second applies a one-hour quarantine only when the behavioral assessment crosses the automation threshold and the IP is supplied separately.

## Security boundary

CED is adaptive, but it is intentionally **not self-authorizing**. Detection data can propose a new defense; cryptographic policy authorization, quorum consensus, and scoped network context remain separate controls. This prevents a poisoned telemetry stream from turning into a global deny rule.
