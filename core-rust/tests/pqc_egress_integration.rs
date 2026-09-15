//! End-to-end defensive integration test: ML-KEM/ML-DSA barrier -> validation -> governed Egress.
//! The test uses only local synthetic data and never opens a network socket.

#[cfg(feature = "pqc-native")]
mod pqc_native {
    use std::sync::{Mutex, OnceLock};

    use ml_kem::{
        kem::{Decapsulate, Encapsulate, Kem},
        KeyExport, MlKem768,
    };

    use atibon_core::crypto::transport::{
        open_barrier, seal_barrier, validate_envelope, BarrierPolicy,
    };
    use atibon_core::egress_governed::{
        evaluate, EgressInput, JsonlAudit, RouteDecision, RuntimeMode,
    };

    const SIGNING_SEED_HEX: &str =
        "4242424242424242424242424242424242424242424242424242424242424242";
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn pqc_barrier_survives_validation_and_governed_egress() {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        unsafe {
            std::env::set_var("ATIBON_MLDSA65_SEED_HEX", SIGNING_SEED_HEX);
        }

        let (recipient_dk, recipient_ek) = MlKem768::generate_keypair();
        let recipient_public_key =
            hex(AsRef::<[u8]>::as_ref(&recipient_ek.to_bytes()));

        let policy = BarrierPolicy {
            policy_id: "pqc-egress-test".into(),
            version: 2,
            epoch: 1,
            expires_at_ms: 4_000,
            action: "quarantine".into(),
            scope: "lab://synthetic-target".into(),
            rule_digest: "aa".repeat(32),
        };
        let consensus_hash = "bb".repeat(32);

        let envelope = seal_barrier(
            &policy,
            "sender-lab",
            "recipient-lab",
            "mlkem768-test-key",
            &recipient_public_key,
            &consensus_hash,
            1_000,
        )
        .expect("PQC sealing must succeed");

        assert_eq!(envelope.kem_algorithm, "ML-KEM-768");
        assert_eq!(envelope.signature_algorithm, "ML-DSA-65");
        assert_eq!(envelope.kem_ciphertext_hex.len(), 2 * 1088);
        assert_eq!(envelope.signer_public_key_hex.len(), 2 * 1952);
        assert_eq!(envelope.signature_hex.len(), 2 * 3309);

        let structural = validate_envelope(&envelope, 1_500, 1, 1).expect("envelope validation");
        assert!(!structural.accepted);

        #[allow(deprecated)]
        let recipient_private_key = hex(recipient_dk.to_expanded_bytes().as_ref());
        let opened = open_barrier(
            &envelope,
            &recipient_private_key,
            &envelope.signer_public_key_hex,
            1_500,
            1,
            1,
        )
        .expect("PQC signature, decapsulation and AEAD verification must succeed");
        assert!(opened.accepted);
        assert_eq!(opened.policy, policy);

        let audit_path = std::env::temp_dir().join(format!(
            "atibon-pqc-egress-{}.jsonl",
            std::process::id()
        ));
        let mut audit = JsonlAudit::open(&audit_path).expect("audit log");
        let egress = evaluate(
            &EgressInput {
                destination: "lab://synthetic-target".into(),
                reputation_score: 90,
                policy_score: 90,
                request_count: 1,
            },
            RuntimeMode::Enforce,
            Some("relay://approved-lab".into()),
            &mut audit,
        )
        .expect("governed Egress must execute");

        assert_eq!(egress.simulated_decision, RouteDecision::PrivacyRoute);
        assert_eq!(egress.effective_decision, RouteDecision::PrivacyRoute);
        assert!(egress.nat_proxy);
        assert!(!egress.source_ip_rewrite);
        assert!(!egress.packet_blocked);
        assert!(egress.audit_written);

        let _ = std::fs::remove_file(audit_path);
    }
}

#[cfg(not(feature = "pqc-native"))]
#[test]
fn pqc_egress_integration_requires_native_feature() {
    // Keep the default test suite explicit: this integration requires the
    // native FIPS 203/FIPS 204 backend and is exercised by the PQC CI job.
    assert!(true);
}
