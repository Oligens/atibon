use crate::crypto::pi_hop::{ApprovedRelay, PiHopSchedule};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RuntimeMode { Shadow, Enforce }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RouteDecision { Allow, Quarantine, PrivacyRoute }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EgressInput {
    pub destination: String,
    pub reputation_score: u8,
    pub policy_score: u8,
    pub request_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EgressTrace {
    pub timestamp: u64,
    pub mode: RuntimeMode,
    pub destination: String,
    pub reputation_score: u8,
    pub policy_score: u8,
    pub simulated_decision: RouteDecision,
    pub effective_decision: RouteDecision,
    pub relay: Option<String>,
    pub nat_proxy: bool,
    pub source_ip_rewrite: bool,
    pub packet_blocked: bool,
    pub shadow_mismatch: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EgressResult {
    pub mode: RuntimeMode,
    pub simulated_decision: RouteDecision,
    pub effective_decision: RouteDecision,
    pub relay: Option<String>,
    pub nat_proxy: bool,
    pub source_ip_rewrite: bool,
    pub packet_blocked: bool,
    pub audit_written: bool,
    pub shadow_mismatch: bool,
}

pub struct JsonlAudit { writer: BufWriter<std::fs::File> }

impl JsonlAudit {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() { create_dir_all(parent)?; }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { writer: BufWriter::new(file) })
    }

    fn write(&mut self, trace: &EgressTrace) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, trace).map_err(std::io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn simulated_decision(input: &EgressInput, relay_available: bool) -> RouteDecision {
    let risk_triggered = input.policy_score >= 80 || input.reputation_score >= 70;
    if risk_triggered {
        if relay_available { RouteDecision::PrivacyRoute } else { RouteDecision::Quarantine }
    } else { RouteDecision::Allow }
}

/// Existing governed Egress API. Kept intact for callers that already provide
/// one approved relay. It delegates to the common execution path without
/// changing Shadow/Enforce semantics.
pub fn evaluate(
    input: &EgressInput,
    mode: RuntimeMode,
    approved_relay: Option<String>,
    audit: &mut JsonlAudit,
) -> std::io::Result<EgressResult> {
    let relay = approved_relay.map(|endpoint| ApprovedRelay {
        id: "configured-relay",
        endpoint: Box::leak(endpoint.into_boxed_str()),
    });
    evaluate_with_pi_hop(input, mode, relay.as_slice(), 0, current_time_ms(), audit)
}

/// Full Egress path with deterministic Pi-Hop relay selection:
/// TRAFFIC -> Reputation -> Risk/Policy -> Egress Decision -> Pi-Hop
/// -> Approved Relay -> NAT/Proxy -> Audit.
///
/// Pi-Hop is only a selector over the supplied allowlist. It does not create
/// endpoints, rewrite source addresses, or perform network operations.
pub fn evaluate_with_pi_hop(
    input: &EgressInput,
    mode: RuntimeMode,
    approved_relays: &[ApprovedRelay],
    epoch: u64,
    now_ms: u64,
    audit: &mut JsonlAudit,
) -> std::io::Result<EgressResult> {
    let relay_available = !approved_relays.is_empty();
    let simulated = simulated_decision(input, relay_available);
    let (effective, blocked) = match mode {
        RuntimeMode::Shadow => (RouteDecision::Allow, false),
        RuntimeMode::Enforce => (simulated, matches!(simulated, RouteDecision::Quarantine)),
    };

    let privacy_route = matches!(effective, RouteDecision::PrivacyRoute);
    let selected_relay = if privacy_route {
        PiHopSchedule::new(approved_relays, epoch).relay_for(now_ms)
    } else { None };
    let relay = selected_relay.map(|r| r.endpoint.to_owned());
    let nat_proxy = privacy_route && selected_relay.is_some();
    let source_ip_rewrite = false;

    let trace = EgressTrace {
        timestamp: now_secs(),
        mode,
        destination: input.destination.clone(),
        reputation_score: input.reputation_score,
        policy_score: input.policy_score,
        simulated_decision: simulated,
        effective_decision: effective,
        relay,
        nat_proxy,
        source_ip_rewrite,
        packet_blocked: blocked,
        shadow_mismatch: mode == RuntimeMode::Shadow && simulated != effective,
        reason: match simulated {
            RouteDecision::Allow => "reputation/policy allow; normal egress".into(),
            RouteDecision::PrivacyRoute => "privacy route selected by Pi-Hop from approved relay allowlist; NAT/proxy address is provider/OS assigned".into(),
            RouteDecision::Quarantine => "risk/policy decision requires controlled quarantine".into(),
        },
    };
    audit.write(&trace)?;

    Ok(EgressResult {
        mode,
        simulated_decision: simulated,
        effective_decision: effective,
        relay: trace.relay,
        nat_proxy,
        source_ip_rewrite,
        packet_blocked: blocked,
        audit_written: true,
        shadow_mismatch: trace.shadow_mismatch,
    })
}

fn current_time_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAYS: [ApprovedRelay; 4] = [
        ApprovedRelay { id: "relay-a", endpoint: "relay-a.internal" },
        ApprovedRelay { id: "relay-b", endpoint: "relay-b.internal" },
        ApprovedRelay { id: "relay-c", endpoint: "relay-c.internal" },
        ApprovedRelay { id: "relay-d", endpoint: "relay-d.internal" },
    ];

    fn audit() -> JsonlAudit {
        JsonlAudit::open(std::env::temp_dir().join(format!("atibon-egress-{}-{}.jsonl", std::process::id(), current_time_ms()))).expect("audit")
    }

    fn risky_input() -> EgressInput {
        EgressInput { destination: "suspicious.example".into(), reputation_score: 90, policy_score: 60, request_count: 1 }
    }

    #[test]
    fn shadow_is_non_blocking_but_records_simulated_privacy_route() {
        let result = evaluate_with_pi_hop(&risky_input(), RuntimeMode::Shadow, &RELAYS, 0, 1_000, &mut audit()).expect("evaluation");
        assert_eq!(result.simulated_decision, RouteDecision::PrivacyRoute);
        assert_eq!(result.effective_decision, RouteDecision::Allow);
        assert!(!result.packet_blocked);
        assert!(result.shadow_mismatch);
        assert!(!result.source_ip_rewrite);
        assert!(!result.nat_proxy);
    }

    #[test]
    fn enforce_privacy_route_uses_pi_hop_selected_approved_relay() {
        let result = evaluate_with_pi_hop(&risky_input(), RuntimeMode::Enforce, &RELAYS, 0, 1_000, &mut audit()).expect("evaluation");
        let expected = PiHopSchedule::new(&RELAYS, 0).relay_for(1_000).unwrap();
        assert_eq!(result.simulated_decision, RouteDecision::PrivacyRoute);
        assert_eq!(result.effective_decision, RouteDecision::PrivacyRoute);
        assert_eq!(result.relay.as_deref(), Some(expected.endpoint));
        assert!(result.nat_proxy);
        assert!(!result.source_ip_rewrite);
        assert!(!result.packet_blocked);
    }

    #[test]
    fn relay_rotates_when_pi_hop_slot_changes() {
        let a = evaluate_with_pi_hop(&risky_input(), RuntimeMode::Enforce, &RELAYS, 0, 0, &mut audit()).expect("a");
        let b = evaluate_with_pi_hop(&risky_input(), RuntimeMode::Enforce, &RELAYS, 0, 100, &mut audit()).expect("b");
        assert_ne!(a.relay, b.relay);
    }

    #[test]
    fn jitter_acceptance_is_bounded_to_adjacent_slots() {
        let schedule = PiHopSchedule::new(&RELAYS, 0);
        let previous = *schedule.relay_for(900).unwrap();
        let current = *schedule.relay_for(1_000).unwrap();
        let next = *schedule.relay_for(1_100).unwrap();
        let far = *schedule.relay_for(1_200).unwrap();
        assert!(schedule.accepts(1_000, &previous));
        assert!(schedule.accepts(1_000, &current));
        assert!(schedule.accepts(1_000, &next));
        assert!(!schedule.accepts(1_000, &far));
    }

    #[test]
    fn enforce_quarantines_without_approved_relay() {
        let result = evaluate_with_pi_hop(&risky_input(), RuntimeMode::Enforce, &[], 0, 1_000, &mut audit()).expect("evaluation");
        assert_eq!(result.effective_decision, RouteDecision::Quarantine);
        assert!(result.packet_blocked);
        assert!(!result.nat_proxy);
        assert!(!result.source_ip_rewrite);
    }

    #[test]
    fn direct_allow_never_enables_nat_proxy_or_source_ip_rewrite() {
        let input = EgressInput { destination: "example.com".into(), reputation_score: 10, policy_score: 10, request_count: 1 };
        let result = evaluate_with_pi_hop(&input, RuntimeMode::Enforce, &RELAYS, 0, 1_000, &mut audit()).expect("evaluation");
        assert_eq!(result.effective_decision, RouteDecision::Allow);
        assert!(!result.nat_proxy);
        assert!(!result.source_ip_rewrite);
    }
}
