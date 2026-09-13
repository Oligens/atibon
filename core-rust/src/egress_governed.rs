use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RuntimeMode {
    Shadow,
    Enforce,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum RouteDecision {
    Allow,
    Quarantine,
    PrivacyRoute,
}

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

pub struct JsonlAudit {
    writer: BufWriter<std::fs::File>,
}

impl JsonlAudit {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    fn write(&mut self, trace: &EgressTrace) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, trace).map_err(std::io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn simulated_decision(input: &EgressInput, relay_available: bool) -> RouteDecision {
    let risk_triggered = input.policy_score >= 80 || input.reputation_score >= 70;

    if risk_triggered {
        if relay_available {
            RouteDecision::PrivacyRoute
        } else {
            RouteDecision::Quarantine
        }
    } else {
        RouteDecision::Allow
    }
}

pub fn evaluate(
    input: &EgressInput,
    mode: RuntimeMode,
    approved_relay: Option<String>,
    audit: &mut JsonlAudit,
) -> std::io::Result<EgressResult> {
    // The policy engine only selects an approved relay. It never accepts or
    // fabricates an arbitrary source IP. Actual NAT/source-address selection
    // belongs to the OS/provider-controlled relay dataplane.
    // Exact order: TRAFFIC -> Reputation -> Risk/Policy -> Approved Relay
    // -> NAT/Proxy -> Audit. Shadow evaluates the same decision but never blocks.
    let relay_available = approved_relay.is_some();
    let simulated = simulated_decision(input, relay_available);
    let (effective, blocked) = match mode {
        RuntimeMode::Shadow => (RouteDecision::Allow, false),
        RuntimeMode::Enforce => (simulated, matches!(simulated, RouteDecision::Quarantine)),
    };

    let privacy_route = matches!(effective, RouteDecision::PrivacyRoute);
    let relay = if privacy_route {
        approved_relay.clone()
    } else {
        None
    };
    // This flag means that the selected path requires the configured relay's
    // NAT/proxy. It is not an instruction to rewrite an arbitrary IP address.
    let nat_proxy = privacy_route && relay.is_some();
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
            RouteDecision::PrivacyRoute => {
                "privacy route uses an approved relay; NAT/proxy address is provider/OS assigned".into()
            }
            RouteDecision::Quarantine => {
                "risk/policy decision requires controlled quarantine".into()
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn audit() -> JsonlAudit {
        JsonlAudit::open(std::env::temp_dir().join(format!("atibon-egress-{}.jsonl", now_secs())))
            .expect("audit")
    }

    #[test]
    fn shadow_is_non_blocking_but_records_simulated_quarantine() {
        let input = EgressInput {
            destination: "bad.example".into(),
            reputation_score: 90,
            policy_score: 90,
            request_count: 1,
        };
        let result =
            evaluate(&input, RuntimeMode::Shadow, None, &mut audit()).expect("evaluation");
        assert_eq!(result.simulated_decision, RouteDecision::Quarantine);
        assert_eq!(result.effective_decision, RouteDecision::Allow);
        assert!(!result.packet_blocked);
        assert!(result.shadow_mismatch);
        assert!(!result.source_ip_rewrite);
    }

    #[test]
    fn enforce_privacy_route_uses_only_selected_relay_for_nat_proxy() {
        let input = EgressInput {
            destination: "suspicious.example".into(),
            reputation_score: 90,
            policy_score: 60,
            request_count: 1,
        };
        let result = evaluate(
            &input,
            RuntimeMode::Enforce,
            Some("relay://approved".into()),
            &mut audit(),
        )
        .expect("evaluation");
        assert_eq!(result.simulated_decision, RouteDecision::PrivacyRoute);
        assert_eq!(result.effective_decision, RouteDecision::PrivacyRoute);
        assert_eq!(result.relay.as_deref(), Some("relay://approved"));
        assert!(result.nat_proxy);
        assert!(!result.source_ip_rewrite);
        assert!(!result.packet_blocked);
    }

    #[test]
    fn enforce_quarantines_without_relay() {
        let input = EgressInput {
            destination: "suspicious.example".into(),
            reputation_score: 90,
            policy_score: 60,
            request_count: 1,
        };
        let result =
            evaluate(&input, RuntimeMode::Enforce, None, &mut audit()).expect("evaluation");
        assert_eq!(result.effective_decision, RouteDecision::Quarantine);
        assert!(result.packet_blocked);
        assert!(!result.nat_proxy);
        assert!(!result.source_ip_rewrite);
    }

    #[test]
    fn direct_allow_never_enables_nat_proxy_or_source_ip_rewrite() {
        let input = EgressInput {
            destination: "example.com".into(),
            reputation_score: 10,
            policy_score: 10,
            request_count: 1,
        };
        let result = evaluate(
            &input,
            RuntimeMode::Enforce,
            Some("relay://approved".into()),
            &mut audit(),
        )
        .expect("evaluation");
        assert_eq!(result.effective_decision, RouteDecision::Allow);
        assert!(!result.nat_proxy);
        assert!(!result.source_ip_rewrite);
    }
}
