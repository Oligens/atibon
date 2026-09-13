use crate::audit::AuditLog;
use crate::egress_privacy::{self, EgressDecision, EgressMode, EgressPolicy};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum EgressRuntimeMode {
    #[default]
    Shadow,
    Enforce,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EgressRequest<'a> {
    pub destination: &'a str,
    pub reputation_score: u8,
    pub request_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EgressExecution {
    pub mode: EgressRuntimeMode,
    pub decision: EgressDecision,
    pub action: String,
    pub enforcement_ready: bool,
}

pub fn evaluate(
    request: &EgressRequest<'_>,
    policy: &EgressPolicy,
    runtime_mode: EgressRuntimeMode,
) -> EgressExecution {
    let decision = egress_privacy::decide(
        request.destination,
        request.reputation_score,
        request.request_count,
        policy,
    );

    let action = match (&runtime_mode, &decision.mode) {
        (EgressRuntimeMode::Shadow, EgressMode::Direct) => "observe:direct",
        (EgressRuntimeMode::Shadow, EgressMode::PrivacyRelay) => "observe:approved-relay",
        (EgressRuntimeMode::Shadow, EgressMode::Quarantine) => "observe:quarantine",
        (EgressRuntimeMode::Enforce, EgressMode::Direct) => "allow:direct",
        (EgressRuntimeMode::Enforce, EgressMode::PrivacyRelay) => "route:approved-relay",
        (EgressRuntimeMode::Enforce, EgressMode::Quarantine) => "deny:quarantine",
    }
    .to_string();

    EgressExecution {
        mode: runtime_mode,
        enforcement_ready: matches!(runtime_mode, EgressRuntimeMode::Enforce),
        decision,
        action,
    }
}

pub fn evaluate_and_audit(
    request: &EgressRequest<'_>,
    policy: &EgressPolicy,
    runtime_mode: EgressRuntimeMode,
    audit: &AuditLog,
) -> std::io::Result<EgressExecution> {
    let execution = evaluate(request, policy, runtime_mode);
    let source = execution.decision.destination.as_str();
    let reason = execution.decision.reason.as_str();
    audit.record(&execution.action, source, reason)?;
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_never_marks_network_enforcement_as_active() {
        let request = EgressRequest {
            destination: "suspicious.example",
            reputation_score: 90,
            request_count: 1,
        };
        let policy = EgressPolicy {
            relay_pool: vec!["proxy://approved-relay".into()],
            ..Default::default()
        };
        let result = evaluate(&request, &policy, EgressRuntimeMode::Shadow);
        assert_eq!(result.action, "observe:approved-relay");
        assert!(!result.enforcement_ready);
    }

    #[test]
    fn enforce_requires_an_approved_relay_for_suspicious_destination() {
        let request = EgressRequest {
            destination: "suspicious.example",
            reputation_score: 90,
            request_count: 1,
        };
        let result = evaluate(
            &request,
            &EgressPolicy::default(),
            EgressRuntimeMode::Enforce,
        );
        assert_eq!(result.decision.mode, EgressMode::Quarantine);
        assert_eq!(result.action, "deny:quarantine");
    }
}
