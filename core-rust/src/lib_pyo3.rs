#![allow(clippy::map_flatten)]
#![allow(clippy::needless_range_loop)]
#![allow(unused_imports)]

pub mod agents;
pub mod audit;
pub mod ced;
pub mod conntrack;
pub mod consensus;
pub mod crypto;
pub mod dpi;
pub mod egress_governed;
pub mod egress_pipeline;
pub mod egress_privacy;
pub mod forensic;
pub mod governance;
pub mod learning;
pub mod matrix_gateway;
pub mod rules;
pub mod shadow;

use pyo3::prelude::*;

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pyfunction]
#[pyo3(signature = (packet, max_packet_size = 65_535))]
fn inspect_packet(packet: &[u8], max_packet_size: usize) -> PyResult<String> {
    dpi::DpiEngine::new(max_packet_size).inspect(packet)
}

#[pyfunction]
fn decide_flow(protocol: u8, dst_port: u16, rules_json: &str) -> PyResult<String> {
    let rules: Vec<rules::Rule> = serde_json::from_str(rules_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let flow = rules::Flow { protocol, dst_port };
    serde_json::to_string(&rules::decide(&flow, &rules))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn assess_shadow_url(url: &str) -> PyResult<String> {
    shadow::assess_url(url)
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn ced_observe(samples_json: &str) -> PyResult<String> {
    let samples: Vec<ced::TelemetrySample> = serde_json::from_str(samples_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&ced::observe(&samples))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (samples_json, thresholds_json = "{}", previous_forensic_hash = "genesis"))]
fn ced_decide(
    samples_json: &str,
    thresholds_json: &str,
    previous_forensic_hash: &str,
) -> PyResult<String> {
    let samples: Vec<ced::TelemetrySample> = serde_json::from_str(samples_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let thresholds: ced::ThreatThresholdConfig = serde_json::from_str(thresholds_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&ced::decide(&samples, &thresholds, previous_forensic_hash))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn forensic_artifact_digest(
    id: &str,
    kind: &str,
    bytes: &[u8],
    collected_at_ms: u64,
) -> PyResult<String> {
    serde_json::to_string(&forensic::artifact_from_bytes(
        id,
        kind,
        bytes,
        collected_at_ms,
    ))
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn validate_barrier(
    envelope_json: &str,
    now_ms: u64,
    current_epoch: u64,
    current_version: u64,
) -> PyResult<String> {
    let envelope: crypto::transport::BarrierEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let result =
        crypto::transport::validate_envelope(&envelope, now_ms, current_epoch, current_version)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn seal_barrier(
    policy_json: &str,
    sender_node_id: &str,
    recipient_node_id: &str,
    key_id: &str,
    recipient_kem_public_key_hex: &str,
    consensus_hash: &str,
    issued_at_ms: u64,
) -> PyResult<String> {
    let policy: crypto::transport::BarrierPolicy = serde_json::from_str(policy_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let envelope = crypto::transport::seal_barrier(
        &policy,
        sender_node_id,
        recipient_node_id,
        key_id,
        recipient_kem_public_key_hex,
        consensus_hash,
        issued_at_ms,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;
    serde_json::to_string(&envelope)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn open_barrier(
    envelope_json: &str,
    recipient_kem_private_key_hex: &str,
    trusted_signer_public_key_hex: &str,
    now_ms: u64,
    current_epoch: u64,
    current_version: u64,
) -> PyResult<String> {
    let envelope: crypto::transport::BarrierEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let result = crypto::transport::open_barrier(
        &envelope,
        recipient_kem_private_key_hex,
        trusted_signer_public_key_hex,
        now_ms,
        current_epoch,
        current_version,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn matrix_gateway_process(packet: &[u8]) -> PyResult<String> {
    matrix_gateway::process(packet)
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[pyfunction]
fn generate_dynamic_barriers(generation: u64, scope: &str, now_ms: u64) -> PyResult<String> {
    serde_json::to_string(&matrix_gateway::generate_barriers(
        generation, scope, now_ms,
    ))
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn recurse_dynamic_barriers(generation: u64, scope: &str, now_ms: u64) -> PyResult<String> {
    serde_json::to_string(&matrix_gateway::recursion_after_breach(
        generation, scope, now_ms,
    ))
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn egress_privacy_decide(
    destination: &str,
    reputation_score: u8,
    request_count: u64,
    policy_json: &str,
) -> PyResult<String> {
    let policy: egress_privacy::EgressPolicy = serde_json::from_str(policy_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&egress_privacy::decide(
        destination,
        reputation_score,
        request_count,
        &policy,
    ))
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (destination, reputation_score, request_count, policy_json, runtime_mode = "shadow", audit_path = "/var/log/atibon/egress.jsonl"))]
fn egress_pipeline_decide(
    destination: &str,
    reputation_score: u8,
    request_count: u64,
    policy_json: &str,
    runtime_mode: &str,
    audit_path: &str,
) -> PyResult<String> {
    let policy: egress_privacy::EgressPolicy = serde_json::from_str(policy_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let mode = match runtime_mode {
        "shadow" | "observe-only" => egress_pipeline::EgressRuntimeMode::Shadow,
        "enforce" => egress_pipeline::EgressRuntimeMode::Enforce,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid egress runtime mode: {other}"
            )))
        }
    };
    let request = egress_pipeline::EgressRequest {
        destination,
        reputation_score,
        request_count,
    };
    let audit = audit::AuditLog::open(audit_path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    let execution = egress_pipeline::evaluate_and_audit(&request, &policy, mode, &audit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    serde_json::to_string(&execution)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn egress_governed_decide(
    destination: &str,
    reputation_score: u8,
    policy_score: u8,
    request_count: u64,
    approved_relay: Option<String>,
    runtime_mode: &str,
    audit_path: &str,
) -> PyResult<String> {
    let mode = match runtime_mode {
        "shadow" | "observe-only" => egress_governed::RuntimeMode::Shadow,
        "enforce" => egress_governed::RuntimeMode::Enforce,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid egress runtime mode: {other}"
            )))
        }
    };
    let input = egress_governed::EgressInput {
        destination: destination.to_string(),
        reputation_score,
        policy_score,
        request_count,
    };
    let mut audit = egress_governed::JsonlAudit::open(audit_path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    let result = egress_governed::evaluate(&input, mode, approved_relay, &mut audit)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn list_defensive_agents() -> PyResult<String> {
    serde_json::to_string(agents::descriptors())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn agent_consensus(
    anomaly_score: f64,
    crypto_violation: bool,
    repeated_behavior: bool,
) -> PyResult<String> {
    serde_json::to_string(&agents::consensus(
        anomaly_score,
        crypto_violation,
        repeated_behavior,
    ))
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn governed_agent_pipeline(
    attack_score: f64,
    stage_scores_json: &str,
    candidate_json: &str,
    now_ms: u64,
) -> PyResult<String> {
    let stage_scores: Vec<f64> = serde_json::from_str(stage_scores_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let candidate: governance::BarrierCandidate = serde_json::from_str(candidate_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let mut governor = governance::ResourceGovernor::default();
    let result = governance::run_pipeline(
        &mut governor,
        attack_score,
        &stage_scores,
        Some(candidate),
        now_ms,
    );
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

// The Python package and maturin configuration both require the native module
// to be named `atibon_core._native`. Keep the PyO3 module name explicit so the
// generated `PyInit__native` symbol cannot drift from Cargo/maturin metadata.
#[pymodule(name = "_native")]
fn native_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_packet, m)?)?;
    m.add_function(wrap_pyfunction!(decide_flow, m)?)?;
    m.add_function(wrap_pyfunction!(assess_shadow_url, m)?)?;
    m.add_function(wrap_pyfunction!(ced_observe, m)?)?;
    m.add_function(wrap_pyfunction!(ced_decide, m)?)?;
    m.add_function(wrap_pyfunction!(forensic_artifact_digest, m)?)?;
    m.add_function(wrap_pyfunction!(validate_barrier, m)?)?;
    m.add_function(wrap_pyfunction!(seal_barrier, m)?)?;
    m.add_function(wrap_pyfunction!(open_barrier, m)?)?;
    m.add_function(wrap_pyfunction!(matrix_gateway_process, m)?)?;
    m.add_function(wrap_pyfunction!(generate_dynamic_barriers, m)?)?;
    m.add_function(wrap_pyfunction!(recurse_dynamic_barriers, m)?)?;
    m.add_function(wrap_pyfunction!(egress_privacy_decide, m)?)?;
    m.add_function(wrap_pyfunction!(egress_pipeline_decide, m)?)?;
    m.add_function(wrap_pyfunction!(egress_governed_decide, m)?)?;
    m.add_function(wrap_pyfunction!(list_defensive_agents, m)?)?;
    m.add_function(wrap_pyfunction!(agent_consensus, m)?)?;
    m.add_function(wrap_pyfunction!(governed_agent_pipeline, m)?)?;
    m.add_class::<dpi::DpiEngine>()?;
    m.add_class::<consensus::HoneyBadgerState>()?;
    m.add_class::<crypto::PqcFacade>()?;
    Ok(())
}
