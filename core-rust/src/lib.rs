pub mod audit;
pub mod ced;
pub mod conntrack;
pub mod dpi;
pub mod consensus;
pub mod crypto;
pub mod rules;
pub mod shadow;

use pyo3::prelude::*;

#[pyfunction]
fn version() -> &'static str { env!("CARGO_PKG_VERSION") }

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
fn validate_barrier(envelope_json: &str, now_ms: u64, current_epoch: u64, current_version: u64) -> PyResult<String> {
    let envelope: crypto::transport::BarrierEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let result = crypto::transport::validate_envelope(&envelope, now_ms, current_epoch, current_version)
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
        &policy, sender_node_id, recipient_node_id, key_id,
        recipient_kem_public_key_hex, consensus_hash, issued_at_ms,
    ).map_err(pyo3::exceptions::PyValueError::new_err)?;
    serde_json::to_string(&envelope)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
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
        &envelope, recipient_kem_private_key_hex, trusted_signer_public_key_hex,
        now_ms, current_epoch, current_version,
    ).map_err(pyo3::exceptions::PyValueError::new_err)?;
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_packet, m)?)?;
    m.add_function(wrap_pyfunction!(decide_flow, m)?)?;
    m.add_function(wrap_pyfunction!(assess_shadow_url, m)?)?;
    m.add_function(wrap_pyfunction!(ced_observe, m)?)?;
    m.add_function(wrap_pyfunction!(validate_barrier, m)?)?;
    m.add_function(wrap_pyfunction!(seal_barrier, m)?)?;
    m.add_function(wrap_pyfunction!(open_barrier, m)?)?;
    m.add_class::<dpi::DpiEngine>()?;
    m.add_class::<consensus::HoneyBadgerState>()?;
    m.add_class::<crypto::PqcFacade>()?;
    Ok(())
}
