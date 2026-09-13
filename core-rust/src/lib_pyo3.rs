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
        other => return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "invalid egress runtime mode: {other}"
        ))),
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
fn version() -> &'static str { env!("CARGO_PKG_VERSION") }

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(egress_governed_decide, m)?)?;
    Ok(())
}
