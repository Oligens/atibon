pub mod audit;
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

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_packet, m)?)?;
    m.add_function(wrap_pyfunction!(decide_flow, m)?)?;
    m.add_function(wrap_pyfunction!(assess_shadow_url, m)?)?;
    m.add_class::<dpi::DpiEngine>()?;
    m.add_class::<consensus::HoneyBadgerState>()?;
    m.add_class::<crypto::PqcFacade>()?;
    Ok(())
}
