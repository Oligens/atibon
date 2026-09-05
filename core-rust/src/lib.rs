pub mod dpi;
pub mod consensus;
pub mod crypto;

use pyo3::prelude::*;

/// Return the native ATIBON core version exposed to Python.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Inspect a raw packet through the native DPI engine.
///
/// The parser is fail-closed: malformed packets are returned as opaque
/// metadata and packets above `max_packet_size` are rejected.
#[pyfunction]
#[pyo3(signature = (packet, max_packet_size = 65_535))]
fn inspect_packet(packet: &[u8], max_packet_size: usize) -> PyResult<String> {
    let engine = dpi::DpiEngine::new(max_packet_size);
    engine.inspect(packet)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_packet, m)?)?;
    m.add_class::<dpi::DpiEngine>()?;
    m.add_class::<consensus::HoneyBadgerState>()?;
    m.add_class::<crypto::PqcFacade>()?;
    Ok(())
}
