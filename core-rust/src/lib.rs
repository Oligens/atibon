pub mod dpi;
pub mod consensus;
pub mod crypto;

use pyo3::prelude::*;

#[pymodule]
fn atibon_core_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<dpi::DpiEngine>()?;
    m.add_class::<consensus::HoneyBadgerState>()?;
    m.add_class::<crypto::PqcFacade>()?;
    Ok(())
}
