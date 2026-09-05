use pyo3::prelude::*;

#[pyclass]
pub struct PqcFacade;

#[pymethods]
impl PqcFacade {
    #[new] pub fn new() -> Self { Self }
    pub fn backend(&self) -> &'static str { if cfg!(feature="pqc-native") { "native-pqc-backend" } else { "unconfigured" } }
    pub fn encapsulation_required(&self) -> bool { true }
    pub fn signature_required(&self) -> bool { true }
}
