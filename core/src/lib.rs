mod engine; mod consensus; mod crypto;
use pyo3::prelude::*;
#[pymodule]
fn defensive_ai_core(m:&Bound<'_,PyModule>)->PyResult<()>{m.add_class::<engine::FilterEngine>()?;m.add_class::<consensus::BFTStateManager>()?;m.add_class::<crypto::PostQuantumCrypto>()?;Ok(())}
