use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[pyclass]
#[derive(Clone)]
pub struct HoneyBadgerState { epoch: u64, accepted: u64, quorum: u64, state_hash: String }

#[pymethods]
impl HoneyBadgerState {
    #[new]
    pub fn new(quorum: u64) -> Self { Self { epoch: 0, accepted: 0, quorum: quorum.max(1), state_hash: String::new() } }
    pub fn propose(&mut self, payload: &[u8], approvals: u64) -> bool {
        if approvals < self.quorum { return false; }
        let mut h = Sha256::new(); h.update(self.epoch.to_be_bytes()); h.update(payload); self.state_hash = format!("{:x}", h.finalize());
        self.accepted += 1; self.epoch += 1; true
    }
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn accepted(&self) -> u64 { self.accepted }
    pub fn state_hash(&self) -> String { self.state_hash.clone() }
}
