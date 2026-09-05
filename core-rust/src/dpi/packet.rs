use pyo3::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct PacketMeta { version: u8, protocol: u8, src: String, dst: String, src_port: u16, dst_port: u16, payload_len: usize, sha256: String }

#[pyclass]
pub struct DpiEngine { max_packet_size: usize }

#[pymethods]
impl DpiEngine {
    #[new]
    pub fn new(max_packet_size: usize) -> Self { Self { max_packet_size } }

    pub fn inspect(&self, packet: &[u8]) -> PyResult<String> {
        if packet.len() > self.max_packet_size { return Err(pyo3::exceptions::PyValueError::new_err("packet exceeds configured limit")); }
        let meta = parse_ipv4(packet).unwrap_or(PacketMeta {
            version: 0, protocol: 0, src: "unknown".into(), dst: "unknown".into(), src_port: 0, dst_port: 0,
            payload_len: packet.len(), sha256: hex_digest(packet),
        });
        serde_json::to_string(&meta).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }
}

fn hex_digest(data: &[u8]) -> String { Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect() }

fn parse_ipv4(p: &[u8]) -> Option<PacketMeta> {
    if p.len() < 20 || (p[0] >> 4) != 4 { return None; }
    let ihl = ((p[0] & 0x0f) as usize) * 4; if ihl < 20 || p.len() < ihl { return None; }
    let protocol = p[9]; let src = format!("{}.{}.{}.{}", p[12],p[13],p[14],p[15]); let dst = format!("{}.{}.{}.{}", p[16],p[17],p[18],p[19]);
    let (src_port,dst_port) = if matches!(protocol, 6|17) && p.len() >= ihl+4 { (u16::from_be_bytes([p[ihl],p[ihl+1]]), u16::from_be_bytes([p[ihl+2],p[ihl+3]])) } else {(0,0)};
    Some(PacketMeta { version:4, protocol, src, dst, src_port, dst_port, payload_len:p.len().saturating_sub(ihl), sha256:hex_digest(p) })
}
