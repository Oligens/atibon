use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STATE_DIM: usize = 12;
pub const MATRIX_SEED: u64 = 0xC04AC0DE;
const DET_EPSILON: f64 = 1e-9;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayState {
    pub gateway: u8,
    pub vector: [f64; STATE_DIM],
    pub payload_digest: String,
    pub fnv1a64: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixPipelineResult {
    pub ingress: GatewayState,
    pub transformed: [f64; STATE_DIM],
    pub egress: GatewayState,
    pub determinant: f64,
    pub determinant_ok: bool,
    pub integrity_ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicBarrier {
    pub id: String,
    pub generation: u64,
    pub scope: String,
    pub action: String,
    pub expires_at_ms: u64,
    pub synthetic: bool,
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn vectorize(payload: &[u8]) -> [f64; STATE_DIM] {
    let mut v = [0.0; STATE_DIM];
    if payload.is_empty() { return v; }
    for (i, byte) in payload.iter().enumerate() {
        let slot = i % STATE_DIM;
        v[slot] = (v[slot] * 31.0 + *byte as f64) % 1_000_003.0;
    }
    v
}

fn matrix() -> [[f64; STATE_DIM]; STATE_DIM] {
    let mut m = [[0.0; STATE_DIM]; STATE_DIM];
    let mut x = MATRIX_SEED;
    for i in 0..STATE_DIM {
        for j in 0..STATE_DIM {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let noise = (x % 10_000) as f64 / 100_000.0;
            m[i][j] = if i == j { 1.0 + noise } else { noise / 100.0 };
        }
    }
    m
}

fn determinant(mut a: [[f64; STATE_DIM]; STATE_DIM]) -> f64 {
    let mut det = 1.0;
    for i in 0..STATE_DIM {
        let mut pivot = i;
        for r in (i + 1)..STATE_DIM {
            if a[r][i].abs() > a[pivot][i].abs() { pivot = r; }
        }
        if a[pivot][i].abs() < f64::EPSILON { return 0.0; }
        if pivot != i {
            a.swap(pivot, i);
            det = -det;
        }
        let p = a[i][i];
        det *= p;
        for r in (i + 1)..STATE_DIM {
            let factor = a[r][i] / p;
            for c in i..STATE_DIM { a[r][c] -= factor * a[i][c]; }
        }
    }
    det
}

fn multiply(m: &[[f64; STATE_DIM]; STATE_DIM], v: &[f64; STATE_DIM]) -> [f64; STATE_DIM] {
    let mut out = [0.0; STATE_DIM];
    for i in 0..STATE_DIM {
        for j in 0..STATE_DIM { out[i] += m[i][j] * v[j]; }
    }
    out
}

fn invert(mut a: [[f64; STATE_DIM]; STATE_DIM]) -> Option<[[f64; STATE_DIM]; STATE_DIM]> {
    let mut inv = [[0.0; STATE_DIM]; STATE_DIM];
    for i in 0..STATE_DIM { inv[i][i] = 1.0; }
    for i in 0..STATE_DIM {
        let mut pivot = i;
        for r in (i + 1)..STATE_DIM {
            if a[r][i].abs() > a[pivot][i].abs() { pivot = r; }
        }
        if a[pivot][i].abs() < f64::EPSILON { return None; }
        if pivot != i { a.swap(pivot, i); inv.swap(pivot, i); }
        let p = a[i][i];
        for c in 0..STATE_DIM { a[i][c] /= p; inv[i][c] /= p; }
        for r in 0..STATE_DIM {
            if r == i { continue; }
            let factor = a[r][i];
            for c in 0..STATE_DIM { a[r][c] -= factor * a[i][c]; inv[r][c] -= factor * inv[i][c]; }
        }
    }
    Some(inv)
}

pub fn process(payload: &[u8]) -> Result<MatrixPipelineResult, String> {
    let m = matrix();
    let det = determinant(m);
    let determinant_ok = det.is_finite() && det.abs() > DET_EPSILON;
    if !determinant_ok { return Err("ATIBON matrix is singular or numerically unstable".into()); }
    let inverse = invert(m).ok_or_else(|| "ATIBON matrix inversion failed".to_string())?;
    let original = vectorize(payload);
    let transformed = multiply(&m, &original);
    let restored = multiply(&inverse, &transformed);
    let integrity_ok = restored.iter().zip(original.iter()).all(|(a, b)| (a - b).abs() <= 1e-6 * (1.0 + b.abs()));
    let digest = hex(&Sha256::digest(payload));
    let hash = fnv1a64(payload);
    let ingress = GatewayState { gateway: 1, vector: original, payload_digest: digest.clone(), fnv1a64: hash };
    let egress = GatewayState { gateway: 3, vector: restored, payload_digest: digest, fnv1a64: hash };
    Ok(MatrixPipelineResult { ingress, transformed, egress, determinant: det, determinant_ok, integrity_ok })
}

pub fn generate_barriers(generation: u64, scope: &str, now_ms: u64) -> Vec<DynamicBarrier> {
    (0..5).map(|i| DynamicBarrier {
        id: format!("barrier-g{generation}-{i}"),
        generation,
        scope: scope.into(),
        action: if i == 4 { "quarantine-and-observe".into() } else { "adaptive-isolation".into() },
        expires_at_ms: now_ms.saturating_add(300_000 + i as u64 * 60_000),
        synthetic: true,
    }).collect()
}

pub fn recursion_after_breach(generation: u64, scope: &str, now_ms: u64) -> Vec<DynamicBarrier> {
    generate_barriers(generation.saturating_add(1), scope, now_ms)
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matrix_pipeline_is_reversible_for_state_vector() {
        let result = process(b"ATIBON test payload").unwrap();
        assert!(result.determinant_ok);
        assert!(result.integrity_ok);
        assert_eq!(result.ingress.fnv1a64, result.egress.fnv1a64);
    }
    #[test]
    fn barrier_generation_is_exactly_five() {
        assert_eq!(generate_barriers(1, "test", 0).len(), 5);
        assert_eq!(recursion_after_breach(1, "test", 0)[0].generation, 2);
    }
}
