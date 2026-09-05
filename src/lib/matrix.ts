/* ============================================================
 * Noyau matriciel — miroir TypeScript du module Rust
 * `matrix_engine.rs` : mêmes algorithmes (Génération à diagonale
 * dominante, déterminant par élimination de Gauss, inversion
 * Gauss-Jordan) pour une simulation fidèle dans le navigateur.
 * ============================================================ */

export const N = 12; // dimension fixe du vecteur d'état

/** PRNG déterministe (mulberry32) — équivalent StdRng seedé côté Rust. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type Mat = number[][];
export type Vec = number[];

/** Génère M ∈ GL(n, ℝ) à diagonale strictement dominante → inversible. */
export function generateMatrix(seed: number, n: number = N): Mat {
  const rnd = mulberry32(seed);
  const m: Mat = Array.from({ length: n }, () => new Array(n).fill(0));
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      m[i][j] =
        i === j
          ? 1.85 + rnd() * 0.65 // diagonale ∈ [1.85, 2.50]
          : (rnd() - 0.5) * 0.55; // hors-diagonale ∈ [-0.275, 0.275]
    }
  }
  return m;
}

export function mulMatVec(m: Mat, v: Vec): Vec {
  return m.map((row) => row.reduce((acc, mij, j) => acc + mij * v[j], 0));
}

/** Déterminant par élimination de Gauss avec pivot partiel. */
export function determinant(input: Mat): number {
  const n = input.length;
  const a = input.map((r) => [...r]);
  let det = 1;
  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let r = col + 1; r < n; r++) {
      if (Math.abs(a[r][col]) > Math.abs(a[pivot][col])) pivot = r;
    }
    if (Math.abs(a[pivot][col]) < 1e-14) return 0;
    if (pivot !== col) {
      [a[pivot], a[col]] = [a[col], a[pivot]];
      det = -det;
    }
    det *= a[col][col];
    for (let r = col + 1; r < n; r++) {
      const f = a[r][col] / a[col][col];
      for (let c = col; c < n; c++) a[r][c] -= f * a[col][c];
    }
  }
  return det;
}

/** Inversion par Gauss-Jordan (équivalent de `m.try_inverse()`). */
export function invert(input: Mat): Mat {
  const n = input.length;
  const a = input.map((r, i) => {
    const aug = new Array(2 * n).fill(0);
    for (let c = 0; c < n; c++) aug[c] = r[c];
    aug[n + i] = 1;
    return aug;
  });
  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let r = col + 1; r < n; r++) {
      if (Math.abs(a[r][col]) > Math.abs(a[pivot][col])) pivot = r;
    }
    [a[pivot], a[col]] = [a[col], a[pivot]];
    const d = a[col][col];
    for (let c = 0; c < 2 * n; c++) a[col][c] /= d;
    for (let r = 0; r < n; r++) {
      if (r === col) continue;
      const f = a[r][col];
      for (let c = 0; c < 2 * n; c++) a[r][c] -= f * a[col][c];
    }
  }
  return a.map((r) => r.slice(n));
}

/** Hash FNV-1a 16 bits — même fonction que `packet.rs`. */
export function fnv1a16(bytes: number[]): number {
  let h = 0x811c;
  for (const b of bytes) {
    h ^= b & 0xff;
    h = (h * 0x01000193) >>> 0;
    h &= 0xffff;
  }
  return h & 0xffff;
}

export function parseIp(ip: string): number[] {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  while (parts.length < 4) parts.push(0);
  return parts.slice(0, 4).map((p) => (Number.isFinite(p) ? Math.max(0, Math.min(255, p)) : 0));
}

export function parsePayloadHex(hex: string): number[] {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const bytes: number[] = [];
  for (let i = 0; i + 1 < clean.length && bytes.length < 32; i += 2) {
    bytes.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return bytes;
}

/** Vectorisation dim. 12 : [src×4, dst×4, port_hi, port_lo, chk_hi, chk_lo]. */
export function vectorize(srcIp: string, dstIp: string, port: number, payloadHex: string): Vec {
  const src = parseIp(srcIp);
  const dst = parseIp(dstIp);
  const chk = fnv1a16(parsePayloadHex(payloadHex));
  const p = Math.max(0, Math.min(65535, port | 0));
  return [
    ...src,
    ...dst,
    (p >> 8) & 0xff,
    p & 0xff,
    (chk >> 8) & 0xff,
    chk & 0xff,
  ];
}

export const fmt = (x: number, d = 1): string =>
  Math.abs(x) >= 1000 || (Math.abs(x) < 0.001 && x !== 0)
    ? x.toExponential(2)
    : x.toFixed(d);
