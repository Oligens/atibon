/* ============================================================
 * lib/matrix.ts — Miroir navigateur du noyau Rust (matrix_engine)
 * Mêmes algorithmes : FNV-1a, diagonale dominante (Lévy–
 * Desplanques), déterminant par élimination de Gauss, inverse
 * par Gauss-Jordan. Tout est déterministe (seed = 0xC04AC0DE).
 * ============================================================ */

export const N = 12;
export const MATRIX_SEED = 0xc04ac0de;
export const DET_DRIFT_EPS = 1e-9;

export type VecN = number[];
export type MatN = number[][];

export interface PacketDef {
  src: [number, number, number, number];
  dst: [number, number, number, number];
  port: number;
  payload: string;
}

export const DEFAULT_PACKET: PacketDef = {
  src: [192, 168, 1, 24],
  dst: [10, 0, 0, 7],
  port: 443,
  payload: "GET /coj/heartbeat HTTP/1.1",
};

/* ── RNG déterministe (équivalent StdRng seedé) ─────────────── */
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

/* ── FNV-1a — empreintes d'intégrité ────────────────────────── */
export function fnv1a16(bytes: Uint8Array): number {
  let h = 0x811c;
  for (const b of bytes) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h & 0xffff;
}

export function fnv1a32(data: Uint8Array): number {
  let h = 0x811c9dc5;
  for (const b of data) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

export function fnv1a32str(s: string): number {
  return fnv1a32(new TextEncoder().encode(s));
}

export function checksumPacket(payload: string): number {
  return fnv1a16(new TextEncoder().encode(payload));
}

/* ── Vectorisation (identique à packet.rs) ──────────────────── */
export function vectorizePacket(p: PacketDef): VecN {
  const chk = checksumPacket(p.payload);
  return [
    p.src[0], p.src[1], p.src[2], p.src[3],
    p.dst[0], p.dst[1], p.dst[2], p.dst[3],
    (p.port >> 8) & 0xff,
    p.port & 0xff,
    (chk >> 8) & 0xff,
    chk & 0xff,
  ];
}

export const VECTOR_LABELS = [
  "src₀", "src₁", "src₂", "src₃",
  "dst₀", "dst₁", "dst₂", "dst₃",
  "portH", "portL", "chkH", "chkL",
];

/* ── Génération de M (diagonale strictement dominante) ──────── */
export function generateMatrix(seed: number): MatN {
  const rng = mulberry32(seed);
  const m: MatN = [];
  for (let i = 0; i < N; i++) {
    const row: number[] = [];
    for (let j = 0; j < N; j++) {
      if (i === j) row.push(1.85 + rng() * 0.65);
      else row.push((rng() - 0.5) * 0.55);
    }
    m.push(row);
  }
  return m;
}

/* ── Produit matrice · vecteur ──────────────────────────────── */
export function matVec(m: MatN, v: VecN): VecN {
  return m.map((row) => row.reduce((acc, mij, j) => acc + mij * v[j], 0));
}

/* ── Déterminant — élimination de Gauss avec pivot partiel ──── */
export function determinant(input: MatN): number {
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
      [a[col], a[pivot]] = [a[pivot], a[col]];
      det = -det;
    }
    det *= a[col][col];
    for (let r = col + 1; r < n; r++) {
      const f = a[r][col] / a[col][col];
      if (f === 0) continue;
      for (let c = col; c < n; c++) a[r][c] -= f * a[col][c];
    }
  }
  return det;
}

/* ── Inverse — Gauss-Jordan (M | I) → (I | M⁻¹) ─────────────── */
export function invertMatrix(input: MatN): MatN | null {
  const n = input.length;
  const a = input.map((row, i) => {
    const ext = new Array(2 * n).fill(0);
    row.forEach((v, j) => (ext[j] = v));
    ext[n + i] = 1;
    return ext;
  });

  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let r = col + 1; r < n; r++) {
      if (Math.abs(a[r][col]) > Math.abs(a[pivot][col])) pivot = r;
    }
    if (Math.abs(a[pivot][col]) < 1e-12) return null; // singulière
    if (pivot !== col) [a[col], a[pivot]] = [a[pivot], a[col]];

    const d = a[col][col];
    for (let c = 0; c < 2 * n; c++) a[col][c] /= d;

    for (let r = 0; r < n; r++) {
      if (r === col) continue;
      const f = a[r][col];
      if (f === 0) continue;
      for (let c = 0; c < 2 * n; c++) a[r][c] -= f * a[col][c];
    }
  }
  return a.map((row) => row.slice(n));
}

/* ── Erreur ‖M·M⁻¹ − I‖∞ (audit d'inversion) ────────────────── */
export function identityError(m: MatN, inv: MatN): number {
  let max = 0;
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      let s = 0;
      for (let k = 0; k < N; k++) s += m[i][k] * inv[k][j];
      const e = Math.abs(s - (i === j ? 1 : 0));
      if (e > max) max = e;
    }
  }
  return max;
}

/* ── Formats d'affichage ────────────────────────────────────── */
export const fmtSci = (v: number, digits = 6): string => {
  const sign = v < 0 ? "-" : "+";
  return sign + Math.abs(v).toExponential(digits);
};

export const fmtHex16 = (v: number): string => "0x" + (v & 0xffff).toString(16).toUpperCase().padStart(4, "0");
export const fmtHex32 = (v: number): string => "0x" + (v >>> 0).toString(16).toUpperCase().padStart(8, "0");

export const toBin = (v: number): string => (v >>> 0).toString(2).padStart(32, "0");

export const ipToStr = (o: [number, number, number, number]): string => o.join(".");

/** Parse une IP "a.b.c.d" → tuple, ou null si invalide. */
export function parseIp(s: string): [number, number, number, number] | null {
  const parts = s.trim().split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => {
    if (!/^\d{1,3}$/.test(p.trim())) return NaN;
    return parseInt(p.trim(), 10);
  });
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return nums as [number, number, number, number];
}
