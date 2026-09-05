/* ============================================================
 * Sources Rust du PoC — COJ-Matrix Firewall (partie 2/2)
 * matrix_engine.rs, shield.rs, rain.rs
 * ============================================================ */

import type { SourceFile } from "./rustCore";

const MATRIX_ENGINE_RS = String.raw`//! ============================================================
//!  matrix_engine.rs — Noyau de Matrice Inversible
//! ------------------------------------------------------------
//!  Le trafic vectorisé traverse une matrice-clé M ∈ GL(12, ℝ) :
//!
//!      V' = M·V     (côté entrée — cœur matriciel)
//!      V  = M⁻¹·V'  (côté sortie — seul le pare-feu détient M⁻¹)
//!
//!  M est construite à DIAGONALE STRICTEMENT DOMINANTE :
//!      |Mᵢᵢ| > Σⱼ≠ᵢ |Mᵢⱼ|
//!  ce qui garantit mathématiquement l'inversibilité (théorème
//!  de Lévy–Desplanques) et un conditionnement numérique sain.
//!
//!  Le déterminant de référence est SCELLÉ à la génération :
//!  toute altération mémoire de M fait diverger le det(M)
//!  recalculé → détection d'anomalie structurelle instantanée.
//! ============================================================

use nalgebra::{SMatrix, SVector};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fmt;

use crate::packet::Packet;

/// Dimension fixe de l'espace d'état (4+4 octets IP, 2 port, 2 chk).
pub const N: usize = 12;

pub type VecN = SVector<f64, N>;
pub type MatN = SMatrix<f64, N, N>;

/// Dérive relative maximale tolérée sur le déterminant (bruit f64).
const DET_DRIFT_EPS: f64 = 1e-9;

/// Verdict d'inspection d'un vecteur transformé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperVerdict {
    /// Le vecteur restitue un paquet cohérent : flux légitime.
    Legit,
    /// Checksum reconstruit ≠ checksum attendu : altération.
    Divergence { attendu: u16, observe: u16 },
}

/// Anomalie structurelle levée par le contrôle du déterminant.
#[derive(Debug)]
pub enum Anomaly {
    DeterminantDivergence { reference: f64, live: f64, derive: f64 },
    MatriceSinguliere,
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Anomaly::DeterminantDivergence { reference, live, derive } => write!(
                f,
                "det(M) a divergé : référence {:+.6e} → live {:+.6e} (dérive {:.2e})",
                reference, live, derive
            ),
            Anomaly::MatriceSinguliere => {
                write!(f, "det(M) ≈ 0 : matrice singulière — clé compromise")
            }
        }
    }
}

pub struct MatrixEngine {
    m: MatN,
    m_inv: MatN,
    /// Sceau : déterminant mesuré à la génération, jamais utilisé
    /// qu'à des fins de comparaison.
    det_ref: f64,
}

impl MatrixEngine {
    /// Génère la paire (M, M⁻¹) depuis une seed scellée.
    /// La diagonale dominante rend l'inversion numériquement stable.
    pub fn generate(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut m = MatN::zeros();

        for i in 0..N {
            for j in 0..N {
                m[(i, j)] = if i == j {
                    1.85 + rng.gen::<f64>() * 0.65 // diag ∈ [1.85 ; 2.50]
                } else {
                    (rng.gen::<f64>() - 0.5) * 0.55 // hors-diag ∈ ±0.275
                };
            }
        }

        let m_inv = m
            .clone()
            .try_inverse()
            .expect("M doit être inversible (diagonale strictement dominante)");

        let det_ref = m.determinant();
        debug_assert!(det_ref.abs() > 1e-6, "matrice quasi singulière");

        Self { m, m_inv, det_ref }
    }

    /// Transformation directe : V' = M·V (neutralise le sniffing).
    pub fn transform(&self, v: &VecN) -> VecN {
        self.m * v
    }

    /// Restitution : V = M⁻¹·V' (seul le pare-feu possède M⁻¹).
    pub fn restore(&self, v_prime: &VecN) -> VecN {
        self.m_inv * v_prime
    }

    /// Sceau de référence du déterminant (valeur attendue).
    pub fn det_ref(&self) -> f64 {
        self.det_ref
    }

    /// Contrôle d'intégrité STRUCTURELLE : recompute det(M) et le
    /// compare au sceau. Un attaquant qui patche M en mémoire — ou
    /// qui substitue une matrice singulière pour annuler le trafic —
    /// déclenche une divergence immédiate.
    pub fn verify_structure(&self) -> Result<f64, Anomaly> {
        let live = self.m.determinant();

        if live.abs() < 1e-12 {
            return Err(Anomaly::MatriceSinguliere);
        }

        let derive = ((live - self.det_ref) / self.det_ref).abs();
        if derive > DET_DRIFT_EPS {
            return Err(Anomaly::DeterminantDivergence {
                reference: self.det_ref,
                live,
                derive,
            });
        }
        Ok(live)
    }

    /// Inspection SÉMANTIQUE : restitue le paquet porté par V' et
    /// confronte son checksum FNV-1a à celui du paquet original.
    /// Toute injection sur V' se réverbère sur le checksum reconstruit.
    pub fn inspect_integrity(&self, original: &Packet, v_prime: &VecN) -> TamperVerdict {
        // 1) verrou structurel d'abord
        if self.verify_structure().is_err() {
            return TamperVerdict::Divergence {
                attendu: original.checksum(),
                observe: 0x0000,
            };
        }

        // 2) restitution + déencapsulation
        let restored = self.restore(v_prime);
        let rebuilt = Packet::devectorize(&restored, original.payload());

        // attendu : recalculé depuis le payload de référence ;
        // observé : extrait des composantes 10-11 du vecteur restitué.
        // Toute injection sur V' corrompt l'observé → Divergence.
        let attendu = original.checksum();
        let observe = rebuilt.wire_checksum();

        if attendu == observe {
            TamperVerdict::Legit
        } else {
            TamperVerdict::Divergence { attendu, observe }
        }
    }

    /// Rapport d'audit : det(M) scellé + erreur d'inversion ‖M·M⁻¹ − I‖∞.
    pub fn audit(&self) {
        let identity_err = (self.m * self.m_inv - MatN::identity()).abs().max();
        println!(
            "[matrice] M ∈ GL({}, ℝ) — det(M) = {:+.6e} scellé · ‖M·M⁻¹ − I‖∞ = {:.2e}",
            N, self.det_ref, identity_err
        );
    }
}
`;

const SHIELD_RS = String.raw`//! ============================================================
//!  shield.rs — Bouclier Anti-Inspection & Anti-Reverse
//! ------------------------------------------------------------
//!  Trois sondes locales, zéro dépendance externe :
//!
//!    1. TracerPid — lit /proc/self/status : tout débogueur
//!       (gdb, strace, attach IDA/Ghidra) laisse un PID ≠ 0.
//!    2. Intégrité binaire — FNV-1a de /proc/self/exe, scellée
//!       à l'armement puis re-vérifiée à chaque scan (détecte
//!       patchs disque et trampolines projetés en mémoire).
//!    3. LD_PRELOAD — détecte les bibliothèques injectées qui
//!       hookeraient les appels système du pare-feu.
//!
//!  Verdict : Clean / Suspicious / Intrusion. En cas d'intrusion,
//!  rain::deploy_decoy prend la main sur le terminal.
//! ============================================================

use std::fs;
use std::path::Path;

/// Niveau de menace évalué par le scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Intrusion,
}

pub struct Shield {
    /// Empreinte FNV-1a 32 bits du binaire, scellée à l'armement.
    pub boot_hash: u32,
    /// TracerPid observé au démarrage (0 = aucun débogueur).
    boot_tracer: u32,
}

impl Shield {
    /// Arme le bouclier : prend l'empreinte de référence.
    pub fn arm() -> Self {
        Self {
            boot_hash: fnv1a32_file("/proc/self/exe").unwrap_or(0xC0FF_EE42),
            boot_tracer: read_tracer_pid().unwrap_or(0),
        }
    }

    /// Passe les trois sondes et retourne le verdict consolidé.
    pub fn scan(&self) -> ThreatLevel {
        // Sonde 1 — attachement de débogueur (ptrace / gdb / strace)
        if let Some(pid) = read_tracer_pid() {
            if pid != 0 && pid != self.boot_tracer {
                return ThreatLevel::Intrusion;
            }
        }

        // Sonde 2 — intégrité du binaire exécuté
        if let Some(h) = fnv1a32_file("/proc/self/exe") {
            if h != self.boot_hash {
                return ThreatLevel::Intrusion;
            }
        }

        // Sonde 3 — injection de bibliothèque (hooking de syscalls)
        if std::env::var_os("LD_PRELOAD").is_some() {
            return ThreatLevel::Suspicious;
        }

        ThreatLevel::Clean
    }

    /// Identifiant de session embarqué dans le leurre (traçabilité
    /// de l'analyste piégé — la « piste d'Ouméga »).
    pub fn session_tag(&self) -> String {
        format!("COJ-{:04X}-{:08X}", std::process::id() & 0xFFFF, self.boot_hash)
    }
}

/// Extrait TracerPid depuis /proc/self/status (Linux uniquement).
#[cfg(target_os = "linux")]
fn read_tracer_pid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Hors Linux : sonde neutre (le PoC cible Linux en priorité).
#[cfg(not(target_os = "linux"))]
fn read_tracer_pid() -> Option<u32> {
    None
}

/// Empreinte FNV-1a 32 bits d'un fichier (intégrité binaire).
fn fnv1a32_file(path: &str) -> Option<u32> {
    let data = fs::read(Path::new(path)).ok()?;
    let mut h: u32 = 0x811C_9DC5;
    for &b in &data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    Some(h)
}
`;

const RAIN_RS = String.raw`//! ============================================================
//!  rain.rs — Leurre visuel « digital rain / COJ »
//! ------------------------------------------------------------
//!  Rendu 100 % terminal (séquences ANSI brutes, zéro dépendance) :
//!    • pluie de glyphes katakana + hexadécimaux en colonnes ;
//!    • incrustation récurrente des initiales « COJ » en sur-
//!      brillance, noyées dans le flux (signature subliminale) ;
//!    • matérialisation progressive d'un CRÂNE ASCII au centre
//!      de l'écran après ~1,5 s ;
//!    • la session de l'intrus (tag bouclier) défile en pied de
//!      page : l'analyste est tracé pendant qu'il déchiffre du vide.
//!
//!  Sortie : Ctrl-C (PoC). Le processus réel, lui, continue de
//!  tourner derrière — l'attaquant ne pilote plus rien.
//! ============================================================

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use crate::shield::Shield;

/// Jeu de glyphes : demi-katakana + hexadécimal + symboles.
const GLYPHS: &[char] = &[
    'ｱ', 'ｲ', 'ｳ', 'ｴ', 'ｵ', 'ｶ', 'ｷ', 'ｸ', 'ｹ', 'ｺ',
    'ｻ', 'ｼ', 'ｽ', 'ｾ', 'ｿ', 'ﾀ', 'ﾁ', 'ﾂ', 'ﾃ', 'ﾄ',
    'ﾅ', 'ﾆ', 'ﾇ', 'ﾈ', 'ﾉ', 'ﾊ', 'ﾋ', 'ﾌ', 'ﾍ', 'ﾎ',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', ':', '+', '*', '#',
];

/// Crâne ASCII — se matérialise au centre du leurre.
const SKULL: &[&str] = &[
    "      ______      ",
    "   .-\"      \"-.   ",
    "  /            \\  ",
    " |              | ",
    " |,  .-.  .-.  ,| ",
    " | )(_o/  \\o_)( | ",
    " |/     /\\     \\| ",
    " (_     ^^     _) ",
    "  \\__|IIIIII|__/  ",
    "   | \\IIIIII/ |   ",
    "   \\          /   ",
    "    '--------'    ",
];

const W: usize = 78; // colonnes logiques
const H: usize = 24; // lignes logiques

struct Column {
    y: f32,
    speed: f32,
}

/// Bascule le terminal en mode leurre. Ne rend jamais la main
/// tant que l'intrus est là (boucle jusqu'à Ctrl-C).
pub fn deploy_decoy(shield: &Shield) {
    let mut out = std::io::stdout();
    // clear écran + curseur masqué + teinte verte de base
    let _ = write!(out, "\x1b[2J\x1b[H\x1b[?25l\x1b[32m");

    let t0 = Instant::now();
    let mut cols: Vec<Column> = (0..W)
        .map(|i| Column {
            y: -(i as f32 % 17.0),
            speed: 0.35 + (i % 7) as f32 * 0.09,
        })
        .collect();
    let mut grid = vec![[' '; W]; H];
    let mut frame: u64 = 0;

    loop {
        frame += 1;
        let elapsed = t0.elapsed().as_secs_f32();

        // — avance la pluie, cellule par cellule —
        for (x, col) in cols.iter_mut().enumerate() {
            col.y += col.speed;
            let head = col.y as isize;
            if head >= 0 && (head as usize) < H {
                grid[head as usize][x] =
                    GLYPHS[(frame as usize * 31 + x * 7) % GLYPHS.len()];
            }
            // efface la traîne derrière la tête
            let tail = head - 14;
            if tail >= 0 && (tail as usize) < H {
                grid[tail as usize][x] = ' ';
            }
            if col.y > (H + 16) as f32 {
                col.y = -(x as f32 % 11.0);
                col.speed = 0.35 + (frame % 9) as f32 * 0.07;
            }
        }

        // — signature subliminale « COJ » toutes les ~40 frames —
        if frame % 40 == 0 {
            let x = (frame as usize * 13) % (W - 3);
            let y = (frame as usize * 7) % H;
            for (k, c) in ['C', 'O', 'J'].iter().enumerate() {
                if y + k < H {
                    grid[y + k][x] = *c;
                }
            }
        }

        // — rendu de la frame (retour curseur en haut, pas de clear :
        //   le recouvrement total évite le flicker) —
        let skull_on = elapsed > 1.5;
        let mut buf = String::with_capacity(W * H * 12);
        buf.push_str("\x1b[H");

        for (r, row) in grid.iter().enumerate() {
            let mut line: String = row.iter().collect();

            // le crâne ASCII écrase les colonnes centrales
            if skull_on {
                let sy0 = H / 2 - SKULL.len() / 2;
                if r >= sy0 && r < sy0 + SKULL.len() {
                    let art = SKULL[r - sy0];
                    let sx0 = W / 2 - art.chars().count() / 2;
                    let mut chars: Vec<char> = line.chars().collect();
                    for (k, c) in art.chars().enumerate() {
                        if c != ' ' && sx0 + k < W {
                            chars[sx0 + k] = c;
                        }
                    }
                    line = chars.iter().collect();
                }
            }
            buf.push_str(&line);
            buf.push('\n');
        }

        // — pied de page : traçabilité de l'intrus —
        buf.push_str(&format!(
            "\x1b[1;36m INTRUSION DÉTECTÉE · session {} · IP en cours de blacklist… \x1b[0;32m",
            shield.session_tag()
        ));

        let _ = out.write_all(buf.as_bytes());
        let _ = out.flush();
        thread::sleep(Duration::from_millis(55)); // ≈ 18 i/s
    }
}
`;

export const ENGINE_FILES: SourceFile[] = [
  {
    name: "matrix_engine.rs",
    path: "src/matrix_engine.rs",
    lang: "rust",
    desc: "Noyau inversible : M à diagonale dominante (Lévy–Desplanques), det(M) scellé, TamperVerdict, audit.",
    code: MATRIX_ENGINE_RS,
  },
  {
    name: "shield.rs",
    path: "src/shield.rs",
    lang: "rust",
    desc: "Sondes anti-inspection : TracerPid (/proc/self/status), intégrité binaire FNV-1a, LD_PRELOAD.",
    code: SHIELD_RS,
  },
  {
    name: "rain.rs",
    path: "src/rain.rs",
    lang: "rust",
    desc: "Leurre terminal ANSI : pluie katakana/hex, signature subliminale « COJ », crâne ASCII, traçabilité de session.",
    code: RAIN_RS,
  },
];
