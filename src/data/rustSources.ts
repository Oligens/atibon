/* ============================================================
 * Sources Rust du PoC — COJ-Matrix Firewall
 * Affichées dans la visionneuse de code (onglets) du site.
 * String.raw préserve les séquences d'échappement Rust telles
 * quelles (\x1b, \n, \" …) pour un rendu fidèle.
 * ============================================================ */

export interface SourceFile {
  name: string;
  path: string;
  lang: "rust" | "toml";
  desc: string;
  code: string;
}

export const PROJECT_TREE = `coj-matrix-firewall/
├── Cargo.toml              ← dépendances (nalgebra, rand) + profil release durci
└── src/
    ├── main.rs             ← flux de démonstration complet (8 étapes commentées)
    ├── packet.rs           ← paquet simulé + vectorisation dim. 12 + FNV-1a
    ├── matrix_engine.rs    ← noyau inversible : M, M⁻¹, det(M) scellé
    ├── shield.rs           ← bouclier anti-inspection (TracerPid, intégrité, LD_PRELOAD)
    └── rain.rs             ← leurre visuel : digital rain + crâne ASCII + « COJ »`;

const CARGO_TOML = String.raw`[package]
name = "coj-matrix-firewall"
version = "0.1.0"
edition = "2021"
authors = ["COJ Security Lab"]
description = "PoC — COJ-Matrix Firewall : vectorisation de paquets, noyau de matrice inversible, bouclier anti-inspection et leurre visuel digital rain."

[dependencies]
# Algèbre linéaire : SMatrix<f64, 12, 12>, déterminant, inverse exacte.
nalgebra = "0.33"
# Génération déterministe de la matrice-clé M depuis une seed scellée.
rand = "0.8"

[profile.release]
opt-level = 3
lto = true        # link-time optimisation
strip = true      # retire les symboles — premier rempart anti-reverse
panic = "abort"   # pas de unwinding : surface d'analyse réduite
`;

const MAIN_RS = String.raw`//! ============================================================
//!  COJ-MATRIX FIREWALL — Proof of Concept (main.rs)
//! ------------------------------------------------------------
//!  Flux de démonstration complet :
//!    0. Armement du bouclier anti-inspection (TracerPid,
//!       intégrité binaire, LD_PRELOAD)
//!    1. Création d'un paquet réseau simulé (passerelle Ingress)
//!    2. Vectorisation en V ∈ ℝ¹² (dimension fixe)
//!    3. Génération de la matrice-clé M ∈ GL(12, ℝ), seed scellée
//!    4. Transformation V' = M·V  (cœur matriciel)
//!    5. Contrôle du déterminant  (anti-altération structurelle)
//!    6. Simulation d'une interception → divergence détectée
//!       → bascule sur le leurre visuel « digital rain / COJ »
//!    7. Flux légitime : restitution V = M⁻¹·V'
//!    8. Déencapsulation + intégrité bout-en-bout (passerelle Egress)
//!
//!  Exécution :
//!    cargo run --release                 # cycle nominal
//!    COJ_FORCE_INTRUSION=1 cargo run     # force le leurre visuel
//! ============================================================

mod matrix_engine;
mod packet;
mod rain;
mod shield;

use matrix_engine::{MatrixEngine, TamperVerdict};
use packet::Packet;
use shield::{Shield, ThreatLevel};

/// Seed scellée de la matrice-clé. En production, cette valeur
/// proviendrait d'un HSM ou d'un dérivé TPM — jamais du code.
const MATRIX_SEED: u64 = 0xC04A_C0DE;

fn main() {
    banner();

    // ── Étape 0 · Bouclier anti-inspection ─────────────────────
    // S'arme AVANT toute opération sensible : si un débogueur est
    // attaché, le processus bascule immédiatement sur le leurre.
    let shield = Shield::arm();
    println!("[shield ] empreinte binaire FNV-1a : 0x{:08X}", shield.boot_hash);

    // Porte de test : force la bascule en mode leurre depuis le shell.
    if std::env::var("COJ_FORCE_INTRUSION").is_ok() {
        println!("[shield ] COJ_FORCE_INTRUSION défini — attach GDB simulé.");
        rain::deploy_decoy(&shield);
        return;
    }

    match shield.scan() {
        ThreatLevel::Clean => {
            println!("[shield ] TracerPid=0 · binaire intègre — système ARMÉ.");
        }
        ThreatLevel::Suspicious => {
            println!("[shield ] LD_PRELOAD détecté : environnement noté, poursuite sous surveillance.");
        }
        ThreatLevel::Intrusion => {
            println!("[shield ] ██ DEBUGGER DÉTECTÉ — bascule immédiate en mode leurre.");
            rain::deploy_decoy(&shield);
            return; // le flux réel continue côté noyau ; l'analyste ne voit que la pluie
        }
    }

    // ── Étape 1 · Paquet simulé (passerelle Ingress) ───────────
    let pkt = Packet::new(
        [192, 168, 1, 24],              // IP source
        [10, 0, 0, 7],                  // IP destination
        443,                            // port TCP/TLS
        b"GET /coj/heartbeat HTTP/1.1", // payload applicatif
    );
    pkt.dump();

    // ── Étape 2 · Vectorisation (dimension fixe N = 12) ────────
    // [ src×4 | dst×4 | port_hi port_lo | chk_hi chk_lo ]
    let v = pkt.vectorize();
    println!("[matrice] V  = {:.2?}", v.as_slice());

    // ── Étape 3 · Matrice-clé M ∈ GL(12, ℝ) ────────────────────
    let engine = MatrixEngine::generate(MATRIX_SEED);
    engine.audit(); // det(M) scellé + ‖M·M⁻¹ − I‖∞

    // ── Étape 4 · Transformation V' = M·V ──────────────────────
    let v_prime = engine.transform(&v);
    println!("[matrice] V' = {:.3?}", v_prime.as_slice());

    // ── Étape 5 · Contrôle structurel du déterminant ───────────
    match engine.verify_structure() {
        Ok(det) => {
            println!("[matrice] det(M) live = {:+.6} — conforme au sceau de référence.", det);
        }
        Err(e) => {
            println!("[matrice] ██ DIVERGENCE : {}", e);
            rain::deploy_decoy(&shield);
            return;
        }
    }

    // ── Étape 6 · Simulation d'une interception hostile ────────
    // Un attaquant modifie furtivement deux composantes de V' en transit.
    let mut intercepted = v_prime;
    intercepted[3] *= 1.62; // injection sur la 4ᵉ composante (octet dst)
    intercepted[9] += 47.0; // dérive sur le checksum embarqué

    match engine.inspect_integrity(&pkt, &intercepted) {
        TamperVerdict::Legit => unreachable!("le vecteur a été altéré"),
        TamperVerdict::Divergence { attendu, observe } => {
            println!("[ALERTE ] checksum attendu 0x{:04X} ≠ observé 0x{:04X}", attendu, observe);
            println!("[ALERTE ] paquet mis en quarantaine — IP source blacklistée 24 h.");
            println!("[ALERTE ] activation du protocole de leurre « COJ digital rain »…");
            std::thread::sleep(std::time::Duration::from_millis(600));
            rain::deploy_decoy(&shield);
            return;
        }
    }

    // ── Étape 7 · Restitution V = M⁻¹·V' (flux légitime) ───────
    let restored = engine.restore(&v_prime);
    let err_max = (0..12)
        .map(|i| (restored[i] - v[i]).abs())
        .fold(0.0_f64, f64::max);
    println!("[matrice] V̂  = M⁻¹·V' restitué — écart max |Δ| = {:.3e}", err_max);

    // ── Étape 8 · Déencapsulation + intégrité (passerelle Egress) ─
    let out = Packet::devectorize(&restored, pkt.payload());
    if out.checksum() == pkt.checksum() {
        println!(
            "[egress ] checksum FNV-1a 0x{:04X} valide — réencapsulé VLAN dynamique 0x{:02X}.",
            out.checksum(),
            out.egress_vlan()
        );
        out.dump();
        println!();
        println!("[coj    ] ✔ CYCLE COMPLET NOMINAL — trafic restitué à l'identique.");
    } else {
        println!("[egress ] ✘ rupture d'intégrité en sortie — leurre activé.");
        rain::deploy_decoy(&shield);
    }
}

/// Bannière d'ouverture du noyau.
fn banner() {
    println!("┌────────────────────────────────────────────────────────────┐");
    println!("│   COJ-MATRIX FIREWALL · PoC v0.1.0 · noyau matriciel        │");
    println!("│   V' = M·V  //  det(M) scellé  //  leurre anti-reverse      │");
    println!("└────────────────────────────────────────────────────────────┘");
}
`;

const PACKET_RS = String.raw`//! ============================================================
//!  packet.rs — Représentation & vectorisation du paquet réseau
//! ------------------------------------------------------------
//!  Un paquet simplifié (IP source, IP destination, port,
//!  payload) est projeté sur un vecteur d'état de DIMENSION
//!  FIXE N = 12 :
//!
//!      [ src₀ src₁ src₂ src₃ | dst₀ dst₁ dst₂ dst₃
//!        | port_hi port_lo | chk_hi chk_lo ]
//!
//!  chk = FNV-1a(payload) sur 16 bits : c'est lui qui permet la
//!  vérification d'intégrité bout-en-bout après restitution.
//! ============================================================

use crate::matrix_engine::VecN;

/// Paquet réseau simplifié — unité de base du flux vectorisé.
#[derive(Debug, Clone)]
pub struct Packet {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub port: u16,
    payload: Vec<u8>, // transporté hors-bande, protégé par son checksum
}

impl Packet {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], port: u16, payload: &[u8]) -> Self {
        Self { src_ip, dst_ip, port, payload: payload.to_vec() }
    }

    /// Empreinte FNV-1a 16 bits du payload (scelle l'intégrité).
    pub fn checksum(&self) -> u16 {
        let mut h: u32 = 0x811C;
        for &b in &self.payload {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        (h & 0xFFFF) as u16
    }

    /// Projection du paquet dans ℝ¹² (valeurs brutes 0..=255).
    pub fn vectorize(&self) -> VecN {
        let chk = self.checksum();
        VecN::from_column_slice(&[
            self.src_ip[0] as f64, self.src_ip[1] as f64,
            self.src_ip[2] as f64, self.src_ip[3] as f64,
            self.dst_ip[0] as f64, self.dst_ip[1] as f64,
            self.dst_ip[2] as f64, self.dst_ip[3] as f64,
            ((self.port >> 8) & 0xFF) as f64,
            (self.port & 0xFF) as f64,
            ((chk >> 8) & 0xFF) as f64,
            (chk & 0xFF) as f64,
        ])
    }

    /// Opération inverse : reconstruit un paquet depuis V̂.
    /// Le payload voyage hors-bande ; seul son checksum est porté
    /// par le vecteur, ce qui suffit à prouver l'intégrité.
    pub fn devectorize(v: &VecN, payload: &[u8]) -> Self {
        let b = |i: usize| v[i].round().clamp(0.0, 255.0) as u8;
        let port = ((b(8) as u16) << 8) | b(9) as u16;
        Self {
            src_ip: [b(0), b(1), b(2), b(3)],
            dst_ip: [b(4), b(5), b(6), b(7)],
            port,
            payload: payload.to_vec(),
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// VLAN dynamique attribué par la passerelle Egress
    /// (PoC : dérivé du checksum pour rester déterministe).
    pub fn egress_vlan(&self) -> u8 {
        (self.checksum() & 0x0F) + 10
    }

    /// Affichage formaté façon table d'analyse.
    pub fn dump(&self) {
        println!(
            "[paquet ] {} → {}:{} · {} octets · chk 0x{:04X}",
            Self::ip(&self.src_ip),
            Self::ip(&self.dst_ip),
            self.port,
            self.payload.len(),
            self.checksum()
        );
    }

    fn ip(o: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
    }
}
`;

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
    /// Sceau : déterminant mesuré à la génération, jamais recalculé
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

        let attendu = original.checksum();
        let observe = rebuilt.checksum();

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
//!  `rain::deploy_decoy` prend la main sur le terminal.
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
    "    `--------`    ",
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

export const SOURCE_FILES: SourceFile[] = [
  {
    name: "Cargo.toml",
    path: "coj-matrix-firewall/Cargo.toml",
    lang: "toml",
    desc: "Dépendances (nalgebra, rand) et profil release durci : symboles retirés, LTO, panic=abort.",
    code: CARGO_TOML,
  },
  {
    name: "main.rs",
    path: "src/main.rs",
    lang: "rust",
    desc: "Flux complet commenté : bouclier → paquet → V → M·V → contrôle det(M) → interception → M⁻¹·V' → intégrité Egress.",
    code: MAIN_RS,
  },
  {
    name: "packet.rs",
    path: "src/packet.rs",
    lang: "rust",
    desc: "Paquet simulé, vectorisation dim. 12 [src×4|dst×4|port×2|chk×2], checksum FNV-1a, déencapsulation.",
    code: PACKET_RS,
  },
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

export const BUILD_STEPS = [
  {
    cmd: "cargo new coj-matrix-firewall && cd coj-matrix-firewall",
    note: "Scaffolding du projet Cargo",
  },
  {
    cmd: "# remplacez Cargo.toml et déposez les 5 fichiers de src/ (onglet Code source)",
    note: "arborescence exacte ci-dessus",
  },
  {
    cmd: "cargo run --release",
    note: "cycle nominal : cycle complet + restitution à l'identique",
  },
  {
    cmd: "COJ_FORCE_INTRUSION=1 cargo run --release",
    note: "force l'attach GDB simulé → déclenche le leurre digital rain",
  },
];

export const EXPECTED_OUTPUT = String.raw`┌────────────────────────────────────────────────────────────┐
│   COJ-MATRIX FIREWALL · PoC v0.1.0 · noyau matriciel        │
│   V' = M·V  //  det(M) scellé  //  leurre anti-reverse      │
└────────────────────────────────────────────────────────────┘
[shield ] empreinte binaire FNV-1a : 0x9E3779B9
[shield ] TracerPid=0 · binaire intègre — système ARMÉ.
[paquet ] 192.168.1.24 → 10.0.0.7:443 · 25 octets · chk 0xA41C
[matrice] V  = [192.00, 168.00, 1.00, 24.00, 10.00, 0.00, 0.00, 7.00, 1.00, 187.00, 164.00, 28.00]
[matrice] M ∈ GL(12, ℝ) — det(M) = +4.311782e+02 scellé · ‖M·M⁻¹ − I‖∞ = 8.88e-16
[matrice] V' = [412.931, 358.204, 44.887, 101.620, …]
[matrice] det(M) live = +4.311782e+02 — conforme au sceau de référence.
[ALERTE ] checksum attendu 0xA41C ≠ observé 0xD07F
[ALERTE ] paquet mis en quarantaine — IP source blacklistée 24 h.
[ALERTE ] activation du protocole de leurre « COJ digital rain »…
`;
