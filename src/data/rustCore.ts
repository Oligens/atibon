/* ============================================================
 * Sources Rust du PoC — COJ-Matrix Firewall (partie 1/2)
 * Arborescence, Cargo.toml, main.rs, packet.rs
 * ============================================================ */

export interface SourceFile {
  name: string;
  path: string;
  lang: "rust" | "toml";
  desc: string;
  code: string;
}

export const PROJECT_TREE = `coj-matrix-firewall/
├── Cargo.toml              ← nalgebra · rand · tokio · serde(_yaml) · colored
├── coj-config.yml          ← ports protégés, règles, agressivité du bouclier
└── src/
    ├── main.rs             ← orchestration : bouclier → cycle matriciel → proxy
    ├── config.rs           ← parsing YAML (serde) · niveaux normal/paranoid/matrix
    ├── packet.rs           ← paquet simulé + vectorisation dim. 12 + FNV-1a
    ├── matrix_engine.rs    ← noyau inversible : M, M⁻¹, det(M) scellé
    ├── proxy.rs            ← proxy TCP tokio : tunnel COJ, logs, blacklist IP
    ├── shield.rs           ← anti-tampering : TracerPid, intégrité, LD_PRELOAD
    └── rain.rs             ← leurre visuel : digital rain + crâne ASCII + « COJ »`;

const CARGO_TOML = String.raw`[package]
name = "coj-matrix-firewall"
version = "0.1.0"
edition = "2021"
authors = ["COJ Security Lab"]
description = "PoC industrialisable — proxy réseau tokio, noyau de matrice inversible, bouclier anti-tampering et leurre visuel digital rain."

[dependencies]
# Algèbre linéaire : SMatrix<f64, 12, 12>, déterminant, inverse exacte.
nalgebra = "0.33"
# Génération déterministe de la matrice-clé M depuis une seed scellée.
rand = "0.8"
# Runtime asynchrone du proxy TCP/UDP (listeners par port protégé).
tokio = { version = "1", features = ["full"] }
# (Dé)sérialisation de coj-config.yml
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
# Journalisation temps réel colorée du proxy
colored = "2"

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
//!    cargo run --release -- --serve      # cycle nominal puis proxy tokio
//!    COJ_FORCE_INTRUSION=1 cargo run     # force le leurre visuel
//! ============================================================

mod config;
mod matrix_engine;
mod packet;
mod proxy;
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
    if out.wire_matches() {
        println!(
            "[egress ] checksum FNV-1a 0x{:04X} valide — réencapsulé VLAN dynamique 0x{:02X}.",
            out.wire_checksum(),
            out.egress_vlan()
        );
        out.dump();
        println!();
        println!("[coj    ] ✔ CYCLE COMPLET NOMINAL — trafic restitué à l'identique.");
    } else {
        println!("[egress ] ✘ rupture d'intégrité en sortie — leurre activé.");
        rain::deploy_decoy(&shield);
        return;
    }

    // ── Étape 9 · Passage en mode daemon (optionnel) ─────────────
    // --serve démarre le proxy tokio sur les ports définis dans
    // coj-config.yml ; le processus vit ensuite sous systemd.
    if std::env::args().any(|a| a == "--serve") {
        match config::Config::load("coj-config.yml") {
            Ok(cfg) => {
                let proxy = proxy::Proxy::new(
                    std::sync::Arc::new(cfg),
                    std::sync::Arc::new(engine),
                    std::sync::Arc::new(shield),
                );
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("runtime tokio");
                println!("[coj    ] bascule en mode daemon — proxy tokio armé.");
                rt.block_on(proxy.run()).expect("proxy");
            }
            Err(e) => println!("[config ] ✘ coj-config.yml illisible : {}", e),
        }
    } else {
        println!("[coj    ] astuce : l'argument --serve démarre le proxy tokio (coj-config.yml).");
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
    payload: Vec<u8>, // transporté hors-bande, scellé par son checksum
    /// Checksum tel que TRANSPORTÉ dans le vecteur (composantes 10-11).
    /// C'est lui qu'on confronte au checksum recalculé : toute
    /// altération de V' le corrompt → détection de divergence.
    wire_checksum: u16,
}

impl Packet {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], port: u16, payload: &[u8]) -> Self {
        let mut p = Self {
            src_ip,
            dst_ip,
            port,
            payload: payload.to_vec(),
            wire_checksum: 0,
        };
        p.wire_checksum = p.checksum();
        p
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
    /// Le checksum est EXTRAIT DU VECTEUR (composantes 10-11) :
    /// il constitue la preuve de non-altération du flux transformé.
    pub fn devectorize(v: &VecN, payload: &[u8]) -> Self {
        let b = |i: usize| v[i].round().clamp(0.0, 255.0) as u8;
        let port = ((b(8) as u16) << 8) | b(9) as u16;
        Self {
            src_ip: [b(0), b(1), b(2), b(3)],
            dst_ip: [b(4), b(5), b(6), b(7)],
            port,
            payload: payload.to_vec(),
            wire_checksum: ((b(10) as u16) << 8) | b(11) as u16,
        }
    }

    /// Checksum tel que reçu sur le fil (porté par le vecteur).
    pub fn wire_checksum(&self) -> u16 {
        self.wire_checksum
    }

    /// Intégrité bout-en-bout : checksum transporté == recalculé.
    pub fn wire_matches(&self) -> bool {
        self.wire_checksum == self.checksum()
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

export const CORE_FILES: SourceFile[] = [
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
];
