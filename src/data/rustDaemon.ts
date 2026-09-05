/* ============================================================
 * Sources Rust — industrialisation daemon (partie 3/3)
 * config.rs (YAML/serde) + proxy.rs (tokio)
 * ============================================================ */

import type { SourceFile } from "./rustCore";

const CONFIG_RS = String.raw`//! ============================================================
//!  config.rs — Configuration YAML (coj-config.yml)
//! ------------------------------------------------------------
//!  Chargée au démarrage via Config::load. Trois niveaux
//!  d'agressivité pilotent le bouclier :
//!    normal   — sondes périodiques, leurre si intrusion avérée
//!    paranoid — sondes à chaque connexion entrante
//!    matrix   — scan continu + leurre visuel + quarantaine
//!               systématique des IP en divergence
//! ============================================================

use serde::Deserialize;

fn default_true() -> bool {
    true
}

/// Niveau d'agressivité du bouclier anti-tampering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Aggression {
    Normal,
    Paranoid,
    Matrix,
}

/// [firewall] — ports protégés et sous-réseaux de confiance.
#[derive(Debug, Deserialize)]
pub struct FirewallCfg {
    pub protected_ports: Vec<u16>,
    #[serde(default)]
    pub trusted_subnets: Vec<String>,
}

/// [matrix] — paramètres du noyau inversible.
#[derive(Debug, Deserialize)]
pub struct MatrixCfg {
    /// ⚠ En production : seed issue d'un HSM/TPM, jamais en clair.
    pub seed: u64,
    #[serde(default = "default_dim")]
    pub dimension: usize,
    #[serde(default = "default_eps")]
    pub det_drift_eps: f64,
}

fn default_dim() -> usize {
    12
}
fn default_eps() -> f64 {
    1e-9
}

/// [shield.watch] — sondes activables individuellement.
#[derive(Debug, Deserialize, Default)]
pub struct WatchCfg {
    #[serde(default = "default_true")]
    pub tracer_pid: bool,
    #[serde(default = "default_true")]
    pub binary_integrity: bool,
    #[serde(default = "default_true")]
    pub ld_preload: bool,
}

/// [shield.response] — riposte en cas de divergence ou d'intrusion.
#[derive(Debug, Deserialize, Default)]
pub struct ResponseCfg {
    #[serde(default = "default_quarantine")]
    pub quarantine_hours: u64,
    #[serde(default = "default_true")]
    pub visual_decoy: bool,
    #[serde(default = "default_true")]
    pub trace_session: bool,
}

fn default_quarantine() -> u64 {
    24
}

/// [shield] — agressivité + sondes + riposte.
#[derive(Debug, Deserialize)]
pub struct ShieldCfg {
    pub aggression: Aggression,
    #[serde(default)]
    pub watch: WatchCfg,
    #[serde(default)]
    pub response: ResponseCfg,
}

/// Racine du fichier coj-config.yml.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub firewall: FirewallCfg,
    pub matrix: MatrixCfg,
    pub shield: ShieldCfg,
}

impl Config {
    /// Charge et valide la configuration YAML.
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&raw)?;

        if cfg.firewall.protected_ports.is_empty() {
            return Err("firewall.protected_ports ne peut pas être vide".into());
        }
        Ok(cfg)
    }

    /// Un sous-réseau de confiance court-circuite la quarantaine
    /// (PoC : comparaison de préfixe /24 ; production : crate ipnet).
    pub fn is_trusted(&self, ip: &str) -> bool {
        self.firewall.trusted_subnets.iter().any(|subnet| {
            subnet.ends_with("/24") && ip.starts_with(&subnet[..subnet.len() - 3])
        })
    }
}
`;

const PROXY_RS = String.raw`//! ============================================================
//!  proxy.rs — Proxy réseau & encapsulation sûre (tokio)
//! ------------------------------------------------------------
//!  Un listener TCP asynchrone par port protégé (défini dans
//!  coj-config.yml). Chaque flux entrant transporte une
//!  TRAME TUNNEL COJ :
//!
//!      [MAGIC "COJ1" · 4 o][longueur · 2 o][V' — 12 × f64 LE]
//!      [payload applicatif]
//!
//!  La transformation matricielle voyage À L'INTÉRIEUR du
//!  tunnel TCP standard : les normes réseau ne sont jamais
//!  cassées, seul le contenu applicatif est vectorisé/obfusqué.
//!
//!  À chaque trame : inspection (det(M) scellé + checksum
//!  FNV-1a), journalisation colorée temps réel, et en cas de
//!  divergence → fermeture immédiate du flux + blacklist de
//!  l'IP source pendant « quarantine_hours » heures.
//! ============================================================

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use colored::Colorize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::config::{Aggression, Config};
use crate::matrix_engine::{MatrixEngine, TamperVerdict, VecN};
use crate::packet::Packet;
use crate::rain;
use crate::shield::{Shield, ThreatLevel};

/// Signature magique des trames tunnel COJ.
pub const MAGIC: &[u8; 4] = b"COJ1";

/// État partagé du proxy : moteur matriciel + blacklist à TTL.
#[derive(Clone)]
pub struct Proxy {
    cfg: Arc<Config>,
    engine: Arc<MatrixEngine>,
    shield: Arc<Shield>,
    /// IP source → instant de mise en quarantaine.
    blacklist: Arc<Mutex<HashMap<IpAddr, Instant>>>,
}

impl Proxy {
    pub fn new(cfg: Arc<Config>, engine: Arc<MatrixEngine>, shield: Arc<Shield>) -> Self {
        Self {
            cfg,
            engine,
            shield,
            blacklist: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Démarre un listener par port protégé.
    /// (UDP : même schéma via tokio::net::UdpSocket + datagrammes.)
    pub async fn run(self) -> std::io::Result<()> {
        for port in &self.cfg.firewall.protected_ports {
            let listener = TcpListener::bind(("0.0.0.0", *port)).await?;
            println!(
                "{}",
                format!("[proxy  ] écoute active : 0.0.0.0:{}", port).green()
            );

            let proxy = self.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            let p = proxy.clone();
                            tokio::spawn(async move { p.handle(stream, peer).await });
                        }
                        Err(e) => eprintln!("{}", format!("[proxy  ] accept : {}", e).red()),
                    }
                }
            });
        }

        // le daemon vit tant que le superviseur (systemd) le maintient
        std::future::pending::<()>().await;
        Ok(())
    }

    /// Traitement d'un flux : quarantaine → bouclier → trame → inspection.
    async fn handle(&self, mut stream: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();

        // 1) IP déjà blacklistée ? fermeture sans un mot.
        {
            let bl = self.blacklist.lock().await;
            if let Some(t0) = bl.get(&ip) {
                let ttl_secs = self.cfg.shield.response.quarantine_hours * 3600;
                if t0.elapsed().as_secs() < ttl_secs && !self.cfg.is_trusted(&ip.to_string()) {
                    println!(
                        "{}",
                        format!("[proxy  ] {} — quarantaine active, flux rejeté.", ip).red()
                    );
                    return; // drop du TcpStream = fermeture immédiate
                }
            }
        }

        // 2) modes paranoid/matrix : rescan du bouclier à chaque connexion
        if self.cfg.shield.aggression != Aggression::Normal
            && self.shield.scan() == ThreatLevel::Intrusion
        {
            println!(
                "{}",
                "[proxy  ] ██ reverse engineering du daemon détecté — leurre déclenché."
                    .red()
                    .bold()
            );
            rain::deploy_decoy(&self.shield);
            return;
        }

        // 3) lecture de l'en-tête de trame tunnel COJ
        let mut header = [0u8; 6];
        if stream.read_exact(&mut header).await.is_err() {
            return;
        }
        if &header[0..4] != MAGIC {
            println!(
                "{}",
                format!("[proxy  ] {} — magic inconnu, flux ignoré.", ip).yellow()
            );
            return;
        }
        let vec_len = u16::from_le_bytes([header[4], header[5]]) as usize; // 96 = 12 × f64
        if vec_len != 12 * 8 {
            return; // trame malformée
        }

        // 4) désérialisation de V' (12 × f64 little-endian)
        let mut buf = vec![0u8; vec_len];
        if stream.read_exact(&mut buf).await.is_err() {
            return;
        }
        let mut v_prime = VecN::zeros();
        for (i, chunk) in buf.chunks_exact(8).enumerate() {
            v_prime[i] = f64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 5) lecture du payload applicatif (borné à 64 Kio)
        let mut payload: Vec<u8> = Vec::new();
        let _ = stream.read_buf(&mut payload).await;
        payload.truncate(65_536);

        // 6) inspection matricielle : det(M) scellé + checksum FNV-1a
        let reference = Packet::new([0, 0, 0, 0], [0, 0, 0, 0], 0, &payload);
        match self.engine.inspect_integrity(&reference, &v_prime) {
            TamperVerdict::Legit => {
                let v = self.engine.restore(&v_prime);
                println!(
                    "{}",
                    format!(
                        "[proxy  ] {} — trame légitime, V restitué (‖V‖∞ = {:.1}).",
                        ip,
                        v.abs().max()
                    )
                    .green()
                );
                // → passerelle Egress : VLAN dynamique + chiffrement E2E
                let _ = stream.write_all(b"COJ-OK").await;
            }
            TamperVerdict::Divergence { attendu, observe } => {
                println!(
                    "{}",
                    format!(
                        "[ALERTE ] {} — divergence chk attendu {:04X} ≠ observé {:04X}.",
                        ip, attendu, observe
                    )
                    .red()
                    .bold()
                );
                self.blacklist.lock().await.insert(ip, Instant::now());
                println!(
                    "{}",
                    format!(
                        "[ALERTE ] {} blacklistée {} h — quarantaine appliquée.",
                        ip, self.cfg.shield.response.quarantine_hours
                    )
                    .red()
                );
                // mode matrix : leurre visuel côté session attaquante
                if self.cfg.shield.response.visual_decoy
                    && self.cfg.shield.aggression == Aggression::Matrix
                {
                    rain::deploy_decoy(&self.shield);
                }
            }
        }
    }
}
`;

export const DAEMON_FILES: SourceFile[] = [
  {
    name: "config.rs",
    path: "src/config.rs",
    lang: "rust",
    desc: "Parsing de coj-config.yml (serde_yaml) : ports protégés, sous-réseaux, agressivité normal/paranoid/matrix.",
    code: CONFIG_RS,
  },
  {
    name: "proxy.rs",
    path: "src/proxy.rs",
    lang: "rust",
    desc: "Proxy TCP tokio : trames tunnel COJ1, inspection matricielle par flux, logs colorés, blacklist IP à TTL.",
    code: PROXY_RS,
  },
];
