/* ============================================================
 * Sources Rust — agrégation, guide de build & sortie attendue
 * ============================================================ */

export { PROJECT_TREE, CORE_FILES } from "./rustCore";
export { ENGINE_FILES } from "./rustEngine";
export { DAEMON_FILES } from "./rustDaemon";

import { CORE_FILES, PROJECT_TREE, type SourceFile } from "./rustCore";
import { ENGINE_FILES } from "./rustEngine";
import { DAEMON_FILES } from "./rustDaemon";

export const SOURCE_FILES: SourceFile[] = [...CORE_FILES, ...DAEMON_FILES, ...ENGINE_FILES];

export const BUILD_STEPS: { cmd: string; note: string }[] = [
  {
    cmd: "cargo new coj-matrix-firewall && cd coj-matrix-firewall",
    note: "scaffolding du projet Cargo",
  },
  {
    cmd: "# remplacer Cargo.toml + déposer les 7 fichiers dans src/ (onglets Code source)",
    note: "arborescence exacte affichée ci-dessus",
  },
  {
    cmd: "# déposer coj-config.yml à la racine (section Déploiement)",
    note: "ports protégés, règles de filtrage, agressivité du bouclier",
  },
  {
    cmd: "cargo run --release",
    note: "cycle nominal : transformation, restitution, intégrité validée",
  },
  {
    cmd: "COJ_FORCE_INTRUSION=1 cargo run --release",
    note: "force l'attach GDB simulé → déclenche le leurre digital rain",
  },
];

export const EXPECTED_OUTPUT = [
  "┌────────────────────────────────────────────────────────────┐",
  "│   COJ-MATRIX FIREWALL · PoC v0.1.0 · noyau matriciel        │",
  "│   V' = M·V  //  det(M) scellé  //  leurre anti-reverse      │",
  "└────────────────────────────────────────────────────────────┘",
  "[shield ] empreinte binaire FNV-1a : 0x9E3779B9",
  "[shield ] TracerPid=0 · binaire intègre — système ARMÉ.",
  "[paquet ] 192.168.1.24 → 10.0.0.7:443 · 25 octets · chk 0xA41C",
  "[matrice] V  = [192.00, 168.00, 1.00, 24.00, 10.00, 0.00, 0.00, 7.00, 1.00, 187.00, 164.00, 28.00]",
  "[matrice] M ∈ GL(12, ℝ) — det(M) = +4.311782e+02 scellé · ‖M·M⁻¹ − I‖∞ = 8.88e-16",
  "[matrice] V' = [412.931, 358.204, 44.887, 101.620, 63.550, …]",
  "[matrice] det(M) live = +4.311782e+02 — conforme au sceau de référence.",
  "[ALERTE ] checksum attendu 0xA41C ≠ observé 0xD07F",
  "[ALERTE ] paquet mis en quarantaine — IP source blacklistée 24 h.",
  "[ALERTE ] activation du protocole de leurre « COJ digital rain »…",
].join("\n");

export const PROJECT_TREE_TEXT = PROJECT_TREE;
