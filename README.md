# ATIBON

**Système souverain de défense numérique** — noyau Rust, bridge Python `atibon_core`, IA défensive, Zero Trust, attestation TPM 2.0 et déploiement durci.

## Architecture

```text
atibon/
├── core-rust/       # DPI, consensus byzantin, crypto/PQC + interfaces HSM/TPM
├── bridge-python/   # package Python atibon_core
├── ml-engine/       # modèles robustes et défense anti-empoisonnement
├── zero-trust/      # mTLS/PQC policy et TPM 2.0
└── deploy/          # Kubernetes + contrôles de conformité
```

L'interface web existante reste au niveau racine (`src/`) pour conserver le produit opérationnel.

## Identité visuelle

ATIBON utilise une arche géométrique comme symbole de portail et de seuil sécurisé, avec glassmorphism, ambre et cyan cybernétique. L'interface ne prétend pas à une certification réglementaire par simple présence de code.

## Sécurité et conformité

Les profils Common Criteria EAL4+ et FIPS dans `deploy/compliance/` sont des **cibles et contrôles de préparation**, pas des certifications. Les primitives post-quantiques, HSM/PKCS#11 et TPM doivent être fournis par des implémentations et équipements validés avant un usage réglementé.

## Build Rust

```bash
cargo check --workspace
cargo test --workspace
```

## Bridge Python

Le module natif est exposé sous `atibon_core._native`; la façade applicative est `atibon_core.AtibonEngine`. Le bridge échoue explicitement si le noyau natif n'est pas disponible.
