# ATIBON

**Système souverain de défense numérique** — noyau Rust, bridge Python atibon_core, IA défensive, Zero Trust, attestation TPM 2.0 et déploiement durci.

## État opérationnel

ATIBON dispose maintenant d'un socle d'enforcement Linux réel via nftables, en complément du DPI Rust, du bridge Python, du suivi de connexions, du moteur de règles fail-closed et de l'audit JSONL.

### Protection d'un serveur Linux

Le binaire `atibon-agent` valide puis applique un ruleset nftables versionné. Le profil fourni bloque par défaut les entrées et autorise uniquement loopback, connexions établies, ICMP/ICMPv6, SSH, HTTP et HTTPS. Il doit être adapté à chaque rôle serveur avant activation.

Voir `deploy/host/README.md`.

## Architecture

```
atibon/
├── core-rust/       # DPI, conntrack, règles fail-closed, consensus, crypto
├── bridge-python/   # package Python atibon_core
├── ml-engine/       # modèles robustes et défense anti-empoisonnement
├── zero-trust/      # mTLS/PQC policy et TPM 2.0
├── deploy/host/     # enforcement Linux nftables + systemd
└── deploy/          # Kubernetes + contrôles de conformité
```

## Production

Le déploiement recommandé est: shadow/observe-only, validation des flux, activation progressive de l'enforcement, puis surveillance continue.

Les profils Common Criteria EAL4+ et FIPS sont des cibles de préparation et ne constituent pas une certification. L'utilisation réelle d'un HSM/PKCS#11, d'un TPM 2.0 et d'un backend PQC dépend du matériel, des bibliothèques système et de la politique cryptographique de l'environnement cible.
