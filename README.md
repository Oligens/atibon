# ATIBON

**Système souverain de défense numérique** — noyau Rust, bridge Python atibon_core, IA défensive, Zero Trust, attestation TPM 2.0 et déploiement durci.

## État opérationnel

ATIBON dispose d'un socle d'enforcement Linux via nftables, en complément du DPI Rust, du bridge Python, du suivi de connexions, du moteur de règles fail-closed et de l'audit JSONL.

### Protection d'un serveur Linux

Le binaire `atibon-agent` valide puis applique un ruleset nftables versionné. Le profil fourni bloque par défaut les entrées et autorise uniquement loopback, connexions établies, ICMP/ICMPv6, SSH, HTTP et HTTPS. Il doit être adapté à chaque rôle serveur avant activation.

Voir `deploy/host/README.md`.

## Egress et adresse IP

ATIBON ne rend pas une adresse IP « invisible » et ne permet pas d'usurper arbitrairement une adresse source. Pour une sortie via confidentialité, le flux réel est :

```text
IP interne
   |
   v
ATIBON
   |
   v
policy / réputation / risque
   |
   +---- ALLOW --------------------------> sortie normale
   |
   +---- QUARANTINE --------------------> blocage contrôlé
   |
   +---- PRIVACY ROUTE
             |
             v
      relais approuvé
             |
             v
        NAT / proxy
             |
             v
       IP d'egress attribuée
       au relais/fournisseur
             |
             v
       serveur distant
```

Le moteur de décision sélectionne uniquement le relais approuvé fourni par la configuration. Il ne prend aucun champ d'« IP source à usurper », ne génère pas d'adresse IP publique arbitraire et ne réécrit pas lui-même l'adresse source. La traduction NAT effective est une fonction du dataplane réseau/du fournisseur de relais et doit utiliser une adresse légitimement attribuée à ce relais ou à l'environnement de sortie.

Voir `docs/EGRESS.md` pour les invariants et le modèle Shadow/Enforce.

## Architecture

```text
Client / serveur interne
        |
        v
      ATIBON
   [DPI + policy]
        |
        +---- ALLOW ------> réseau normal ------> serveur distant
        |
        +---- QUARANTINE -> blocage contrôlé
        |
        +---- PRIVACY ROUTE
                 |
                 v
          relais approuvé
                 |
                 v
             NAT/proxy
                 |
                 v
       IP d'egress attribuée
                 |
                 v
          serveur distant
                 |
                 v
              audit
```

```text
atibon/
├── core-rust/       # DPI, conntrack, règles fail-closed, egress, consensus, crypto
├── bridge-python/   # package Python atibon_core
├── ml-engine/       # modèles robustes et défense anti-empoisonnement
├── zero-trust/      # mTLS/PQC policy et TPM 2.0
├── deploy/host/     # enforcement Linux nftables + systemd
└── deploy/          # Kubernetes + contrôles de conformité
```

## Production

Le déploiement recommandé est: shadow/observe-only, validation des flux, activation progressive de l'enforcement, puis surveillance continue.

Les profils Common Criteria EAL4+ et FIPS sont des cibles de préparation et ne constituent pas une certification. L'utilisation réelle d'un HSM/PKCS#11, d'un TPM 2.0, d'un NAT/proxy et d'un backend PQC dépend du matériel, des bibliothèques système, des adresses réellement attribuées et de la politique de l'environnement cible.
