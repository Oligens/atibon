# ATIBON Egress — routage, NAT et Shadow Mode

## Principe de réalité réseau

ATIBON ne « rend pas l'adresse IP invisible ». Une connexion sortante possède toujours une adresse source au niveau du chemin réseau. Lorsqu'une route de confidentialité est utilisée, le serveur distant voit l'adresse d'egress du relais/proxy, et non une adresse publique inventée par ATIBON.

Le flux de référence est :

```text
IP interne
    |
    v
 ATIBON
    |
    v
[1] Reputation
    |
    v
[2] Risk / Policy Decision
    |
    +---- ALLOW ------------------------------+
    |                                         |
    |                                  sortie normale
    |                                         |
    +---- QUARANTINE                          |
    |        |                                |
    |        v                                |
    |   blocage contrôlé                      |
    |                                         |
    +---- PRIVACY ROUTE                       |
             |                                |
             v                                |
      [3] Approved Relay                     |
             |                                |
             v                                |
      [4] NAT / Proxy                         |
             |                                |
             v                                |
      IP d'egress attribuée                   |
      au relais/fournisseur                   |
             |                                |
             +--------------+-----------------+
                            |
                            v
                     serveur distant
                            |
                            v
                        [5] Audit
```

## Zéro usurpation arbitraire

Le moteur Egress reçoit un relais explicitement approuvé par la configuration. Il ne reçoit pas et ne calcule pas une adresse IP source arbitraire à injecter dans les paquets.

Dans `core-rust/src/egress_privacy.rs`, les champs `source_ip_rewrite` et `header_spoofing` sont explicitement `false`. Le choix d'un relais repose sur le pool configuré, et une destination suspecte sans relais approuvé est mise en quarantaine. Le module ne réalise donc pas une usurpation d'adresse source. fileciteturn44file0

Dans `core-rust/src/egress_governed.rs`, `nat_proxy` décrit le chemin qui nécessite le NAT/proxy du relais sélectionné ; `source_ip_rewrite` reste `false`. La traduction de l'adresse source doit être effectuée par le dataplane réseau ou le fournisseur du relais avec une adresse qui lui est légitimement attribuée. Le moteur de politique ne peut pas déclarer arbitrairement qu'une IP publique appartient au relais. fileciteturn46file0

### Invariants

1. Aucun champ `spoof_source_ip` ou équivalent n'est accepté par la décision Egress.
2. Une Privacy Route sans relais approuvé ne passe pas en sortie : elle devient `Quarantine`.
3. `nat_proxy=true` signifie « utiliser le NAT/proxy du relais sélectionné », pas « fabriquer une IP source ».
4. L'IP visible par le serveur distant est celle effectivement utilisée par le relais/provider ou par le NAT de l'environnement de sortie.
5. Toute activation d'un chemin Egress doit rester traçable dans l'audit JSONL.

## Shadow Mode

Avant l'enforcement, ATIBON calcule la décision de routage complète en parallèle du trafic réel. La décision simulée est enregistrée, mais le paquet n'est pas bloqué par le moteur Shadow.

```text
trafic réel -------------------------------> sortie réelle
     |
     +----> même Reputation + Risk/Policy
                    |
                    +----> décision simulée
                              |
                              +----> audit JSONL
                              |
                              +----> shadow_mismatch
```

En mode `Enforce`, la décision simulée devient la décision effective : `Allow`, `PrivacyRoute` ou `Quarantine`.

## Audit JSONL

Chaque décision Egress est écrite comme une ligne JSON indépendante. La trace contient notamment le mode, la destination, les scores, la décision simulée, la décision effective, le relais sélectionné, l'état NAT/proxy, l'absence de réécriture arbitraire de l'IP source, le blocage et les divergences Shadow.

Exemple de structure :

```json
{"timestamp":0,"mode":"Shadow","destination":"example.invalid","reputation_score":90,"policy_score":90,"simulated_decision":"Quarantine","effective_decision":"Allow","relay":null,"nat_proxy":false,"source_ip_rewrite":false,"packet_blocked":false,"shadow_mismatch":true,"reason":"risk/policy decision requires controlled quarantine"}
```

## Limite d'implémentation

Le module de décision Egress ne constitue pas à lui seul un dataplane NAT. La possession/l'attribution d'une adresse IP doit être garantie par la configuration réseau, l'OS ou le fournisseur de sortie. Une intégration de production doit donc vérifier les interfaces, routes, pools NAT et relais réellement attribués avant de passer de Shadow à Enforce.
