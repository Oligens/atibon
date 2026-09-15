# ATIBON Test Lab

Banc de test reproductible pour mesurer les performances défensives d'ATIBON dans un environnement isolé.

## Sécurité du banc

Les 13 campagnes utilisent exclusivement des **événements synthétiques** et des charges inertes. Elles ne lancent pas de brute-force réel, n'exécutent pas de malware, n'exfiltrent pas de données, ne réalisent pas de mouvement latéral et ne consomment pas volontairement toutes les ressources d'une machine réelle.

Le lab mesure le comportement d'ATIBON face à des représentations contrôlées de ces catégories. Pour une validation réseau réelle, exécuter uniquement dans un laboratoire isolé et explicitement autorisé.

## Vecteurs

V01 reconnaissance; V02 scans; V03 brute-force; V04 credential attacks; V05 web attacks; V06 malware simulation; V07 lateral movement; V08 exfiltration simulation; V09 abnormal egress; V10 DNS abuse; V11 TLS anomalies; V12 API abuse; V13 resource exhaustion.

Les définitions exactes sont dans `scenarios.json`. Chaque campagne doit également inclure un **contrôle bénin** afin de mesurer les faux positifs.

## Exécution reproductible

```bash
cd atibon-test-lab
python3 run_campaign.py --scenario all --repetitions 5 --mode shadow --output results-shadow.json
python3 run_campaign.py --scenario all --repetitions 5 --mode enforce --output results-enforce.json
python3 evaluate.py results-enforce.json --output evaluation.json --markdown-output evaluation.md
```

Le dernier appel produit deux rapports : `evaluation.json` (machine-readable) et `evaluation.md` (rapport lisible/auditable).

Pour une campagne auditable, enregistrer le SHA du commit testé, `git diff --exit-code`, la version de Python/Rust, l'OS, la configuration ATIBON, le mode d'exécution, le nombre de répétitions et les fichiers de résultats. Un second passage doit utiliser exactement les mêmes scénarios et paramètres.

## Score ADES officiel

Le banc remplace les pourcentages publicitaires vagues par le calcul mathématique ADES suivant :

**ADES = (30% × détection) + (25% × prévention) + (15% × confinement) + (10% × résistance à l'évasion) + (10% × récupération) + (10% × auditabilité)**

Chaque sous-composante est normalisée sur **0–100**, puis multipliée par son poids. Le score final est sur 100.

### Classification automatique

| Score final | Niveau |
|---:|---|
| < 50 | insuffisant |
| 50–69 | expérimental |
| 70–84 | robuste |
| 85–94 | très robuste |
| 95+ | niveau exceptionnel |

Le code implémente ces seuils sans arrondi préalable susceptible de changer de catégorie.

### Normalisation utilisée par le Lab

La pondération 30/25/15/10/10/10 est la définition ADES implémentée. Pour transformer les observations du Lab en sous-scores 0–100, `evaluate.py` applique une règle explicite et reproductible :

- **Détection** = TP / (TP + FN) × 100.
- **Prévention** = attaques détectées et effectivement bloquées / attaques attendues × 100.
- **Confinement** = attaques détectées avec blocage effectif / attaques détectées × 100.
- **Résistance à l'évasion** = (1 − FN / attaques attendues) × 100.
- **Récupération** = attaques détectées avec timestamp de récupération / attaques détectées × 100.
- **Auditabilité** = échantillons contenant tous les champs d'audit requis / nombre total d'échantillons × 100.

Cette normalisation est volontairement documentée : elle évite de présenter comme « officiel » un sous-score dont la méthode de mesure n'aurait pas été définie. Les valeurs manquantes des mesures brutes restent `null` et ne sont jamais converties silencieusement en zéro.

## Mesures

- **TP** : scénario malveillant simulé détecté comme attendu.
- **FP** : contrôle bénin détecté à tort.
- **FN** : scénario malveillant simulé non détecté.
- **Detection Time** : temps monotone entre injection de l'événement synthétique et décision de détection.
- **Blocking Time** : temps entre injection et décision effective de blocage en Enforce Mode; en Shadow Mode, une décision simulée ne constitue pas un blocage.
- **CPU overhead** : différence entre charge CPU de la campagne et baseline correspondante.
- **Memory overhead** : différence de RSS entre campagne et baseline.
- **Network latency** : différence de latence d'un chemin de contrôle autorisé par rapport à la même mesure avec ATIBON.
- **Recovery Time** : temps entre la fin du scénario et retour aux seuils nominaux définis par le protocole.

Pour les temps et ressources, le rapport fournit au minimum moyenne, médiane, p95 et nombre d'échantillons.

## Adaptateur ATIBON

`run_campaign.py` constitue le harnais déterministe et sans danger. Le raccordement à une instance ATIBON de laboratoire doit être fait par un adaptateur local autorisé qui :

1. injecte un événement synthétique dans l'interface de test;
2. récupère la classification et la décision;
3. récupère les timestamps de décision/blocage;
4. échantillonne CPU/RSS;
5. mesure la latence d'un endpoint de contrôle;
6. mesure le retour à l'état nominal;
7. ne transmet jamais de charge vers une cible externe.

L'adaptateur doit conserver les mêmes identifiants de scénario et répétition afin de rendre les résultats traçables.

## Procédure auditeur / testeur externe

1. Préparer une VM ou un réseau de laboratoire isolé et autorisé.
2. Vérifier que la cible de test est locale et qu'aucune route de campagne ne vise Internet ou un tiers.
3. Cloner le dépôt et noter le commit exact.
4. Installer les dépendances documentées par ATIBON.
5. Vérifier `scenarios.json` et le contrôle bénin.
6. Exécuter au moins 5 répétitions en Shadow Mode.
7. Exécuter les mêmes répétitions en Enforce Mode si l'environnement autorise le blocage.
8. Archiver les deux JSON, les logs ATIBON et les informations système.
9. Calculer les métriques avec `evaluate.py` sans modifier les résultats bruts.
10. Archiver `evaluation.json` et `evaluation.md` avec le commit, les paramètres et les résultats afin qu'une tierce partie puisse rejouer exactement la campagne.

### Critères d'interprétation

Un score ADES ne constitue pas à lui seul une preuve de sécurité en production. Les résultats doivent être accompagnés des TP/FP/FN, distributions temporelles, surcoûts CPU/mémoire, données d'environnement et valeurs manquantes explicitement signalées. Les résultats d'un banc synthétique ne doivent pas être présentés comme une validation réelle contre des attaques.
