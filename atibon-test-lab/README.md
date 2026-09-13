# ATIBON Test Lab

Banc de test reproductible pour mesurer les performances défensives d'ATIBON dans un environnement isolé.

## Sécurité du banc

Les 13 campagnes utilisent exclusivement des **événements synthétiques** et des charges inertes. Elles ne lancent pas de brute-force réel, n'exécutent pas de malware, n'exfiltrent pas de données, ne réalisent pas de mouvement latéral et ne consomment pas volontairement toutes les ressources d'une machine réelle.

Le lab mesure le comportement d'ATIBON face à des représentations contrôlées de ces catégories. Pour une validation réseau réelle, exécuter uniquement dans un laboratoire isolé et explicitement autorisé.

## Vecteurs

| ID | Vecteur | Simulation sûre |
|---|---|---|
| V01 | Reconnaissance | événements de découverte synthétiques |
| V02 | Scans | séquence de ports/ressources simulée |
| V03 | Brute-force | série de tentatives d'authentification synthétiques |
| V04 | Credential attacks | identifiants factices uniquement |
| V05 | Web attacks | requêtes HTTP malveillantes synthétiques |
| V06 | Malware simulation | indicateurs comportementaux inertes |
| V07 | Lateral movement | graphe de déplacement synthétique |
| V08 | Exfiltration simulation | flux de volume/ destination simulés, sans données |
| V09 | Abnormal egress | destination/volume anormal synthétique |
| V10 | DNS abuse | motifs DNS synthétiques |
| V11 | TLS anomalies | métadonnées TLS anormales synthétiques |
| V12 | API abuse | appels API synthétiques hors profil |
| V13 | Resource exhaustion | charge logique bornée, sans épuisement réel |

## Protocole

1. Installer ATIBON et démarrer en Shadow Mode.
2. Réinitialiser l'état et enregistrer l'heure monotone de début.
3. Exécuter `python3 run_campaign.py --scenario all --repetitions 5 --output results.json`.
4. Pour chaque scénario, conserver l'événement, la décision attendue, la décision ATIBON, les timestamps et les compteurs système.
5. Rejouer exactement le même jeu de scénarios avec le même nombre de répétitions.
6. Comparer les métriques et exporter le rapport JSON.
7. Répéter en Enforce Mode dans un environnement de test autorisé.

## Mesures

- **TP** : attaque simulée détectée/bloquée comme attendu.
- **FP** : trafic bénin de contrôle classifié comme attaque.
- **FN** : attaque simulée non détectée.
- **Detection Time** : événement → décision de détection.
- **Blocking Time** : événement → décision effective de blocage.
- **CPU overhead** : différence CPU entre baseline et campagne.
- **Memory overhead** : différence RSS entre baseline et campagne.
- **Network latency** : différence de latence mesurée par rapport au contrôle.
- **Recovery Time** : retour à l'état nominal après la fin du scénario.

Les mesures temporelles sont prises avec une horloge monotone. Les résultats doivent être rapportés avec moyenne, médiane, p95 et nombre de répétitions; ne pas confondre absence de mesure avec zéro.

## Reproductibilité

Conserver avec chaque campagne : commit ATIBON, version Rust/Python, OS, configuration, mode Shadow/Enforce, seed éventuel, nombre de répétitions et fichier `results.json`.

Aucune campagne ne doit cibler un système tiers ou une adresse publique non autorisée.
