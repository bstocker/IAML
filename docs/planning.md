# Planning et correspondance fiche projet ↔ ateliers

## 1. Correspondance

| Atelier | Titre | Temps de la fiche | UT | Durée TP |
|---|---|---|---|---|
| [00](../notebooks/enonces/00_prise_en_main.ipynb) | Prise en main : Codespace, Python, pandas | **UT 0** (remise à niveau, optionnelle) | 0–1 | 2 h |
| [01](../notebooks/enonces/01_donnees_soc.ipynb) | Typologie des données SOC, traitement des logs | **Temps 1** | 1 | 2 h |
| [02](../notebooks/enonces/02_km_ontologies.ipynb) | KM 1 — ontologies, RDF, SPARQL, inférence | **Temps 2** | 2 | 2 × 2 h |
| [03](../notebooks/enonces/03_km_graphe_attack.ipynb) | KM 2 — graphe ATT&CK, STIX, plan de détection | **Temps 2** | 2 | 2 × 2 h |
| [04](../notebooks/enonces/04_ml_supervise.ipynb) | ML supervisé — triage des alertes | **Temps 3** | 2 | 2 × 2 h |
| [05](../notebooks/enonces/05_ml_non_supervise.ipynb) | ML non supervisé — segmentation des journaux | **Temps 3** | 1 | 2 h |
| [06](../notebooks/enonces/06_reseaux_de_neurones.ipynb) | Réseaux de neurones, séquences, auto-encodeur | **Temps 3** | 1 | 2 h |
| [07](../notebooks/enonces/07_process_mining.ipynb) | Process mining du processus de réponse | **Temps 4 — option A** | 1 | 2 h |
| [08](../notebooks/enonces/08_detection_anomalies.ipynb) | Détection d'anomalies sur flux réseau | **Temps 4 — option B** | 1 | 2 h |
| [09](../notebooks/enonces/09_donnees_non_structurees.ipynb) | Texte libre, IoC, classification, retour au graphe | **Temps 1 / 3** (compétence 3.1) | 1 | 2 h |
| [10](../notebooks/enonces/10_deploiement_mlops.ipynb) | Déploiement, API, dérive, surveillance | **Temps 3** (MLOps) | 1 | 2 h |
| [11](../notebooks/enonces/11_recherche_bibliographique.ipynb) | Recherche bibliographique outillée | **Temps 5** | 1 (+3 de tutorat) | 2 h |

## 2. Le point de vigilance de la fiche : 12 UT ou 14 UT ?

La fiche projet signale que la somme des temps (1 + 4 + 4 + 1 + 4) fait **14 UT**
pour un volume annoncé de **12 UT**. Le dépôt ne tranche pas à votre place : il
propose deux montages cohérents, à choisir avant publication de l'emploi du temps.

### Option A — 12 UT (recommandée si le volume est contraint)

Ramener le Temps 2 (KM) et le Temps 5 (RB) à 3 UT chacun.

| Semaine | Temps | Atelier | Notes |
|---|---|---|---|
| S1 | 1 | 01 | UT 0 (atelier 00) en travail personnel préalable |
| S2 | 2 | 02 | ontologies, RDF, SPARQL |
| S3 | 2 | 02 (suite) + 03 | inférence, puis graphe ATT&CK |
| S4 | 2 | 03 (suite) | plan de détection priorisé |
| S5 | 3 | 04 | ML supervisé — fuite, partition temporelle |
| S6 | 3 | 04 (suite) + 05 | seuil de décision, puis non supervisé |
| S7 | 3 | 06 | réseaux de neurones et séquences |
| S8 | 3 | 10 | déploiement et surveillance |
| S9 | 4 | 07 **ou** 08 | choix pédagogique, voir §3 |
| S10 | 5 | 11 | méthode bibliographique |
| S11 | 5 | tutorat | encadrement individuel de la note de lecture |
| S12 | 5 | restitutions | soutenances mini-projet + notes de lecture |

L'atelier 09 (données non structurées) devient alors du travail personnel guidé,
adossé au mini-projet.

### Option B — 14 UT (recommandée si le volume peut être acté)

Le découpage de la fiche est respecté à la lettre : Temps 1 = 1 UT, Temps 2 = 4 UT
(ateliers 02 et 03, deux séances chacun), Temps 3 = 4 UT (ateliers 04, 05, 06, 10),
Temps 4 = 1 UT (07 **et** 08 en survol, ou l'un des deux approfondi),
Temps 5 = 4 UT (atelier 11 puis trois semaines de tutorat et de restitution).
L'atelier 09 s'insère en fin de Temps 1 ou en ouverture du Temps 3.

> **Recommandation.** L'option B est plus confortable : le Temps 2 (KM) est celui
> où les étudiants issus d'un parcours informatique classique ont le moins de
> repères, et le Temps 5 perd tout son sens s'il est comprimé. Si 14 UT sont
> impossibles, préférez réduire le Temps 2 à 3 UT plutôt que le Temps 5 : la
> compétence méta visée par la fiche (« apprendre à apprendre ») est portée par
> le Temps 5, pas par la maîtrise de SPARQL.

## 3. Temps 4 : process mining ou détection d'anomalies ?

Les deux ateliers sont fournis, complets et indépendants.

| Critère | Atelier 07 — Process mining | Atelier 08 — Détection d'anomalies |
|---|---|---|
| Nouveauté conceptuelle | forte (rien d'équivalent ailleurs dans la maquette) | modérée (prolonge les ateliers 01, 05, 06) |
| Utilité SOC immédiate | organisation, audit, dimensionnement | détection, cœur de métier |
| Difficulté technique | faible (pm4py fait le gros du travail) | moyenne (ingénierie de caractéristiques) |
| Recouvrement avec le reste | faible | fort |
| Attente du marché de l'emploi | indirecte | directe |

**Trois montages possibles :**

- **07 seul** — si vous voulez maximiser la couverture disciplinaire. C'est le
  seul endroit de la maquette où l'on analyse le SOC comme une organisation.
- **08 seul** — si le groupe se destine à des postes de détection. C'est aussi
  l'atelier qui démontre le mieux la thèse centrale du cours (la représentation
  prime sur l'algorithme).
- **07 + 08 en survol** (2 × 1 h) — faisable en tronquant : sections 1 à 5 de
  l'atelier 07, sections 1 à 5 de l'atelier 08. On perd les parties les plus
  riches (conformité, enrichissement contextuel), à réserver au travail personnel.

**Recommandation :** si le Temps 3 a été mené jusqu'à l'atelier 06,
choisissez **07** — la détection d'anomalies aura déjà été rencontrée trois fois.

## 4. Charge de travail personnel

Chaque atelier se conclut par une section « travail personnel (≥ 4 h) » alignée
sur le rythme de la fiche. Le mini-projet (voir [mini-projet.md](mini-projet.md))
se déroule en parallèle à partir de la semaine 5.

## 5. Prérequis Python

L'atelier 00 sert de test d'entrée. Si plus d'un tiers du groupe peine sur ses
exercices 4.1 et 5.1, prévoyez l'UT 0 en présentiel plutôt qu'en travail personnel :
le Temps 3 devient très difficile sans aisance sur `groupby`, `merge` et les
horodatages.
