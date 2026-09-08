# Planning et correspondance fiche projet ↔ ateliers

## 1. Correspondance

| Atelier | Titre | Temps de la fiche | Semaine | Durée TP |
|---|---|---|---|---|
| [00](../notebooks/enonces/00_prise_en_main.ipynb) | Prise en main : Codespace, Python, pandas | **UT 0** (remise à niveau) | *travail perso.* | 2 h |
| [01](../notebooks/enonces/01_donnees_soc.ipynb) | Typologie des données SOC, traitement des logs | **Temps 1** | S1 | 2 h |
| [02](../notebooks/enonces/02_km_ontologies.ipynb) | KM 1 — ontologies, RDF, SPARQL, inférence | **Temps 2** | S2–S3 | 2 × 2 h |
| [03](../notebooks/enonces/03_km_graphe_attack.ipynb) | KM 2 — graphe ATT&CK, STIX, plan de détection | **Temps 2** | S4–S5 | 2 × 2 h |
| [04](../notebooks/enonces/04_ml_supervise.ipynb) | ML supervisé — triage des alertes | **Temps 3** | S6 | 2 h (dense — voir §2.1) |
| [05](../notebooks/enonces/05_ml_non_supervise.ipynb) | ML non supervisé — segmentation des journaux | **Temps 3** | S7 | 2 h |
| [06](../notebooks/enonces/06_reseaux_de_neurones.ipynb) | Réseaux de neurones, séquences, auto-encodeur | **Temps 3** | S8 | 2 h |
| [07](../notebooks/enonces/07_process_mining.ipynb) | Process mining du processus de réponse | **Temps 4 — option A** | S10 | 2 h |
| [08](../notebooks/enonces/08_detection_anomalies.ipynb) | Détection d'anomalies sur flux réseau | **Temps 4 — option B** | S10 | 2 h |
| [09](../notebooks/enonces/09_donnees_non_structurees.ipynb) | Texte libre, IoC, classification, retour au graphe | **Temps 3** (compétence 3.1) | *travail perso.* | 2 h |
| [10](../notebooks/enonces/10_deploiement_mlops.ipynb) | Déploiement, API, dérive, surveillance | **Temps 3** (MLOps) | S9 | 2 h |
| [11](../notebooks/enonces/11_recherche_bibliographique.ipynb) | Recherche bibliographique outillée | **Temps 5** | S11 (+ S12–S14) | 2 h |

Les deux ateliers en *travail perso.* sont justifiés en §2.2, avec les variantes
possibles si vous préférez les traiter en présentiel.

## 2. Volume retenu : **14 UT**

La fiche projet signalait un écart entre la somme des temps (1 + 4 + 4 + 1 + 4 =
**14 UT**) et le volume annoncé (**12 UT**).

> **Décision : le cours est positionné à 14 UT**, soit 14 semaines à raison
> d'1 UT par semaine. Le découpage de la fiche est respecté à la lettre. Un plan
> de repli à 12 UT est documenté en §2.3 s'il faut réduire en cours de route.

### 2.1 Maquette retenue — 14 semaines

| Semaine | Temps | Séance | Contenu dominant |
|---|---|---|---|
| S1 | **1** | atelier 01 | typologie des données SOC, pipeline de traitement des logs, cadrage du problème d'apprentissage |
| S2 | **2** | atelier 02 (1/2) | donnée / information / connaissance ; RDF, ontologie cyber, instanciation |
| S3 | **2** | atelier 02 (2/2) | SPARQL, inférence RDFS et OWL-RL |
| S4 | **2** | atelier 03 (1/2) | bundle STIX 2.1, construction du graphe, métriques de graphe |
| S5 | **2** | atelier 03 (2/2) | couverture de détection, communautés, **plan de détection priorisé** · *lancement du mini-projet* |
| S6 | **3** | atelier 04 | fuite de données, partition temporelle, seuil et capacité · *fiche de cadrage du mini-projet à rendre* |
| S7 | **3** | atelier 05 | vectorisation, k-moyennes, DBSCAN, ACP, référence de normalité par groupe |
| S8 | **3** | atelier 06 | perceptron, modèle de séquence, auto-encodeur, et quand s'en passer |
| S9 | **3** | atelier 10 | déploiement, API de scoring, dérive, surveillance · *point d'étape mini-projet* |
| S10 | **4** | atelier 07 **ou** 08 | process mining **ou** détection d'anomalies — voir §3 |
| S11 | **5** | atelier 11 | protocole de recherche, criblage, grille de lecture |
| S12 | **5** | tutorat | encadrement individuel de la note de lecture (enseignant-chercheur) |
| S13 | **5** | tutorat | suite du tutorat · *dépôt du notebook et du rapport de mini-projet* |
| S14 | **5** | restitutions | soutenances de mini-projet et notes de lecture |

**Répartition par temps : 1 + 4 + 4 + 1 + 4 = 14 UT.** C'est exactement le
découpage de la fiche projet, sans réinterprétation. L'atelier 10 est
comptabilisé sur le Temps 3 au titre du MLOps, conformément au tableau §3.4 de
la fiche.

> **Contrainte à connaître : l'atelier 04 tient sur une seule séance.** C'est le
> plus dense du dépôt. En 2 h on traite les sections 1 à 6 — fuite de données,
> partition temporelle, ingénierie des caractéristiques, seuil et courbe de
> décision, c'est-à-dire tous les moments de bascule. Les sections 7 à 9
> (matrice de confusion, importance par permutation, validation croisée
> temporelle) passent en travail personnel ; elles sont rédigées pour être
> lisibles sans accompagnement.

### 2.2 Les ateliers hors maquette

Dix ateliers sur douze occupent une séance. Les deux suivants sont volontairement
placés hors du présentiel :

| Atelier | Statut | Pourquoi |
|---|---|---|
| **00** — prise en main | UT 0, **travail personnel préalable** | sert de test d'entrée ; à basculer en présentiel si le groupe est hétérogène (voir §5) |
| **09** — données non structurées | **travail personnel guidé**, adossé au mini-projet | c'est la compétence 3.1 la mieux absorbée par la pratique : les sujets B et E du mini-projet la mobilisent directement |

Trois variantes si vous préférez un autre équilibre :

| Variante | Ce qu'on gagne | Ce qu'on perd |
|---|---|---|
| Étaler l'atelier **04 sur S6–S7** et basculer l'atelier **10** en travail personnel | la séance la plus dense respire | l'objectif pédagogique 6 (« restituer et déployer ») n'est plus traité en séance, alors qu'il est cité tel quel dans les offres d'emploi |
| Traiter **09** en S9 et basculer **10** en travail personnel | la compétence 3.1 est couverte en présentiel | même perte que ci-dessus |
| **Acter 15 UT** | tout tient, y compris 09 | une semaine de plus à négocier — si 14 sont acquises, 15 le sont peut-être |

### 2.3 Plan de repli — réduire à 12 UT

Si le volume doit être ramené à 12 UT, **supprimez S3 et S12** :

| Suppression | Effet | Compensation |
|---|---|---|
| **S3** — atelier 02 (2/2) | Temps 2 ramené à 3 UT | SPARQL et inférence traités en survol en S2 (sections 5 et 6 de l'atelier 02) ; l'exercice 6.1 passe en travail personnel |
| **S12** — une des deux semaines de tutorat | Temps 5 ramené à 3 UT | tutorat en rendez-vous individuels hors séance ; la note de lecture reste due |

> **Ordre de sacrifice.** Réduisez le Temps 2 avant le Temps 5. La compétence
> méta visée par la fiche (« on ne peut pas tout connaître ; on apprend à
> apprendre ») est portée par le Temps 5, pas par la maîtrise de SPARQL. Ne
> supprimez jamais S14 : une maquette sans restitution ne valide pas l'objectif
> pédagogique 6.
>
> Si le repli intervient en cours d'année, prévenez-en les étudiants **avant**
> la semaine 6 : la charge du mini-projet est calibrée sur 14 semaines.

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
