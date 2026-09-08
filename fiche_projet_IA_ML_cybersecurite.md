# Fiche projet de cours — IA & ML pour la cybersécurité

> **Modéliser et concevoir des moteurs d'apprentissage artificiel simples (ML), supervisés et
> non supervisés, utilisables dans un centre de sécurité opérationnel (SOC) en complément d'un
> SIEM ; structurer la connaissance cyber (KM) par ontologies et graphes de connaissances ;
> explorer le process mining (PM) et la détection d'anomalies (DA) ; et développer une posture
> scientifique pour « apprendre à apprendre » face à des technologies qui évoluent vite.**

| Rubrique | Valeur |
|---|---|
| **Intitulé** | Intelligence artificielle et Machine Learning pour la cybersécurité |
| **Parcours** | Ingénieur informatique — spécialité cybersécurité |
| **Volume** | 12 UT (unités-temps) — voir *Point de vigilance planification* |
| **Rythme** | 1 UT / semaine (2 h cours + 2 h TP + ≥ 4 h travail personnel) |
| **Positionnement** | SOC, cyberdéfense, investigation (forensic), anticipation de la menace (CTI / hunting) |
| **Prérequis** | Python (niveau intermédiaire), bases de statistiques, notions de systèmes et de réseaux |
| **Support pratique** | Atelier GitHub / Codespaces (notebooks Jupyter, jeux de données synthétiques SOC) |

---

## 1. Contexte et intention

Les centres de sécurité opérationnelle (SOC) produisent et consomment des volumes massifs de
données hétérogènes : journaux d'événements, configurations système, flux réseau, bases de
connaissances de la menace (TTP, CVE, ATT&CK). Les outils traditionnels — au premier rang
desquels le **SIEM** — atteignent leurs limites lorsqu'il s'agit de détecter des comportements
inédits, de corréler à grande échelle ou de capitaliser la connaissance cyber.

Ce cours forme des ingénieurs capables de **modéliser un problème de sécurité comme un problème
d'apprentissage** et d'y répondre avec des méthodes d'intelligence artificielle appropriées :
apprentissage supervisé et non supervisé, gestion des connaissances (KM), process mining (PM) et
détection d'anomalies (DA).

L'ambition dépasse la maîtrise d'outils particuliers — qui deviennent vite obsolètes. Le cours
vise une **compétence méta** : savoir rechercher, lire et évaluer de façon critique l'état de
l'art (« deep tech »), afin de faire des choix structurants face à une problématique de
traitement de données massives. **On ne peut pas tout connaître ; on apprend à apprendre.**

---

## 2. Objectifs pédagogiques

À l'issue du cours, l'étudiant est capable de :

1. **Poser un problème de sécurité comme un problème d'apprentissage** et déterminer s'il relève
   du supervisé, du non-supervisé, de la détection d'anomalies ou de la modélisation de
   connaissances — et de justifier ce choix.
2. **Concevoir un moteur d'apprentissage simple de bout en bout** : données → prétraitement →
   caractéristiques → modèle → évaluation → intégration au flux SOC/SIEM.
3. **Structurer et interroger la connaissance cyber** au moyen d'ontologies et de graphes de
   connaissances (web sémantique, MITRE ATT&CK, STIX).
4. **Mettre en œuvre des techniques avancées** utiles au SOC : process mining sur journaux
   d'événements, détection d'anomalies sur données de sécurité.
5. **Évaluer l'état de l'art de manière scientifique** : conduire une recherche bibliographique
   tutorée, lire et critiquer la littérature récente reliant IA et cybersécurité.
6. **Restituer et déployer** un modèle auprès d'utilisateurs finaux, avec le souci de
   l'industrialisation (pipelines, surveillance, gestion des alertes).

---

## 3. Compétences visées

Le cours vise l'acquisition de compétences élevées sur **trois domaines de l'IA** — machine
learning (ML), gestion des connaissances (KM) et détection d'anomalies (DA) — appliqués à
l'extraction, l'analyse et la présentation de données massives dans un contexte SOC.

### 3.1 Fondamentaux (savoir-faire techniques)

- Appliquer des **prétraitements** sur des données collectées, **structurées ou non** (journaux
  d'événements, configurations système, bases TTP/CVE, etc.).
- **Prétraiter et analyser des données structurées** pour répondre à un problème métier.
- **Prétraiter et analyser des données non structurées** (texte, images) pour obtenir un jeu de
  données exploitable.
- **Développer des algorithmes** de machine learning ou de modélisation des connaissances, en
  sachant **rédiger une spécification des besoins**.

### 3.2 Entraîner un modèle d'apprentissage

- **Supervisé** — analyse prédictive (ex. moteurs de détection comportementale).
- **Non supervisé** — segmentation et réduction de données (ex. journaux d'événements collectés
  dans un SOC).

### 3.3 Déployer à l'échelle Big Data

- **Présenter et déployer** un modèle d'apprentissage automatique auprès d'utilisateurs finaux
  (appliqué aux journaux d'événements).

### 3.4 Adéquation avec les attentes du marché (compétences issues d'offres d'emploi)

Ces compétences, demandées à un ingénieur cybersécurité pour concevoir un prototype d'IA ou
analyser/développer un algorithme d'IA, reposent directement sur le ML, le KM et la DA :

| Compétence attendue (offre d'emploi) | Domaine | Module(s) du cours |
|---|---|---|
| Participer à la veille sur les nouveaux mécanismes de détection et méthodes d'investigation | Méta / RB | Temps 5 (RB) |
| À partir de scénarios d'agression redoutés : mise sous surveillance, traduction en règles de corrélation, collecte des données, définition des réponses à incident, pilotage de la mise en œuvre et recette | ML / DA | Temps 1, 3, 4 |
| Mettre en place des outillages d'ingénierie de la connaissance cyber (collecte, extraction, modélisation, enrichissement, capitalisation) | KM | Temps 2 |
| Implémenter des pipelines automatisés de déploiement et de surveillance des modèles (gestion des alertes) | ML / MLOps | Temps 3, 4 |
| Configurer / déployer / automatiser / industrialiser le déploiement de modèles ML | ML / MLOps | Temps 3 |
| Développer, entraîner et optimiser des modèles d'IA pour les outils numériques de l'organisation | ML | Temps 3 |

---

## 4. Découpage des enseignements (12 UT, 5 temps)

> **1 UT = 2 h de cours + 2 h de travaux pratiques + au moins 4 h de travail personnel.** Chaque
> UT est espacée d'une semaine ; ce rythme hebdomadaire conditionne la planification.

### Temps 1 — IA/ML pour la cyber *(1 UT)*

- Histoire, enjeux et champ disciplinaire de l'intelligence artificielle.
- Techniques de l'IA au service de la cybersécurité.
- Fondamentaux de la détection d'anomalie à partir des données.
- Typologie des données de sécurité traitées pour l'apprentissage (hétérogénéité, structures…).
- Modèle général du traitement automatique des logs.

### Temps 2 — Gestion des connaissances (KM) *(4 UT)*

- Fondamentaux pour la gestion des connaissances.
- Langages semi-formels : ontologies et web sémantique.

### Temps 3 — Machine Learning (ML) *(4 UT)*

- Classifications statistiques : supervisées, semi-supervisées, non supervisées.
- Fondamentaux de l'apprentissage artificiel.
- Techniques du machine learning : réseaux de neurones, deep learning.

### Temps 4 — Process Mining (PM) ou Détection d'Anomalies (DA) *(1 UT)*

- Généralités sur le process mining ou sur la détection d'anomalies.

### Temps 5 — Recherche bibliographique : IA/ML pour la cyber *(4 UT)*

- Lien avec les applications actuelles en cybersécurité, via une étude bibliographique **tutorée
  par un enseignant-chercheur**.
- Panorama des outils de cybersécurité à base de machine learning, knowledge management et IA.

> **Point de vigilance — planification.** La somme des temps ci-dessus (1 + 4 + 4 + 1 + 4)
> représente **14 UT**, alors que le volume global annoncé est de **12 UT**. Il conviendra
> d'arbitrer : soit ramener certains temps (par ex. KM ou RB) à 3 UT, soit acter un volume réel
> de 14 UT/semaines. À trancher avant publication de l'emploi du temps.

---

## 5. Planning indicatif

En retenant le rythme d'**1 UT par semaine**, la maquette s'étale sur 12 à 14 semaines :

| Semaine(s) | Temps | Contenu dominant | TP associé |
|---|---|---|---|
| S1 | Temps 1 | IA/ML pour la cyber, typologie des données, traitement des logs | Prise en main des données SOC (Pandas) |
| S2–S5 | Temps 2 | KM, ontologies, web sémantique | Graphe de connaissances ATT&CK (RDF / NetworkX) |
| S6–S9 | Temps 3 | ML supervisé, non supervisé, deep learning | Triage d'alertes ; segmentation de logs |
| S10 | Temps 4 | Process mining **ou** détection d'anomalies | PM sur journal d'incident **ou** anomalies netflow |
| S11–S14 | Temps 5 | Recherche bibliographique tutorée | Fiche de lecture + restitution |

---

## 6. Modalités pédagogiques et environnement technique

- **Cours magistraux** pour les fondements théoriques ; **travaux pratiques** sur notebooks
  Jupyter exécutables.
- **Environnement reproductible** via GitHub Codespaces (conteneur préconfiguré) : aucune
  installation locale requise, démarrage en quelques minutes.
- **Données synthétiques** imitant des artefacts SOC réalistes (alertes SIEM, flux réseau,
  journaux d'événements, sous-ensemble ATT&CK), sans aucune donnée réelle ni personnelle.
- **Langages / bibliothèques** : Python, pandas, scikit-learn, NetworkX/RDFLib (KM), pm4py (PM).

---

## 7. Évaluation

- **Contrôle continu** — notebooks de TP complétés (modules ML, KM, PM/DA).
- **Mini-projet** — reprendre (ou apporter) un jeu de données et dérouler la démarche complète :
  spécification du besoin, prétraitement, modélisation, choix de méthode, évaluation critique,
  restitution auprès d'un « utilisateur final ».
- **Note de lecture (Temps 5)** — fiche critique d'un article récent (< 3 ans) reliant IA et
  cybersécurité, selon une grille de lecture fournie.

---

## 8. Livrables du projet

1. **Support de cours** (théorie, par temps).
2. **Atelier pratique** — dépôt GitHub / Codespaces : notebooks énoncés + corrigés, générateur
   de données, environnement `devcontainer`.
3. **Grille de lecture bibliographique** et glossaire (ML / KM / PM / DA / SOC / SIEM / ATT&CK).
4. **Barème et sujets** de mini-projet.

---

## 9. Points à arbitrer avant lancement

- Volume réel : **12 UT vs 14 UT** (voir §4).
- **Temps 4** : choix entre process mining et détection d'anomalies, ou traitement des deux en
  survol.
- Niveau Python d'entrée : prévoir éventuellement une **UT 0 de remise à niveau** si le groupe
  est hétérogène.
- Modalités d'accès Codespaces (quota GitHub Education).

---

*Fiche projet — version de travail. Document destiné à cadrer la conception du cours ; les
volumes et modalités sont à valider par l'équipe pédagogique.*
