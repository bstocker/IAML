# Atelier IA & Machine Learning pour la cybersécurité

Atelier pratique GitHub / Codespaces accompagnant le cours
**« Intelligence artificielle et Machine Learning pour la cybersécurité »**
(ingénieur informatique, spécialité cybersécurité — **14 UT**).

Douze ateliers sur notebooks Jupyter, un générateur de données synthétiques
imitant les artefacts d'un SOC, et un environnement reproductible qui démarre en
quelques minutes sans aucune installation locale.

> **Aucune donnée réelle, aucune donnée personnelle.** Tous les jeux de données
> sont générés à partir de lois statistiques, avec une graine fixe.

---

## Démarrer en 3 minutes

1. Sur la page GitHub du dépôt : **Code** → onglet **Codespaces** →
   **Create codespace on main**.
2. Attendre la fin du provisionnement (2 à 4 minutes : dépendances + génération
   des données). Une bannière confirme que l'environnement est prêt.
3. Ouvrir `notebooks/enonces/01_donnees_soc.ipynb`.

En local, si vous préférez :

```bash
git clone <url-du-depot> && cd IAML
make install    # dépendances Python (3.11 recommandé)
make data       # génère les jeux de données synthétiques
make check      # vérifie que tout est en place
```

---

## Les ateliers

| # | Atelier | Temps | Ce qu'on y apprend |
|---|---|---|---|
| **00** | [Prise en main](notebooks/enonces/00_prise_en_main.ipynb) | UT 0 | Codespace, pandas, les pièges des données de sécurité |
| **01** | [Données SOC et traitement des logs](notebooks/enonces/01_donnees_soc.ipynb) | T1 | typologie des données, pipeline collecte → détection, poser le problème d'apprentissage |
| **02** | [KM 1 — ontologies, RDF, SPARQL](notebooks/enonces/02_km_ontologies.ipynb) | T2 | modéliser la connaissance cyber, interroger, inférer |
| **03** | [KM 2 — graphe ATT&CK et STIX](notebooks/enonces/03_km_graphe_attack.ipynb) | T2 | centralités, communautés, plan de détection priorisé |
| **04** | [ML supervisé — triage des alertes](notebooks/enonces/04_ml_supervise.ipynb) | T3 | fuite de données, partition temporelle, seuil et capacité |
| **05** | [ML non supervisé — segmenter les journaux](notebooks/enonces/05_ml_non_supervise.ipynb) | T3 | vectorisation, k-moyennes, DBSCAN, ACP, référence par groupe |
| **06** | [Réseaux de neurones et séquences](notebooks/enonces/06_reseaux_de_neurones.ipynb) | T3 | perceptron, modèle de séquence, auto-encodeur, et quand s'en passer |
| **07** | [Process mining de la réponse à incident](notebooks/enonces/07_process_mining.ipynb) | T4-A | découverte, conformité, goulets, reprises |
| **08** | [Détection d'anomalies sur flux réseau](notebooks/enonces/08_detection_anomalies.ipynb) | T4-B | anomalies collectives, balises C2, enrichissement contextuel |
| **09** | [Données non structurées](notebooks/enonces/09_donnees_non_structurees.ipynb) | T1/T3 | extraction d'IoC, TF-IDF, classification, retour au graphe |
| **10** | [Déploiement et surveillance](notebooks/enonces/10_deploiement_mlops.ipynb) | T3 | API de scoring, dérive, PSI, fiche de modèle |
| **11** | [Recherche bibliographique](notebooks/enonces/11_recherche_bibliographique.ipynb) | T5 | protocole, criblage, grille de lecture, défauts récurrents |

Maquette semaine par semaine et correspondance détaillée avec les 5 temps de
la fiche projet : **[docs/planning.md](docs/planning.md)**.

---

## Le fil conducteur

Un SOC fictif : 140 machines, 220 comptes, 14 000 alertes SIEM sur six mois,
77 000 événements système, 98 000 flux réseau, 700 incidents traités, 180
rapports en texte libre. Chaque atelier répond à une question qu'un SOC se pose
réellement, et chacun contient un **moment où le résultat attendu n'arrive pas** :

- l'AUC passe à 0,998 dès qu'on ajoute une variable — parce qu'elle n'existe pas
  au moment de la décision (atelier 04) ;
- le détecteur d'anomalies obtient 0 % de rappel sur les balises C2, et aucun
  réglage n'y change rien — le problème est l'unité d'observation (atelier 08) ;
- le classement des machines suspectes est dominé par les postes
  d'administration, qui ne sont pas anormaux mais atypiques (atelier 06) ;
- la surveillance du modèle affiche 0,999 d'AUC-PR sur les mois qu'il a mémorisés
  et 0,27 sur les suivants (atelier 10).

**Ce sont ces moments qui constituent le cours.** Les bibliothèques changeront ;
ces réflexes non.

---

## Jeux de données

Générés par [`tools/generate_soc_data.py`](tools/generate_soc_data.py), graine 42.

| Fichier | Contenu | Ateliers |
|---|---|---|
| `alertes_siem.csv` | 14 000 alertes avec verdict analyste | 01, 04, 06, 10 |
| `evenements_systeme.csv` | journaux système par sessions markoviennes | 01, 05, 06 |
| `netflow.csv` | flux réseau avec anomalies étiquetées | 08 |
| `journal_incidents.csv` | 700 incidents, processus de réponse | 07 |
| `rapports/*.txt` | 180 rapports d'incident en texte libre | 09 |
| `attack/` | sous-ensemble ATT&CK, tabulaire et STIX 2.1 | 02, 03 |
| `assets.csv`, `utilisateurs.csv`, `cve.csv`, … | référentiels | 01, 02, 03 |
| `verite_terrain/` | étiquettes réservées à l'**évaluation** | 05, 06, 08 |

Le détail est dans `data/LISEZ-MOI.md`, généré en même temps que les données.

---

## Documentation

| Document | Pour qui |
|---|---|
| [docs/planning.md](docs/planning.md) | maquette 14 semaines, plan de repli à 12 UT, choix du Temps 4 |
| [docs/glossaire.md](docs/glossaire.md) | étudiants — ML, KM, PM, DA, SOC, SIEM, ATT&CK |
| [docs/grille-de-lecture.md](docs/grille-de-lecture.md) | étudiants — note de lecture du Temps 5 |
| [docs/mini-projet.md](docs/mini-projet.md) | étudiants — six sujets, livrables, attendus |
| [docs/bareme.md](docs/bareme.md) | enseignants — barèmes détaillés des trois modalités |
| [docs/guide-enseignant.md](docs/guide-enseignant.md) | enseignants — conduite de séance, distribution, quotas |

---

## Commandes

```bash
make help      # liste les commandes
make data      # régénère les jeux de données
make build     # régénère les notebooks depuis ateliers/src/
make check     # vérifie l'environnement et la synchronisation
make test      # exécute les 12 corrigés (~3 min) — garde-fou du dépôt
```

**Les notebooks ne se modifient pas directement.** Ils sont générés depuis
`ateliers/src/*.py`, source unique qui produit l'énoncé et le corrigé — voir
[docs/guide-enseignant.md](docs/guide-enseignant.md#2-le-principe-éditorial--une-seule-source).

---

## Environnement

Python 3.11, `pandas`, `scikit-learn`, `matplotlib`, `networkx`, `rdflib`,
`owlrl`, `pm4py`, `fastapi`. Versions figées dans
[`requirements.txt`](requirements.txt). L'intégration continue vérifie à chaque
modification que les données se génèrent, que les notebooks distribués sont à
jour et que les 12 corrigés s'exécutent.

---

## Avertissements

- Les **identifiants MITRE ATT&CK** proviennent du référentiel public ; les
  descriptions et relations de ce dépôt sont **simplifiées et synthétiques**, et
  ne doivent pas servir de source de référence.
- Le **corpus bibliographique** de l'atelier 11 est **entièrement fictif**
  (titres préfixés `[FICTIF]`). Il sert à s'entraîner au criblage, jamais à citer.
- **`pm4py` est distribué sous licence AGPL v3** : sans difficulté en contexte
  pédagogique, à vérifier avant tout usage industriel.
- Le répertoire `data/verite_terrain/` contient des étiquettes réservées à
  l'**évaluation**. Les utiliser à l'apprentissage d'un modèle non supervisé
  fausse tout l'exercice.
