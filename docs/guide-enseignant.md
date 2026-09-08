# Guide de l'enseignant

## 1. Ce que contient le dépôt

```
IAML/
├── .devcontainer/          environnement Codespaces (Python 3.11 + dépendances)
├── ateliers/src/           SOURCE UNIQUE des 12 ateliers (format « percent »)
├── notebooks/
│   ├── enonces/            généré — remis aux étudiants
│   └── corriges/           généré — usage enseignant
├── data/                   généré par tools/generate_soc_data.py (non versionné)
├── docs/                   planning, glossaire, grille de lecture, mini-projet, barème
├── service/                généré par l'atelier 10 (API de scoring)
├── tools/
│   ├── generate_soc_data.py   générateur de données synthétiques
│   ├── build_notebooks.py     source → énoncés + corrigés
│   ├── run_notebooks.py       exécute tous les corrigés (garde-fou)
│   └── check_env.py           diagnostic d'environnement
└── Makefile
```

## 2. Le principe éditorial : une seule source

**Ne modifiez jamais un `.ipynb` directement.** Les notebooks sont générés depuis
`ateliers/src/*.py`. Le format est celui de jupytext (« percent »), lisible et
diffable dans Git :

```python
# %% [markdown]
# ## Titre de section
# Texte en markdown, préfixé par « # ».

# %%
# Cellule de code présente dans l'énoncé ET dans le corrigé.

# %% tags=["todo"]
# Cellule présente uniquement dans l'ÉNONCÉ (amorce, TODO).

# %% tags=["solution"]
# Cellule présente uniquement dans le CORRIGÉ.
```

Après modification :

```bash
make build     # régénère les 24 notebooks
make test      # exécute les 12 corrigés — ~3 minutes
```

Bénéfices : pas de divergence entre énoncé et corrigé, revue de modifications
lisible dans Git, et garantie que tout ce qui est distribué s'exécute.

## 3. Les données

Un seul script, une seule graine :

```bash
python tools/generate_soc_data.py --out data --seed 42
```

Tous les étudiants obtiennent **exactement** les mêmes données, donc les mêmes
résultats numériques que les corrigés. Le répertoire `data/` n'est pas versionné :
il est régénéré à la création de chaque Codespace.

**Changer la graine change tous les résultats.** Si vous le faites (par exemple
pour donner un jeu différent d'une promotion à l'autre), relancez `make test` et
relisez les commentaires numériques des corrigés — certains citent des valeurs.

### Ce que le générateur injecte volontairement

| Propriété | Où | Atelier qui l'exploite |
|---|---|---|
| Déséquilibre de classes (~7 % de vrais positifs) | `alertes_siem.csv` | 04 |
| Variable fuitée (`temps_traitement_analyste_min`) | `alertes_siem.csv` | 04 |
| Dérive de distribution sur les 30 derniers jours | `alertes_siem.csv` | 10 |
| Valeurs manquantes et doublons | `alertes_siem.csv` | 00, 04 |
| Profils d'usage latents | `evenements_systeme.csv` | 05 |
| Structure séquentielle markovienne | `evenements_systeme.csv` | 06 |
| Compromission additive et datée (6 hôtes) | `evenements_systeme.csv` | 05, 06 |
| Anomalies ponctuelles, contextuelles, collectives | `netflow.csv` | 08 |
| Balises périodiques **légitimes** (NTP, télémétrie) | `netflow.csv` | 08 |
| Boucles de reprise et écarts de procédure | `journal_incidents.csv` | 07 |
| Techniques ATT&CK cohérentes avec le type d'incident | `rapports/` | 09 |

Ces propriétés sont le cœur pédagogique du dépôt : chacune supporte un
« moment de bascule » d'un atelier. Si vous modifiez le générateur, vérifiez que
le moment de bascule correspondant fonctionne toujours.

## 4. Les moments de bascule de chaque atelier

C'est là que se joue l'apprentissage. Ne les escamotez pas faute de temps.

| Atelier | Moment de bascule | Réaction attendue |
|---|---|---|
| 01 | la courbe de charge du seuil | « une règle ne peut pas faire mieux » |
| 02 | l'inférence crée 780 triplets non écrits | « une règle métier se propage toute seule » |
| 03 | la couverture ATT&CK affichée cache le rendement réel | « 80 % de couverture ne veut rien dire » |
| 04 | AUC 0,998 avec la variable fuitée | « c'était trop beau » |
| 05 | le LOF trouve les 6 compromis, mais avec 40 % de faux positifs | « un score d'atypie priorise, il ne conclut pas » |
| 06 | le score relatif bat le score absolu | « la référence doit être proche de l'entité » |
| 07 | le goulet n'est pas la transition la plus lente | « lenteur × fréquence » |
| 08 | 0 % de rappel sur les balises C2 en analyse par flux | « le problème n'est pas l'algorithme » |
| 09 | 100 % d'exactitude sur des données gabarités | « ne transposez jamais sans le dire » |
| 10 | AUC-PR 0,999 en échantillon, 0,27 hors échantillon | « surveiller sur l'historique complet ment » |
| 11 | corrélation quasi nulle fiabilité / citations | « les citations mesurent la notoriété » |

## 5. Conduite de séance (2 h de TP)

Trame qui fonctionne bien :

| Durée | Phase |
|---|---|
| 10 min | rappel du cours, énoncé du problème de la séance, **sans montrer le notebook** |
| 15 min | prise en main : exécution des cellules de contexte, exploration des données |
| 50 min | exercices en autonomie, par binômes ; l'enseignant circule |
| 20 min | mise en commun du moment de bascule (§4) — au tableau, pas à l'écran |
| 20 min | fin des exercices, ouverture sur le travail personnel |
| 5 min | annonce de la séance suivante |

**Ne projetez pas le corrigé.** Le moment de bascule perd tout effet s'il est
donné avant que les étudiants aient obtenu le résultat décevant par eux-mêmes.

## 6. Difficultés fréquentes des étudiants

| Symptôme | Cause probable | Réponse |
|---|---|---|
| « Mon modèle fait 99 % » | fuite de données, ou exactitude sur classes déséquilibrées | ramener à la question : *cette variable existe-t-elle à la décision ?* |
| Blocage sur `groupby` / `merge` | prérequis Python insuffisant | faire l'atelier 00 en présentiel |
| « À quoi sert RDF, SQL suffirait » | question légitime | l'exercice 5 de l'atelier 02 : cinq jointures en SQL, un motif en SPARQL |
| Notebook non exécutable au rendu | cellules exécutées dans le désordre | imposer *Restart & Run All* avant tout rendu |
| Le clustering « ne marche pas » | oubli de la normalisation | section 2 de l'atelier 05 |
| pm4py très lent | journal non filtré | filtrer les variantes rares avant la découverte |

## 7. Distribution aux étudiants

### Option 1 — dépôt modèle GitHub (recommandé)

1. Marquer ce dépôt comme *template* dans les réglages GitHub.
2. Retirer `notebooks/corriges/` de la copie distribuée (voir §8).
3. Les étudiants créent leur propre dépôt depuis le modèle, puis un Codespace.
4. Le rendu se fait par lien vers leur dépôt.

### Option 2 — GitHub Classroom

Créer un devoir à partir du dépôt modèle. Les corrections automatiques peuvent
s'appuyer sur `tools/run_notebooks.py`.

### Quota Codespaces

Le compte GitHub Education gratuit offre un quota mensuel d'heures-cœur. Une
machine à 2 cœurs consomme deux fois plus vite qu'annoncé en heures « brutes ».

Recommandations :
- machine **2 cœurs / 8 Go** (déclaré dans `devcontainer.json`) — suffisant pour
  tous les ateliers ;
- rappeler aux étudiants d'**arrêter** leur Codespace après usage (il s'arrête
  seul au bout de 30 minutes d'inactivité, mais l'habitude vaut mieux) ;
- l'atelier 06 est le plus long (~80 s pour le corrigé complet), tout le reste
  s'exécute en quelques secondes.

Le dépôt fonctionne aussi en local (`make install && make data && make build`)
si le quota est épuisé.

## 8. Retirer les corrigés de la version étudiante

```bash
git rm -r --cached notebooks/corriges
echo "notebooks/corriges/" >> .gitignore
git commit -m "Version étudiante : sans corrigés"
```

Conservez `ateliers/src/` **uniquement dans votre dépôt de travail** : les
sources contiennent les cellules `tags=["solution"]`. Pour une version étudiante
strictement expurgée, ne distribuez que `notebooks/enonces/`, `data/` (ou le
générateur), `docs/`, `.devcontainer/` et `requirements.txt`.

## 9. Intégration continue

Le workflow `.github/workflows/ci.yml` vérifie à chaque *push* :

1. que les dépendances s'installent sur Python 3.11 ;
2. que les données se génèrent ;
3. que les notebooks distribués sont **synchronisés** avec `ateliers/src/` ;
4. que les 12 corrigés s'exécutent sans erreur.

C'est la garantie qu'aucun TP ne casse silencieusement à la montée de version
d'une bibliothèque. Durée : environ 8 minutes.

## 10. Licences et mentions

- **pm4py** (atelier 07) est distribué sous **AGPL v3**. Sans difficulté en
  contexte pédagogique et de recherche ; à vérifier avant tout usage industriel.
- Les **identifiants MITRE ATT&CK** sont ceux du référentiel public. Les
  descriptions et relations du dépôt sont **simplifiées et synthétiques** : elles
  ne doivent pas être utilisées comme source de référence.
- Le **corpus bibliographique** est entièrement fictif, titres préfixés
  `[FICTIF]`. L'avertissement figure dans le fichier, dans `data/LISEZ-MOI.md` et
  dans l'atelier 11, et le barème sanctionne son usage en note de lecture.
- **Aucune donnée réelle ni personnelle** n'est présente dans le dépôt.
