# ---
# Atelier 01 — Temps 1 : IA/ML pour la cyber
# ---

# %% [markdown]
# # Atelier 01 — Typologie des données SOC et modèle général de traitement des logs
#
# > **Temps 1 — IA/ML pour la cyber** (1 UT) · **semaine 1** · 2 h de TP
#
# ## Objectifs
#
# 1. Caractériser les **types de données** produits par un SOC et leur structure.
# 2. Dérouler le **modèle général de traitement automatique des journaux** :
#    collecte → normalisation → enrichissement → agrégation → détection.
# 3. Formuler une question de sécurité **comme un problème d'apprentissage** et
#    savoir dire de quelle famille il relève.
# 4. Comprendre pourquoi le SIEM à base de règles atteint ses limites — c'est la
#    justification de tout le reste du cours.
#
# ## Le fil rouge de l'atelier
#
# > *« Notre SOC reçoit 14 000 alertes par semestre pour 3 analystes. Sur quoi
# > doivent-ils travailler en premier ? »*
#
# Nous n'allons pas encore entraîner de modèle : nous allons **poser le problème**.

# %%
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
pd.set_option("display.width", 140)
pd.set_option("display.max_columns", 40)

# %% [markdown]
# ## 1. Inventaire des sources : quatre natures de données
#
# Un SOC ne manipule pas « des logs » mais au moins quatre natures de données,
# qui appellent des traitements différents.

# %%
sources = {
    "alertes_siem.csv": "Alertes SIEM (tabulaire, étiqueté)",
    "evenements_systeme.csv": "Journaux d'événements système (tabulaire, séquentiel)",
    "netflow.csv": "Flux réseau (tabulaire, numérique, haute volumétrie)",
    "journal_incidents.csv": "Journal du processus de réponse (log de processus)",
    "assets.csv": "Inventaire des actifs (référentiel)",
    "cve.csv": "Vulnérabilités (référentiel + texte)",
}
for fichier, description in sources.items():
    chemin = DATA / fichier
    taille = chemin.stat().st_size / 1e6
    n = sum(1 for _ in chemin.open(encoding="utf-8")) - 1
    print(f"{fichier:26s} {n:>8,d} lignes  {taille:6.1f} Mo   {description}")

print(f"\n{len(list((DATA / 'rapports').glob('*.txt'))):>8,d} rapports d'incident "
      f"en texte libre        Données NON structurées")

# %% [markdown]
# | Nature | Exemple ici | Traitement adapté | Module du cours |
# |---|---|---|---|
# | **Structurée étiquetée** | alertes avec verdict analyste | apprentissage **supervisé** | Temps 3 |
# | **Structurée non étiquetée** | journaux d'événements, netflow | **non supervisé**, **détection d'anomalies** | Temps 3, 4 |
# | **Séquentielle / processus** | journal de réponse à incident | **process mining** | Temps 4 |
# | **Non structurée (texte)** | rapports d'incident, CVE | TALN, extraction d'entités | Temps 1, 3 |
# | **Connaissance / référentiel** | ATT&CK, CMDB, CVE | **ontologies, graphes** | Temps 2 |

# %% [markdown]
# ## 2. Le modèle général de traitement automatique des logs
#
# ```
#   ┌──────────┐   ┌───────────────┐   ┌──────────────┐   ┌────────────┐   ┌───────────┐
#   │ COLLECTE │ → │ NORMALISATION │ → │ENRICHISSEMENT│ → │ AGRÉGATION │ → │ DÉTECTION │
#   └──────────┘   └───────────────┘   └──────────────┘   └────────────┘   └───────────┘
#    agents,        schéma commun,      CMDB, CTI,          fenêtres,        règles
#    syslog,        types, UTC,         géo-IP,             entités,         + modèles
#    API            déduplication       ATT&CK              compteurs        d'apprentissage
# ```
#
# **C'est exactement le pipeline d'un projet de ML.** La « préparation des
# données » d'un data scientist et la « chaîne d'ingestion » d'un ingénieur SOC
# désignent la même chose. Déroulons-la.

# %% [markdown]
# ### 2.1 Collecte

# %%
brut = pd.read_csv(DATA / "evenements_systeme.csv")
print(f"{len(brut):,} événements bruts")
brut.head()   # aperçu : 5 premières lignes par défaut, head(10) pour en voir plus

# %% [markdown]
# ### 2.2 Normalisation
#
# Trois opérations non négociables : **typer**, **dédupliquer**, **cadrer le temps**.

# %%
def normaliser(df: pd.DataFrame) -> pd.DataFrame:
    """Étape 2 du pipeline : schéma stable, types corrects, pas de doublon."""
    df = df.copy()
    df["horodatage"] = pd.to_datetime(df["horodatage"])
    df["event_id"] = df["event_id"].astype("int32")
    for col in ("hostname", "username", "type_evenement", "statut"):
        df[col] = df[col].astype("category")
    df["processus"] = df["processus"].fillna("").str.lower()
    avant = len(df)
    df = df.drop_duplicates()
    print(f"normalisation : {avant:,} → {len(df):,} lignes "
          f"({avant - len(df):,} doublons retirés)")
    return df.sort_values("horodatage").reset_index(drop=True)


evenements = normaliser(brut)
evenements.dtypes

# %% [markdown]
# ### 2.3 Enrichissement
#
# Un événement isolé ne veut rien dire. Le contexte (à qui appartient la machine ?
# le compte est-il privilégié ?) est ce qui transforme une donnée en information.

# %% [markdown]
# #### Exercice 2.3
#
# Enrichissez `evenements` avec :
# - la `zone`, la `criticite` et l'`os` de l'actif (fichier `assets.csv`, clé `hostname`) ;
# - le `role` et `compte_admin` de l'utilisateur (fichier `utilisateurs.csv`, clé `username`).
#
# Vérifiez le taux de jointures non résolues : dans un vrai SOC, un actif inconnu
# de la CMDB est **en soi** un signal.

# %% tags=["todo"]
assets = pd.read_csv(DATA / "assets.csv")
utilisateurs = pd.read_csv(DATA / "utilisateurs.csv")

# TODO : deux merge successifs en 'left', puis mesurer les valeurs manquantes
#        introduites par la jointure.
enrichis = None

# %% tags=["solution"]
assets = pd.read_csv(DATA / "assets.csv")
utilisateurs = pd.read_csv(DATA / "utilisateurs.csv")

enrichis = (
    evenements
    .merge(assets[["hostname", "zone", "criticite", "os", "agent_edr"]],
           on="hostname", how="left")
    .merge(utilisateurs[["username", "role", "compte_admin", "departement"]],
           on="username", how="left")
)

orphelins_actif = enrichis["zone"].isna().mean()
orphelins_compte = enrichis["role"].isna().mean()
print(f"{len(evenements):,} événements → {len(enrichis):,} lignes "
      f"× {enrichis.shape[1]} colonnes après jointure")
print(f"Événements sans actif connu en CMDB : {orphelins_actif:.2%}")
print(f"Événements sans compte connu        : {orphelins_compte:.2%}")
enrichis.head(3)

# %% [markdown]
# ### 2.4 Agrégation
#
# La détection ne porte presque jamais sur l'événement unitaire mais sur un
# **comportement observé dans une fenêtre**. Le choix de l'entité (hôte ? compte ?
# couple hôte-compte ?) et de la fenêtre (5 min ? 1 h ? 1 jour ?) est une
# décision de modélisation, pas un détail technique.

# %%
fenetre = (
    enrichis
    .assign(heure=enrichis["horodatage"].dt.floor("h"))
    .groupby(["hostname", "heure"], observed=True)
    .agg(nb_evenements=("event_id", "size"),
         nb_echecs_auth=("type_evenement", lambda s: (s == "echec_auth").sum()),
         nb_elevations=("type_evenement", lambda s: (s == "elevation").sum()),
         nb_comptes=("username", "nunique"),
         nb_processus=("processus", "nunique"))
    .reset_index()
)
print(f"{len(evenements):,} événements → {len(fenetre):,} observations (hôte × heure)")
fenetre.head()   # aperçu : 5 premières lignes par défaut, head(10) pour en voir plus

# %% [markdown]
# > **Point clé.** L'agrégation est déjà de l'**ingénierie de caractéristiques**
# > (*feature engineering*). Chaque colonne créée ci-dessus est une hypothèse sur
# > ce qui distingue un comportement normal d'un comportement malveillant.

# %% [markdown]
# ### 2.5 Détection par règles — et ses limites
#
# Écrivons une règle de corrélation « à la SIEM », puis mesurons ce qu'elle coûte.

# %%
REGLE_SEUIL_ECHECS = 5

def regle_bruteforce(f: pd.DataFrame, seuil: int = REGLE_SEUIL_ECHECS) -> pd.Series:
    """Règle SIEM classique : N échecs d'authentification en une heure sur un hôte."""
    return f["nb_echecs_auth"] >= seuil


declenchements = regle_bruteforce(fenetre)
print(f"La règle se déclenche {declenchements.sum():,} fois "
      f"({declenchements.mean():.2%} des fenêtres)")
print(f"Soit environ {declenchements.sum() / 30:.0f} alertes par jour pour un seul cas d'usage.")

# %% [markdown]
# #### Exercice 2.5 — la courbe de charge du seuil
#
# Tracez, pour un seuil variant de 2 à 20, le nombre d'alertes générées par jour.
# Ce graphique est l'argument que tout ingénieur SOC doit savoir produire face à
# une direction qui demande « plus de détection ».

# %% tags=["todo"]
# TODO : boucle sur les seuils, comptage, tracé en échelle logarithmique.

# %% tags=["solution"]
seuils = range(2, 21)
charge = [regle_bruteforce(fenetre, s).sum() / 30 for s in seuils]

fig, ax = plt.subplots(figsize=(9, 4))
ax.plot(list(seuils), charge, marker="o")
ax.set_yscale("log")
ax.axhline(30, color="crimson", ls="--", lw=1,
           label="capacité de traitement (~30 alertes/jour)")
ax.set_xlabel("Seuil : nombre d'échecs d'authentification par heure")
ax.set_ylabel("Alertes générées par jour (log)")
ax.set_title("Le dilemme du seuil : sensibilité contre charge de travail")
ax.set_xticks(list(seuils))
ax.legend()
ax.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# **Ce que montre cette courbe.** Une règle à seuil n'offre qu'un curseur, sur une
# seule variable, identique pour tout le parc. Elle ne sait pas que 8 échecs sur
# un serveur de sauvegarde sont normaux et que 3 échecs sur le poste du directeur
# financier à 3 h du matin ne le sont pas.
#
# **Le ML n'est pas « mieux » qu'une règle : il fait autre chose.** Il combine
# des dizaines de variables et apprend le seuil à partir des données.

# %% [markdown]
# ## 3. Ce que coûte réellement le bruit
#
# Passons aux alertes SIEM, qui portent le verdict rendu par les analystes.

# %%
alertes = pd.read_csv(DATA / "alertes_siem.csv", parse_dates=["horodatage"])
alertes = alertes.drop_duplicates(subset="alert_id")

taux_vp = (alertes["verdict"] == "vrai_positif").mean()
temps_total = alertes["temps_traitement_analyste_min"].sum() / 60
temps_perdu = alertes.loc[alertes["verdict"] == "faux_positif",
                          "temps_traitement_analyste_min"].sum() / 60

print(f"Alertes                      : {len(alertes):,}")
print(f"Taux de vrais positifs       : {taux_vp:.1%}")
print(f"Temps analyste total         : {temps_total:,.0f} h sur 6 mois")
print(f"dont passé sur des faux positifs : {temps_perdu:,.0f} h "
      f"({temps_perdu / temps_total:.0%})")
print(f"Équivalent temps plein gaspillé  : {temps_perdu / (6 * 151):.1f} ETP")

# %% [markdown]
# ### Exercice 3.1 — où est le gisement ?
#
# Construisez un tableau par `famille_regle` avec : le volume, le taux de vrais
# positifs, et le **temps analyste consommé par vrai positif trouvé**. Classez par
# ce dernier indicateur : c'est le coût d'acquisition d'une détection utile.

# %% tags=["todo"]
# TODO : groupby('famille_regle') + agrégations, puis colonne dérivée.
cout_par_detection = None
cout_par_detection

# %% tags=["solution"]
cout_par_detection = (
    alertes.groupby("famille_regle")
    .agg(volume=("alert_id", "count"),
         taux_vp=("verdict", lambda s: (s == "vrai_positif").mean()),
         heures_analyste=("temps_traitement_analyste_min", lambda s: s.sum() / 60))
    .assign(vrais_positifs=lambda d: (d["volume"] * d["taux_vp"]).round().astype(int))
)
cout_par_detection["heures_par_vp"] = (
    cout_par_detection["heures_analyste"] /
    cout_par_detection["vrais_positifs"].replace(0, np.nan)
)
cout_par_detection = cout_par_detection.sort_values("heures_par_vp", ascending=False)
cout_par_detection.round(2)

# %% [markdown]
# ## 4. Formuler le problème d'apprentissage
#
# C'est **l'exercice central du Temps 1**. Avant tout code, on remplit cette fiche.

# %% [markdown]
# ### Fiche de cadrage — modèle
#
# | Rubrique | Contenu |
# |---|---|
# | **Question métier** | Sur quelles alertes les analystes doivent-ils travailler en premier ? |
# | **Unité d'observation** | une alerte SIEM dédupliquée |
# | **Variable cible** | `verdict` ∈ {vrai_positif, faux_positif} |
# | **Étiquettes disponibles ?** | oui, produites par les analystes lors de la clôture |
# | **Famille d'apprentissage** | **supervisé**, classification binaire |
# | **Variables d'entrée** | uniquement celles connues **au moment de l'alerte** |
# | **Métrique** | précision @ top-K (K = capacité quotidienne), rappel sur les P1 |
# | **Coût d'erreur** | FN ≫ FP : un incident manqué coûte plus qu'une vérification inutile |
# | **Intégration SOC** | score de priorité renvoyé au SIEM, pas de fermeture automatique |
#
# ### Exercice 4.1 — à vous
#
# Remplissez la même fiche pour les **trois** questions suivantes, en précisant à
# chaque fois la famille d'apprentissage (supervisé / non supervisé / détection
# d'anomalies / modélisation de connaissances) **et sa justification**.
#
# 1. *« Quels sont les profils d'usage réels de notre parc de machines ? »*
# 2. *« Une machine communique-t-elle avec un serveur de commande et de contrôle ? »*
# 3. *« Quelles techniques ATT&CK notre couverture de détection ignore-t-elle ? »*

# %% [markdown] tags=["solution"]
# ### Corrigé de l'exercice 4.1
#
# **1. Profils d'usage du parc — non supervisé (partitionnement).**
# Aucune étiquette n'existe : personne n'a jamais écrit « ce poste est un poste de
# développeur » dans la CMDB. L'objectif est descriptif : faire émerger des groupes
# homogènes. Unité d'observation : l'hôte, décrit par un vecteur d'usage agrégé sur
# 30 jours. Métrique : cohésion/séparation (silhouette) **et** interprétabilité par
# un analyste — un cluster que personne ne sait nommer est un cluster inutile.
# → Atelier 05.
#
# **2. Communication avec un C2 — détection d'anomalies (et non classification).**
# On pourrait croire à du supervisé, mais les étiquettes manquent : on ne dispose
# pas d'un historique de milliers de C2 confirmés sur *notre* parc, et un C2 inconnu
# ne ressemblera pas aux précédents. On modélise donc le **normal** et on signale
# l'écart. Unité d'observation : le couple (source, destination) agrégé, pas le flux
# unitaire — la régularité temporelle n'existe qu'au niveau agrégé. Métrique :
# précision dans les K premiers scores, car on ne connaît pas le rappel réel.
# → Atelier 08.
#
# **3. Couverture de détection ATT&CK — modélisation de connaissances.**
# Ce n'est pas un problème d'apprentissage du tout. C'est un problème de
# **représentation** : relier un référentiel de techniques, un inventaire de règles
# et des sources de données, puis interroger ce graphe. Vouloir y appliquer du ML
# serait une erreur de cadrage classique. Métrique : couverture par tactique,
# techniques orphelines.
# → Ateliers 02 et 03.

# %% [markdown]
# ## 5. Détection d'anomalies : les trois définitions
#
# Le Temps 1 introduit les fondamentaux de la détection d'anomalie. Trois notions
# d'« anomalie » cohabitent, et confondre les deux premières est l'erreur la plus
# fréquente.

# %%
netflow = pd.read_csv(DATA / "netflow.csv", nrows=200_000, parse_dates=["horodatage"])

# Anomalie PONCTUELLE : un point aberrant dans la distribution marginale.
seuil_haut = netflow["octets_envoyes"].quantile(0.9995)
ponctuelles = netflow[netflow["octets_envoyes"] > seuil_haut]

# Anomalie CONTEXTUELLE : normal dans l'absolu, anormal dans son contexte.
netflow["heure"] = netflow["horodatage"].dt.hour
nuit = netflow[netflow["heure"].between(1, 5)]
seuil_nuit = nuit["octets_envoyes"].quantile(0.995)
contextuelles = nuit[nuit["octets_envoyes"] > seuil_nuit]

print(f"Anomalies ponctuelles  (> {seuil_haut / 1e6:.1f} Mo)              : {len(ponctuelles):,}")
print(f"Anomalies contextuelles (> {seuil_nuit / 1e6:.1f} Mo, entre 1 h et 5 h) : {len(contextuelles):,}")

fig, axes = plt.subplots(1, 2, figsize=(12, 3.8))
axes[0].hist(np.log10(netflow["octets_envoyes"] + 1), bins=80, color="steelblue")
axes[0].axvline(np.log10(seuil_haut), color="crimson", ls="--")
axes[0].set_title("Distribution marginale\n(anomalie ponctuelle)")
axes[0].set_xlabel("log10(octets envoyés)")
axes[1].scatter(netflow["heure"] + np.random.uniform(-.4, .4, len(netflow)),
                np.log10(netflow["octets_envoyes"] + 1), s=1, alpha=.03)
axes[1].set_title("Volume selon l'heure\n(anomalie contextuelle)")
axes[1].set_xlabel("heure de la journée")
plt.tight_layout()

# %% [markdown]
# | Type | Définition | Exemple SOC | Méthode |
# |---|---|---|---|
# | **Ponctuelle** | une observation loin de la masse | transfert de 4 Go | seuils, z-score, forêt d'isolement |
# | **Contextuelle** | normale en soi, anormale dans son contexte | 200 Mo à 3 h du matin depuis un poste bureautique | modèle conditionnel au contexte |
# | **Collective** | chaque point est normal, la **séquence** ne l'est pas | 300 connexions de 1,2 ko toutes les 60 s | agrégation puis analyse temporelle |
#
# > La balise C2 est une anomalie **collective** : aucun de ses flux, pris isolément,
# > n'est suspect. C'est la démonstration que nous ferons à l'atelier 08 — et la
# > raison pour laquelle le choix de l'unité d'observation prime sur le choix de
# > l'algorithme.

# %% [markdown]
# ## 6. Synthèse et travail personnel
#
# **À retenir**
#
# 1. Le pipeline SOC (collecte → normalisation → enrichissement → agrégation →
#    détection) **est** le pipeline ML. L'essentiel du travail est en amont du modèle.
# 2. Choisir l'unité d'observation et la fenêtre d'agrégation est une décision de
#    modélisation qui détermine ce qui sera détectable.
# 3. Une règle à seuil n'a qu'un curseur ; le ML apprend une frontière
#    multivariée. Ce n'est pas un remplacement mais un complément.
# 4. La famille d'apprentissage se déduit de la **disponibilité des étiquettes** et
#    de la **nature de la question**, jamais de la mode technologique.
#
# **Travail personnel (≥ 4 h)**
#
# - Rédigez la fiche de cadrage complète pour un cas d'usage de votre choix issu
#   du fichier `docs/mini-projet.md`.
# - Lisez `docs/glossaire.md` (sections ML, DA, SOC).
# - Question ouverte à préparer pour le cours suivant : *quelles étiquettes votre
#   SOC produit-il déjà sans le savoir, et quel biais portent-elles ?*
