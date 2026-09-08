# ---
# Atelier 00 — UT 0 (remise a niveau, optionnelle)
# ---

# %% [markdown]
# # Atelier 00 — Prise en main : Codespace, Python et données de sécurité
#
# > **Temps 0 (UT de remise à niveau, optionnelle)** — 2 h de TP
#
# ## Objectifs
#
# À l'issue de cet atelier vous savez :
#
# 1. vérifier que votre environnement Codespaces est fonctionnel ;
# 2. charger, filtrer, agréger et joindre des données de sécurité avec `pandas` ;
# 3. produire une visualisation lisible ;
# 4. reconnaître les pièges classiques (types, fuseaux horaires, valeurs manquantes).
#
# **Cet atelier ne fait pas d'IA.** Il garantit que le socle Python est acquis
# avant le Temps 1. Si tout vous paraît évident, passez directement à l'atelier 01.

# %% [markdown]
# ## 1. Vérification de l'environnement

# %%
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Racine du dépôt : les notebooks tournent depuis n'importe quel répertoire.
RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"

print("Python  :", sys.version.split()[0])
print("pandas  :", pd.__version__)
print("numpy   :", np.__version__)
print("Données :", DATA)
assert DATA.exists(), "Lancez d'abord : python tools/generate_soc_data.py --out data"

# %% [markdown]
# ## 2. Charger un jeu de données
#
# On commence par l'inventaire des actifs (une CMDB simplifiée).

# %%
assets = pd.read_csv(DATA / "assets.csv")
assets.head()

# %%
assets.info()

# %% [markdown]
# ### Exercice 2.1
#
# Affichez, pour chaque **zone** réseau, le nombre d'actifs et la criticité moyenne,
# triés par criticité décroissante.

# %% tags=["todo"]
# TODO : groupby sur 'zone', agréger 'asset_id' (count) et 'criticite' (mean),
#        puis trier par criticité moyenne décroissante.
resume_zones = None
resume_zones

# %% tags=["solution"]
resume_zones = (
    assets.groupby("zone")
    .agg(nb_actifs=("asset_id", "count"), criticite_moyenne=("criticite", "mean"))
    .sort_values("criticite_moyenne", ascending=False)
    .round(2)
)
resume_zones

# %% [markdown]
# ## 3. Les horodatages : le piège numéro un
#
# Un CSV ne connaît que du texte. Tant que la colonne n'est pas convertie en
# `datetime`, toute opération temporelle est fausse silencieusement.

# %%
alertes = pd.read_csv(DATA / "alertes_siem.csv")
print("Type brut de la colonne horodatage :", alertes["horodatage"].dtype)

alertes["horodatage"] = pd.to_datetime(alertes["horodatage"])
print("Après conversion                   :", alertes["horodatage"].dtype)
print("Période couverte :", alertes["horodatage"].min(), "→", alertes["horodatage"].max())

# %% [markdown]
# > **En production**, ajoutez systématiquement le fuseau : un SOC international
# > raisonne en UTC et affiche en heure locale. Un décalage d'une heure suffit à
# > invalider une corrélation « hors heures ouvrables ».

# %% [markdown]
# ### Exercice 3.1
#
# Construisez une série `alertes_par_jour` donnant le nombre d'alertes par jour
# calendaire, et tracez-la.

# %% tags=["todo"]
# TODO : utilisez .dt.date ou un resample('D') sur l'index temporel.
alertes_par_jour = None

# %% tags=["solution"]
alertes_par_jour = (
    alertes.set_index("horodatage").resample("D").size().rename("nb_alertes")
)

fig, ax = plt.subplots(figsize=(11, 3.5))
alertes_par_jour.plot(ax=ax, lw=1.2)
ax.set_title("Volume d'alertes SIEM par jour")
ax.set_xlabel("")
ax.set_ylabel("alertes / jour")
ax.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# **Question.** Observez-vous une rupture dans la série ? Notez la date : elle
# resservira à l'atelier 10 (dérive de distribution).

# %% [markdown]
# ## 4. Filtrer et joindre
#
# Une jointure typique en SOC : enrichir une alerte avec le contexte de l'actif.

# %%
# Alertes de forte sévérité, hors heures ouvrables
critiques = alertes[(alertes["severite_siem"] >= 4) & alertes["hors_heures_ouvrables"]]
print(f"{len(critiques)} alertes critiques hors heures ouvrables "
      f"({len(critiques) / len(alertes):.1%} du total)")

# %% [markdown]
# ### Exercice 4.1
#
# Joignez `critiques` avec `assets` (clé `hostname`) et affichez les 10 actifs
# les plus touchés, avec leur zone et leur criticité.

# %% tags=["todo"]
# TODO : merge puis value_counts / groupby.
top_actifs = None
top_actifs

# %% tags=["solution"]
top_actifs = (
    critiques.merge(assets[["hostname", "zone", "criticite", "os"]],
                    on="hostname", how="left", suffixes=("", "_actif"))
    .groupby(["hostname", "zone", "criticite"])
    .size()
    .rename("nb_alertes")
    .reset_index()
    .sort_values("nb_alertes", ascending=False)
    .head(10)
)
top_actifs

# %% [markdown]
# ## 5. Valeurs manquantes et doublons
#
# Le générateur a volontairement introduit des défauts de qualité, comme dans un
# vrai collecteur : champs absents, événements dupliqués par une double ingestion.

# %%
manquants = alertes.isna().sum()
print("Colonnes avec valeurs manquantes :")
print(manquants[manquants > 0])
print(f"\nDoublons exacts sur alert_id : {alertes['alert_id'].duplicated().sum()}")

# %% [markdown]
# ### Exercice 5.1
#
# Produisez `alertes_propres` : sans doublon d'`alert_id`, avec
# `reputation_source` manquante imputée par la médiane **de la même famille de
# règle** (et non par la médiane globale).

# %% tags=["todo"]
# TODO : drop_duplicates, puis groupby(...).transform pour l'imputation.
alertes_propres = None

# %% tags=["solution"]
alertes_propres = alertes.drop_duplicates(subset="alert_id").copy()
alertes_propres["reputation_source"] = alertes_propres.groupby("famille_regle")[
    "reputation_source"
].transform(lambda s: s.fillna(s.median()))

print(f"{len(alertes)} → {len(alertes_propres)} lignes")
print("Valeurs manquantes restantes :",
      int(alertes_propres["reputation_source"].isna().sum()))

# %% [markdown]
# > **Pourquoi la médiane par groupe ?** Les familles de règles ont des profils de
# > réputation très différents (une règle de politique interne voit surtout des IP
# > internes, réputation ≈ 0). Imputer par la médiane globale créerait un signal
# > artificiel que le modèle apprendrait comme s'il était réel.

# %% [markdown]
# ## 6. Une visualisation qui sert à décider
#
# Un graphique de TP doit répondre à une question opérationnelle. Ici : *quelles
# règles saturent le SOC pour un faible rendement ?*

# %%
rendement = (
    alertes_propres.groupby("regle_nom")
    .agg(volume=("alert_id", "count"),
         taux_vp=("verdict", lambda s: (s == "vrai_positif").mean()))
    .sort_values("volume", ascending=False)
)

fig, ax = plt.subplots(figsize=(8, 6))
ax.scatter(rendement["volume"], rendement["taux_vp"] * 100, s=60, alpha=.75)
for nom, r in rendement.iterrows():
    ax.annotate(nom[:26], (r["volume"], r["taux_vp"] * 100),
                fontsize=7, alpha=.8, xytext=(4, 3), textcoords="offset points")
ax.set_xscale("log")
ax.set_xlabel("Volume d'alertes (échelle log)")
ax.set_ylabel("Taux de vrais positifs (%)")
ax.set_title("Rendement des règles de détection\n(en bas à droite : à revoir en priorité)")
ax.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# ## 7. À retenir
#
# | Piège | Conséquence | Réflexe |
# |---|---|---|
# | Horodatage laissé en texte | tri et fenêtres temporelles faux | `pd.to_datetime` dès le chargement |
# | Doublons d'ingestion | volumétrie surestimée, fuite train/test | `drop_duplicates` sur l'identifiant métier |
# | Imputation globale | signal artificiel appris par le modèle | imputer **par groupe** métier |
# | Graphique sans question | joli mais inutile | énoncer la décision avant de tracer |
#
# **Suite :** atelier 01 — typologie des données SOC et modèle général de
# traitement des journaux.
