# ---
# Atelier 08 — Temps 4 (option B) : Détection d'anomalies
# ---

# %% [markdown]
# # Atelier 08 — Détection d'anomalies sur les flux réseau
#
# > **Temps 4 — Process Mining ou Détection d'Anomalies** (1 UT) — 2 h de TP
# >
# > Cet atelier traite l'option **détection d'anomalies**. L'atelier 07 traite
# > l'option **process mining**.
#
# ## Objectifs
#
# 1. Distinguer anomalie **ponctuelle**, **contextuelle** et **collective**, et
#    voir que chacune impose une unité d'observation différente.
# 2. Mettre en œuvre et comparer les détecteurs usuels : z-score robuste, forêt
#    d'isolement, LOF, enveloppe elliptique, SVM à une classe.
# 3. Démontrer que le **choix de la représentation** pèse plus lourd que le choix
#    de l'algorithme.
# 4. Utiliser l'**enrichissement contextuel** pour transformer un détecteur
#    inutilisable en détecteur exploitable.
# 5. Évaluer sans vérité terrain — et savoir ce que valent les métriques quand on
#    en a une.
#
# ## Le problème
#
# ~98 000 flux réseau sur 14 jours. Quelque part : une balise vers un serveur de
# commande, une exfiltration, un balayage de ports, un tunnel DNS. Aucune signature,
# aucune règle. **Il faut modéliser le normal et mesurer l'écart.**

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                             roc_auc_score)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.svm import OneClassSVM

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
ALEA = 42

flux = pd.read_csv(DATA / "netflow.csv", parse_dates=["horodatage"])
print(f"{len(flux):,} flux · {flux['ip_source'].nunique()} sources · "
      f"{flux['ip_destination'].nunique()} destinations · "
      f"{(flux['horodatage'].max() - flux['horodatage'].min()).days} jours")
flux.head()

# %% [markdown]
# > **Note de méthode.** Le fichier `verite_terrain/netflow_etiquettes.csv`
# > contient les étiquettes réelles. Elles servent **uniquement** à évaluer, à la
# > toute fin. En situation réelle vous ne les auriez pas : on travaille donc
# > d'abord sans les regarder.

# %% [markdown]
# ## 1. Explorer le normal
#
# Avant de chercher l'anormal, il faut savoir à quoi ressemble le normal.

# %%
fig, axes = plt.subplots(1, 3, figsize=(14, 3.8))
axes[0].hist(np.log10(flux["octets_envoyes"] + 1), bins=90, color="steelblue")
axes[0].set(xlabel="log10(octets envoyés)", ylabel="flux", title="Volume sortant")
axes[1].hist(np.log10(flux["duree_s"] + .01), bins=90, color="seagreen")
axes[1].set(xlabel="log10(durée en s)", title="Durée des flux")
ports = flux["port_destination"].value_counts().head(12)
axes[2].bar(range(len(ports)), ports.to_numpy(), color="indianred")
axes[2].set_xticks(range(len(ports)))
axes[2].set_xticklabels(ports.index, rotation=45, fontsize=8)
axes[2].set(title="Ports de destination les plus vus")
plt.tight_layout()

print("Les distributions sont fortement asymétriques (log-normales) :")
print("→ toujours passer au logarithme avant un détecteur fondé sur une distance.")

# %% [markdown]
# ## 2. Première tentative : détecter flux par flux
#
# L'unité d'observation la plus évidente est le flux. Voyons jusqu'où elle mène.

# %%
def caracteristiques_par_flux(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "log_envoyes": np.log1p(df["octets_envoyes"]),
        "log_recus": np.log1p(df["octets_recus"]),
        "log_ratio": np.log1p(df["octets_envoyes"] / (df["octets_recus"] + 1)),
        "log_duree": np.log1p(df["duree_s"]),
        "log_paquets": np.log1p(df["paquets_envoyes"]),
        "octets_par_paquet": df["octets_envoyes"] / (df["paquets_envoyes"] + 1),
        "port": df["port_destination"],
        "port_courant": df["port_destination"].isin([80, 443, 53, 123]).astype(int),
        "debit": df["octets_envoyes"] / (df["duree_s"] + .01),
    })


F = caracteristiques_par_flux(flux)
Fs = StandardScaler().fit_transform(F)

foret = IsolationForest(n_estimators=200, contamination=0.05,
                        random_state=ALEA, n_jobs=-1).fit(Fs)
score_flux = -foret.score_samples(Fs)
print(f"Forêt d'isolement entraînée sur {len(Fs):,} flux × {Fs.shape[1]} variables.")

# %% [markdown]
# ### Le moment de vérité

# %%
verite = pd.read_csv(DATA / "verite_terrain" / "netflow_etiquettes.csv")
evaluation = flux[["flow_id"]].assign(score=score_flux).merge(verite, on="flow_id")

print(f"AUC-ROC : {roc_auc_score(evaluation['anomalie'], evaluation['score']):.3f}")
print(f"AUC-PR  : {average_precision_score(evaluation['anomalie'], evaluation['score']):.3f}  "
      f"(base : {evaluation['anomalie'].mean():.3f})\n")

seuil = np.quantile(score_flux, 0.95)
detecte = evaluation["score"] >= seuil
rappel = (evaluation[evaluation["anomalie"]]
          .assign(detecte=detecte[evaluation["anomalie"]].to_numpy())
          .groupby("categorie_reelle")["detecte"].agg(["mean", "size"]))
rappel.columns = ["rappel", "nb_flux"]
print("Rappel par catégorie d'anomalie (seuil au 95ᵉ centile) :")
print(rappel.round(3).to_string())

# %% [markdown]
# ### Lisez bien ce tableau
#
# L'AUC globale paraît honorable. Pourtant :
#
# - l'**exfiltration** et le **balayage de ports** sont bien détectés — ce sont
#   des anomalies **ponctuelles**, visibles sur un flux isolé ;
# - la **balise C2** et le **tunnel DNS** ne le sont pas du tout — ce sont des
#   anomalies **collectives** : chacun de leurs flux, pris séparément, est
#   parfaitement banal.
#
# > **Aucun réglage d'hyperparamètre ne corrigera cela.** Le problème n'est pas
# > l'algorithme : c'est l'unité d'observation. Un flux isolé ne peut pas porter
# > l'information « ces connexions reviennent toutes les 60 secondes ».

# %% [markdown]
# ## 3. Changer d'unité d'observation
#
# Passons du flux au **couple (source, destination)**, décrit par la régularité de
# ses connexions dans le temps.

# %%
flux = flux.sort_values("horodatage")


def caracteristiques_par_paire(df: pd.DataFrame, minimum: int = 20) -> pd.DataFrame:
    lignes = []
    for (src, dst), g in df.groupby(["ip_source", "ip_destination"], sort=False):
        if len(g) < minimum:
            continue
        ecarts = g["horodatage"].diff().dt.total_seconds().dropna()
        if len(ecarts) < 3 or ecarts.mean() <= 0:
            continue
        envoyes = g["octets_envoyes"]
        lignes.append({
            "ip_source": src, "ip_destination": dst,
            "n_flux": len(g),
            # Régularité temporelle : c'est LA variable qui manquait.
            "cv_intervalle": ecarts.std() / ecarts.mean(),
            "intervalle_median_s": ecarts.median(),
            # Régularité de la charge utile
            "cv_taille": envoyes.std() / max(envoyes.mean(), 1),
            "taille_mediane": envoyes.median(),
            "ratio_envoi_reception": envoyes.sum() / max(g["octets_recus"].sum(), 1),
            "duree_totale_h": (g["horodatage"].max() - g["horodatage"].min()).total_seconds() / 3600,
            "ports_distincts": g["port_destination"].nunique(),
            "port_principal": int(g["port_destination"].mode().iat[0]),
        })
    return pd.DataFrame(lignes)


paires = caracteristiques_par_paire(flux)
print(f"{len(flux):,} flux → {len(paires):,} couples (source, destination) "
      f"d'au moins 20 flux")
paires.head()

# %% [markdown]
# ### Exercice 3.1
#
# Appliquez une forêt d'isolement sur les couples, puis évaluez : quelle est la
# catégorie majoritaire parmi les 20 couples les plus anormaux ?
#
# Pour construire la vérité terrain au niveau du couple, joignez `flux` et
# `verite` puis prenez la catégorie majoritaire de chaque couple.

# %% tags=["todo"]
# TODO : variables numériques → normalisation robuste → IsolationForest → top 20.
COLONNES = ["n_flux", "cv_intervalle", "intervalle_median_s", "cv_taille",
            "taille_mediane", "ratio_envoi_reception", "duree_totale_h",
            "ports_distincts"]

# %% tags=["solution"]
COLONNES = ["n_flux", "cv_intervalle", "intervalle_median_s", "cv_taille",
            "taille_mediane", "ratio_envoi_reception", "duree_totale_h",
            "ports_distincts"]

P = paires[COLONNES].copy()
for c in ["n_flux", "intervalle_median_s", "taille_mediane",
          "ratio_envoi_reception", "duree_totale_h"]:
    P[c] = np.log1p(P[c])
Ps = RobustScaler().fit_transform(P)

foret_paires = IsolationForest(n_estimators=300, contamination=0.05,
                               random_state=ALEA, n_jobs=-1).fit(Ps)
paires["score"] = -foret_paires.score_samples(Ps)

# Vérité terrain au niveau du couple
verite_paires = (
    flux[["flow_id", "ip_source", "ip_destination"]]
    .merge(verite, on="flow_id")
    .groupby(["ip_source", "ip_destination"])["categorie_reelle"]
    .agg(lambda s: s.value_counts().idxmax())
    .rename("categorie_reelle").reset_index()
)
paires = paires.merge(verite_paires, on=["ip_source", "ip_destination"], how="left")
paires["anomalie"] = paires["categorie_reelle"].fillna("normal") != "normal"

print(f"AUC-ROC : {roc_auc_score(paires['anomalie'], paires['score']):.3f}")
print(f"AUC-PR  : {average_precision_score(paires['anomalie'], paires['score']):.3f}  "
      f"(base : {paires['anomalie'].mean():.3f})\n")
print("Catégorie des 20 couples les plus anormaux :")
print(paires.nlargest(20, "score")["categorie_reelle"].value_counts().to_string())

# %% [markdown]
# #### Attention à l'AUC parfaite
#
# L'AUC obtenue au niveau du couple est proche de 1. **Ne concluez pas que le
# problème est résolu.** Après agrégation, il ne reste qu'une dizaine de couples
# anormaux sur environ un millier : l'AUC est calculée sur si peu de positifs
# qu'elle n'a plus de valeur statistique, et c'est l'**agrégation elle-même** qui a
# fait le travail, pas le détecteur.
#
# Le tableau des 20 premiers est plus honnête : dix couples parfaitement normaux
# y figurent. En production, ces dix-là sont dix tickets à traiter. C'est cette
# question — le bruit résiduel — que traite la suite.

# %% [markdown]
# ## 4. Une variable dédiée : la régularité
#
# La forêt d'isolement mélange toutes les variables. Or nous avons une hypothèse
# précise sur les balises C2 : **intervalle régulier ET charge utile constante**.
# Formulons-la explicitement.

# %%
candidats = paires[(paires["cv_intervalle"] < 0.25) & (paires["cv_taille"] < 0.35)]
print(f"{len(candidats)} couples « périodiques » sur {len(paires)} "
      f"({len(candidats) / len(paires):.1%})\n")
print(candidats["categorie_reelle"].value_counts().to_string())

fig, ax = plt.subplots(figsize=(9, 5.5))
normaux = paires[~paires["anomalie"]]
ax.scatter(normaux["cv_intervalle"], normaux["cv_taille"], s=14, alpha=.3,
           color="grey", label="normal")
for categorie, couleur in [("c2_beaconing", "crimson"), ("tunnel_dns", "darkorange"),
                           ("exfiltration", "purple"), ("scan_ports", "seagreen")]:
    m = paires["categorie_reelle"] == categorie
    if m.any():
        ax.scatter(paires.loc[m, "cv_intervalle"], paires.loc[m, "cv_taille"],
                   s=95, color=couleur, edgecolor="k", lw=.5, label=categorie, zorder=3)
ax.add_patch(plt.Rectangle((0, 0), 0.25, 0.35, fill=False, ls="--", lw=1.6,
                           edgecolor="k"))
ax.set(xscale="log", yscale="log",
       xlabel="coefficient de variation des intervalles (régularité temporelle)",
       ylabel="coefficient de variation de la taille (régularité de la charge)",
       title="Deux variables suffisent à isoler les communications périodiques\n"
             "(cadre : zone « périodique »)")
ax.legend(fontsize=8)
ax.grid(alpha=.3, which="both")
plt.tight_layout()

# %% [markdown]
# ## 5. Le problème des faux positifs légitimes
#
# La zone périodique contient les balises C2 — mais aussi tout ce qui est
# légitimement périodique : NTP, remontée d'agent EDR, sondes de supervision.
# **C'est le problème réel de la détection de balises.** Un détecteur qui remonte
# 48 couples dont 6 vrais est inutilisable tel quel.
#
# La solution n'est pas statistique, elle est **contextuelle**.

# %% [markdown]
# ### Exercice 5.1 — enrichir avec le contexte
#
# Ajoutez, pour chaque couple, le nombre d'hôtes distincts qui contactent la même
# destination. Argument d'analyste :
#
# > *Un service légitime (serveur de temps, télémétrie éditeur) est contacté par
# > beaucoup de machines. Un serveur de commande et de contrôle, dans une
# > compromission ciblée, ne l'est que par les machines compromises.*
#
# Mesurez la précision et le rappel avant et après ce filtre.

# %% tags=["todo"]
# TODO : popularité = nb d'IP sources distinctes par destination ; filtrer.

# %% tags=["solution"]
popularite = flux.groupby("ip_destination")["ip_source"].nunique().rename("hotes_vers_destination")
paires = paires.merge(popularite, on="ip_destination", how="left")

candidats = paires[(paires["cv_intervalle"] < 0.25) & (paires["cv_taille"] < 0.35)].copy()
retenus = candidats[candidats["hotes_vers_destination"] <= 2]


def bilan(sous_ensemble, libelle):
    n = len(sous_ensemble)
    vrais = int((sous_ensemble["categorie_reelle"] == "c2_beaconing").sum())
    total_c2 = int((paires["categorie_reelle"] == "c2_beaconing").sum())
    print(f"{libelle}")
    print(f"   {n} couples remontés · {vrais} balises C2 réelles")
    print(f"   précision {vrais / max(n, 1):.0%} · rappel {vrais / max(total_c2, 1):.0%}\n")


bilan(candidats, "Régularité seule")
bilan(retenus, "Régularité + destination contactée par ≤ 2 hôtes")

print("Couples retenus :")
print(retenus[["ip_source", "ip_destination", "n_flux", "cv_intervalle",
               "intervalle_median_s", "hotes_vers_destination", "categorie_reelle"]]
      .round(3).to_string(index=False))

# %% [markdown]
# > **La leçon de cet atelier.** Nous sommes passés d'un détecteur à 0 % de rappel
# > sur les balises C2 à un détecteur exploitable, **sans changer d'algorithme** :
# >
# > 1. changement d'unité d'observation (flux → couple) ;
# > 2. variable construite sur une hypothèse d'analyste (régularité) ;
# > 3. enrichissement contextuel (popularité de la destination).
# >
# > L'algorithme n'a jamais été le facteur limitant. C'est la règle générale en
# > détection d'anomalies appliquée à la sécurité.

# %% [markdown]
# ## 6. Comparer les familles de détecteurs
#
# Maintenant que la représentation est bonne, comparons les algorithmes — et
# constatons que l'écart entre eux est bien plus faible que l'écart entre les
# représentations.

# %%
detecteurs = {
    "Forêt d'isolement": IsolationForest(n_estimators=300, contamination=.05,
                                         random_state=ALEA, n_jobs=-1),
    "LOF (novelty)": LocalOutlierFactor(n_neighbors=20, contamination=.05,
                                        novelty=True),
    "SVM à une classe": OneClassSVM(nu=.05, gamma="scale"),
    "Enveloppe elliptique": EllipticEnvelope(contamination=.05, support_fraction=.9,
                                             random_state=ALEA),
}

resultats = {}
for nom, detecteur in detecteurs.items():
    detecteur.fit(Ps)
    s = -detecteur.score_samples(Ps) if hasattr(detecteur, "score_samples") \
        else -detecteur.decision_function(Ps)
    resultats[nom] = s
    print(f"{nom:22s} AUC-ROC={roc_auc_score(paires['anomalie'], s):.3f}  "
          f"AUC-PR={average_precision_score(paires['anomalie'], s):.3f}")
print(f"\nTaux de base : {paires['anomalie'].mean():.3f}")

# %%
fig, ax = plt.subplots(figsize=(8, 5))
for nom, s in resultats.items():
    precision, rappel_, _ = precision_recall_curve(paires["anomalie"], s)
    ax.plot(rappel_, precision, label=f"{nom} ({average_precision_score(paires['anomalie'], s):.3f})")
ax.axhline(paires["anomalie"].mean(), ls="--", color="k", lw=.8, label="hasard")
ax.set(xlabel="rappel", ylabel="précision",
       title="Détecteurs comparés sur la MÊME représentation")
ax.legend(fontsize=8)
ax.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# ## 7. La contamination : l'hyperparamètre qui ment
#
# Tous ces détecteurs prennent un paramètre `contamination` : la proportion
# supposée d'anomalies. **On ne la connaît jamais.** Mesurons l'impact de ce choix.

# %%
taux = [0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20]
lignes = []
for t in taux:
    d = IsolationForest(n_estimators=200, contamination=t, random_state=ALEA,
                        n_jobs=-1).fit(Ps)
    predit = d.predict(Ps) == -1
    vp = int((predit & paires["anomalie"]).sum())
    lignes.append({"contamination": t, "remontes": int(predit.sum()),
                   "vrais_positifs": vp,
                   "precision": vp / max(predit.sum(), 1),
                   "rappel": vp / int(paires["anomalie"].sum())})
pd.DataFrame(lignes).round(3).to_string(index=False)

# %% [markdown]
# > **Conséquence pratique.** `contamination` ne fixe pas un niveau de risque : il
# > fixe un **volume d'alertes**. En production, on ne le règle pas « au mieux »,
# > on le règle sur la capacité de traitement de l'équipe — exactement comme le
# > seuil de l'atelier 04. Et on documente ce choix.

# %% [markdown]
# ## 8. Évaluer sans vérité terrain
#
# Le cas réel. Trois substituts, aucun n'étant équivalent à une étiquette.

# %%
score_reference = resultats["Forêt d'isolement"]

# (a) Stabilité : deux graines différentes classent-elles pareil ?
from scipy.stats import spearmanr

a = -IsolationForest(n_estimators=200, contamination=.05, random_state=1,
                     n_jobs=-1).fit(Ps).score_samples(Ps)
b = -IsolationForest(n_estimators=200, contamination=.05, random_state=2,
                     n_jobs=-1).fit(Ps).score_samples(Ps)
print(f"(a) Stabilité entre deux graines (Spearman) : {spearmanr(a, b).statistic:.3f}")

# (b) Concordance entre familles d'algorithmes
noms = list(resultats)
concordance = pd.DataFrame(
    [[spearmanr(resultats[x], resultats[y]).statistic for y in noms] for x in noms],
    index=noms, columns=noms,
)
print("\n(b) Concordance entre détecteurs (Spearman) :")
print(concordance.round(2).to_string())

# (c) Taux de confirmation par l'analyste : le seul vrai indicateur
print("\n(c) Taux de confirmation analyste sur les 20 premiers remontés :")
top20 = paires.nlargest(20, "score")
print(f"    {int((top20['categorie_reelle'] != 'normal').sum())}/20 confirmés")
print("    → c'est CET indicateur qu'il faut instrumenter en production,")
print("      en journalisant systématiquement le verdict rendu sur chaque remontée.")

# %% [markdown]
# ## 9. Synthèse et travail personnel
#
# **À retenir**
#
# 1. Trois types d'anomalies, trois unités d'observation. **Le cadrage précède
#    l'algorithme.**
# 2. Un détecteur qui obtient 0 % de rappel sur une catégorie entière ne souffre
#    pas d'un mauvais réglage : il souffre d'une mauvaise représentation.
# 3. Les familles d'algorithmes se valent largement à représentation égale.
# 4. L'**enrichissement contextuel** est ce qui rend un détecteur exploitable.
# 5. `contamination` fixe un volume d'alertes, pas un niveau de risque.
# 6. Sans étiquettes, on mesure la **stabilité**, la **concordance**, et surtout
#    le **taux de confirmation** par les analystes — qu'il faut donc journaliser.
#
# **Travail personnel (≥ 4 h)**
#
# - Le tunnel DNS n'est toujours pas traité. Construisez la représentation qui le
#   révèle (indice : volume sortant par requête, nombre de requêtes par heure vers
#   un même résolveur, ratio envoyé/reçu sur UDP/53) et mesurez votre rappel.
# - Ajoutez une dimension temporelle : au lieu d'agréger les 14 jours, découpez en
#   fenêtres de 24 h et détectez le **jour d'apparition** de chaque anomalie.
# - Rédigez la procédure de réponse associée à une détection de balise C2 :
#   éléments à collecter, critères d'escalade, actions de confinement. Une
#   détection sans procédure n'est pas une capacité de détection.
#
# **Suite :** atelier 09 — les données non structurées.
