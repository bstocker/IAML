# ---
# Atelier 05 — Temps 3 : Machine Learning (2/4) — semaine 7
# ---

# %% [markdown]
# # Atelier 05 — Apprentissage non supervisé : segmenter et réduire les journaux
#
# > **Temps 3 — Machine Learning** (1 UT sur 4) · **semaine 7** · 2 h de TP
#
# ## Objectifs
#
# 1. Construire une **représentation vectorielle** d'une entité (ici : un hôte) à
#    partir de journaux bruts.
# 2. Appliquer et comparer trois familles de **partitionnement** : k-moyennes,
#    classification ascendante hiérarchique, DBSCAN.
# 3. Choisir un nombre de groupes avec des critères défendables (coude, silhouette)
#    — et savoir que le critère décisif reste l'**interprétabilité**.
# 4. Réduire la dimension (**ACP**) pour visualiser et pour dénoyauter le bruit.
# 5. Transformer une segmentation en **capacité de détection** : la référence de
#    normalité par groupe.
#
# ## Le problème
#
# 66 000 événements système, 140 machines, **aucune étiquette**. Personne n'a
# jamais écrit dans la CMDB « ce poste est utilisé comme station de développement ».
# Question : *quels sont les usages réels de notre parc, et lesquelles de nos
# machines se comportent de façon atypique par rapport à leurs semblables ?*

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.cluster.hierarchy import dendrogram, linkage
from sklearn.cluster import DBSCAN, AgglomerativeClustering, KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import adjusted_rand_score, silhouette_samples, silhouette_score
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.preprocessing import StandardScaler

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
ALEA = 42

evenements = pd.read_csv(DATA / "evenements_systeme.csv", parse_dates=["horodatage"])
print(f"{len(evenements):,} événements · {evenements['hostname'].nunique()} hôtes · "
      f"{evenements['horodatage'].dt.date.nunique()} jours")
evenements.head()

# %% [markdown]
# ## 1. Le choix décisif : l'unité d'observation
#
# On peut vectoriser l'événement, l'heure, le jour, l'hôte, le compte, le couple
# hôte × compte… **Ce choix détermine ce qui sera détectable** et il est
# irréversible pour la suite du pipeline.
#
# Ici : *un hôte = une observation*, décrit par son profil d'activité sur 30 jours.
# Justification : la question posée porte sur l'usage des machines.

# %%
def vectoriser_hotes(ev: pd.DataFrame) -> pd.DataFrame:
    """Un vecteur de caractéristiques par hôte, à partir des journaux bruts."""
    ev = ev.copy()
    ev["heure"] = ev["horodatage"].dt.hour
    ev["jour"] = ev["horodatage"].dt.date
    ev["week_end"] = ev["horodatage"].dt.weekday >= 5

    # (a) Profil de types d'événements, en PROPORTIONS et non en volumes bruts :
    #     sinon la variable dominante serait la taille de la machine.
    mix = pd.crosstab(ev["hostname"], ev["type_evenement"], normalize="index")
    mix.columns = [f"part_{c}" for c in mix.columns]

    # (b) Volumétrie et rythme
    volume = ev.groupby("hostname").agg(
        evenements_total=("event_id", "size"),
        jours_actifs=("jour", "nunique"),
        comptes_distincts=("username", "nunique"),
        processus_distincts=("processus", lambda s: s[s != ""].nunique()),
    )
    volume["evenements_par_jour"] = np.log1p(
        volume["evenements_total"] / volume["jours_actifs"].clip(lower=1)
    )

    # (c) Profil temporel
    temps = ev.groupby("hostname").agg(
        part_nuit=("heure", lambda s: (s < 7).mean()),
        part_week_end=("week_end", "mean"),
        heure_mediane=("heure", "median"),
        dispersion_horaire=("heure", "std"),
    )

    # (d) Signaux de sécurité, relatifs au volume de l'hôte
    secu = ev.assign(
        echec=(ev["type_evenement"] == "echec_auth"),
        elev=(ev["type_evenement"] == "elevation"),
    ).groupby("hostname").agg(taux_echec=("echec", "mean"),
                              taux_elevation=("elev", "mean"))

    X = mix.join([volume, temps, secu]).drop(columns=["evenements_total", "jours_actifs"])
    return X.fillna(0)


X_brut = vectoriser_hotes(evenements)
print(f"{X_brut.shape[0]} hôtes × {X_brut.shape[1]} caractéristiques")
X_brut.head(3).round(3)

# %% [markdown]
# ## 2. Normaliser — sans quoi le partitionnement est faux
#
# Les k-moyennes minimisent une distance euclidienne. Une variable exprimée en
# milliers écrase mécaniquement une proportion comprise entre 0 et 1.

# %%
print("Écarts-types avant normalisation :")
print(X_brut.std().sort_values(ascending=False).head(5).round(3))

echelle = StandardScaler()
X = echelle.fit_transform(X_brut)
print(f"\nAprès normalisation : moyenne ≈ {X.mean():.2e}, écart-type ≈ {X.std():.3f}")

# %% [markdown]
# ## 3. Combien de groupes ?
#
# Deux critères usuels, qui ne sont **pas** des preuves : le coude de l'inertie et
# le coefficient de silhouette.

# %%
ks = range(2, 11)
inerties, silhouettes = [], []
for k in ks:
    km = KMeans(n_clusters=k, n_init=20, random_state=ALEA).fit(X)
    inerties.append(km.inertia_)
    silhouettes.append(silhouette_score(X, km.labels_))

fig, axes = plt.subplots(1, 2, figsize=(11.5, 4))
axes[0].plot(list(ks), inerties, marker="o")
axes[0].set(xlabel="nombre de groupes k", ylabel="inertie intra-classe",
            title="Méthode du coude")
axes[1].plot(list(ks), silhouettes, marker="o", color="darkorange")
axes[1].set(xlabel="nombre de groupes k", ylabel="silhouette moyenne",
            title="Coefficient de silhouette")
for a in axes:
    a.grid(alpha=.3)
k_optimal = list(ks)[int(np.argmax(silhouettes))]
axes[1].axvline(k_optimal, ls=":", color="grey")
plt.tight_layout()
print(f"Silhouette maximale pour k = {k_optimal} ({max(silhouettes):.3f})")

# %% [markdown]
# > **Prudence.** La silhouette récompense les partitions sphériques et bien
# > séparées. Elle peut préférer k = 2 (« gros » et « petits » serveurs) là où
# > l'exploitant a besoin de cinq profils exploitables. **Le critère final est
# > opérationnel : un groupe que personne ne sait nommer est un groupe inutile.**

# %% [markdown]
# ## 4. k-moyennes et interprétation
#
# L'étape d'interprétation est le vrai livrable. On caractérise chaque groupe par
# ses écarts à la moyenne générale.

# %%
K = 5
kmeans = KMeans(n_clusters=K, n_init=30, random_state=ALEA).fit(X)
X_brut["groupe"] = kmeans.labels_

profils = X_brut.groupby("groupe").mean()
ecarts = (profils - X_brut.drop(columns="groupe").mean()) / X_brut.drop(columns="groupe").std()

print(f"Effectifs : {np.bincount(kmeans.labels_)}\n")
for g in range(K):
    haut = ecarts.loc[g].sort_values(ascending=False).head(3)
    bas = ecarts.loc[g].sort_values().head(2)
    print(f"Groupe {g} ({(kmeans.labels_ == g).sum():>3} hôtes)")
    print("   fort  : " + ", ".join(f"{n} ({v:+.1f}σ)" for n, v in haut.items()))
    print("   faible: " + ", ".join(f"{n} ({v:+.1f}σ)" for n, v in bas.items()))

# %% [markdown]
# ### Exercice 4.1 — nommer les groupes
#
# À partir des écarts ci-dessus, proposez un nom métier pour chacun des cinq
# groupes et une phrase de caractérisation. Un nom du type « groupe 3 » n'a
# aucune valeur pour un exploitant.

# %% tags=["todo"]
# TODO : dictionnaire {numero_de_groupe: "nom métier"} et justification.
noms_groupes = {}

# %% tags=["solution"]
# Attribution guidée par les écarts : on s'appuie sur les variables les plus
# discriminantes, pas sur une intuition.
def nommer(ecarts_g: pd.Series) -> str:
    if ecarts_g["part_elevation"] > 1 or ecarts_g["taux_elevation"] > 1:
        return "administration systeme"
    if ecarts_g["evenements_par_jour"] > 0.8 and ecarts_g["part_nuit"] > 0.5:
        return "serveur batch / traitement de nuit"
    if ecarts_g["processus_distincts"] > 0.5:
        return "poste de developpement"
    if ecarts_g["part_ouverture_session"] > 0.7 or ecarts_g["taux_echec"] > 0.7:
        return "poste itinerant / nomade"
    return "poste bureautique"


noms_groupes = {g: nommer(ecarts.loc[g]) for g in range(K)}
for g, nom in noms_groupes.items():
    print(f"Groupe {g} ({(kmeans.labels_ == g).sum():>3} hôtes) → {nom}")

# %% [markdown]
# ## 5. Validation *a posteriori*
#
# Dans un vrai SOC, il n'y a pas de vérité terrain. Ici, le générateur en a
# conservé une pour que vous puissiez mesurer la qualité de la démarche —
# **elle n'a jamais servi à l'apprentissage**.

# %%
verite = pd.read_csv(DATA / "verite_terrain" / "profils_hotes.csv")
compare = X_brut.reset_index()[["hostname", "groupe"]].merge(verite, on="hostname")

ari = adjusted_rand_score(compare["profil_usage"], compare["groupe"])
print(f"Indice de Rand ajusté : {ari:.3f}  (0 = hasard, 1 = partition identique)\n")
tableau = pd.crosstab(compare["profil_usage"], compare["groupe"].map(noms_groupes))
tableau

# %% [markdown]
# > **Ce que cela valide et ce que cela ne valide pas.** Un ARI élevé confirme que
# > la structure d'usage est bien présente dans les journaux et que la
# > vectorisation la capte. Il ne dit rien de l'utilité opérationnelle : c'est
# > l'usage qui suit (§ 7) qui la démontre.

# %% [markdown]
# ## 6. Réduction de dimension : ACP
#
# L'ACP sert ici à deux choses : **visualiser** en 2D, et **comprendre** quelles
# combinaisons de variables portent la variance.

# %%
acp = PCA(n_components=None, random_state=ALEA).fit(X)
variance_cumulee = np.cumsum(acp.explained_variance_ratio_)
n_90 = int(np.searchsorted(variance_cumulee, 0.90) + 1)

fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.6))
axes[0].bar(range(1, len(acp.explained_variance_ratio_) + 1),
            acp.explained_variance_ratio_ * 100, alpha=.75)
axes[0].plot(range(1, len(variance_cumulee) + 1), variance_cumulee * 100,
             marker="o", color="crimson", label="cumul")
axes[0].axhline(90, ls="--", color="grey")
axes[0].set(xlabel="composante", ylabel="variance expliquée (%)",
            title=f"Éboulis — {n_90} composantes pour 90 % de la variance")
axes[0].legend()

C = acp.transform(X)
for g in range(K):
    m = kmeans.labels_ == g
    axes[1].scatter(C[m, 0], C[m, 1], s=42, alpha=.75, label=noms_groupes[g])
axes[1].set(xlabel=f"CP1 ({acp.explained_variance_ratio_[0]:.0%})",
            ylabel=f"CP2 ({acp.explained_variance_ratio_[1]:.0%})",
            title="Parc projeté sur les deux premières composantes")
axes[1].legend(fontsize=8)
axes[1].grid(alpha=.3)
plt.tight_layout()

# %%
# Que « signifient » les deux premières composantes ?
charges = pd.DataFrame(acp.components_[:2].T, index=X_brut.drop(columns="groupe").columns,
                       columns=["CP1", "CP2"])
print("Variables contribuant le plus à CP1 :")
print(charges["CP1"].abs().sort_values(ascending=False).head(4).round(3))
print("\nVariables contribuant le plus à CP2 :")
print(charges["CP2"].abs().sort_values(ascending=False).head(4).round(3))

# %% [markdown]
# ## 7. Comparer les familles d'algorithmes
#
# Les k-moyennes imposent des groupes convexes et de taille comparable, et
# **affectent tout le monde**. DBSCAN, lui, sait dire « ce point n'appartient à
# aucun groupe » — propriété précieuse en sécurité.

# %%
# Choix d'epsilon par la courbe des k-distances (méthode standard pour DBSCAN).
k_min = 4
distances, _ = NearestNeighbors(n_neighbors=k_min).fit(X).kneighbors(X)
d_triees = np.sort(distances[:, -1])

fig, ax = plt.subplots(figsize=(7, 3.4))
ax.plot(d_triees)
ax.set(xlabel="hôtes triés", ylabel=f"distance au {k_min}ᵉ plus proche voisin",
       title="Choix d'epsilon : le coude de la courbe des k-distances")
eps = float(np.percentile(d_triees, 90))
ax.axhline(eps, color="crimson", ls="--", label=f"eps = {eps:.2f}")
ax.legend()
ax.grid(alpha=.3)
plt.tight_layout()

# %%
resultats = {}

cah = AgglomerativeClustering(n_clusters=K, linkage="ward").fit(X)
resultats["CAH (Ward)"] = cah.labels_

db = DBSCAN(eps=eps, min_samples=k_min).fit(X)
resultats["DBSCAN"] = db.labels_

resultats["k-moyennes"] = kmeans.labels_

for nom, etiquettes in resultats.items():
    n_groupes = len(set(etiquettes) - {-1})
    bruit = int((etiquettes == -1).sum())
    masque = etiquettes != -1
    sil = (silhouette_score(X[masque], etiquettes[masque])
           if n_groupes > 1 and masque.sum() > n_groupes else float("nan"))
    ari_n = adjusted_rand_score(
        verite.set_index("hostname").loc[X_brut.index, "profil_usage"], etiquettes
    )
    print(f"{nom:14s} groupes={n_groupes}  hors-groupe={bruit:>3}  "
          f"silhouette={sil:.3f}  ARI={ari_n:.3f}")

# %%
fig, ax = plt.subplots(figsize=(13, 4))
Z = linkage(X, method="ward")
dendrogram(Z, ax=ax, no_labels=True, color_threshold=Z[-(K - 1), 2])
ax.set(title="Dendrogramme (Ward) — la coupure fixe le nombre de groupes",
       ylabel="distance d'agrégation")
ax.axhline(Z[-(K - 1), 2], ls="--", color="grey")
plt.tight_layout()

# %% [markdown]
# ## 8. De la segmentation à la détection
#
# Un partitionnement n'est pas une fin. Son intérêt opérationnel : définir une
# **référence de normalité par groupe**. Un serveur de sauvegarde qui travaille la
# nuit est normal ; un poste bureautique qui adopte le même profil ne l'est pas.
#
# Nous cherchons ici les hôtes **atypiques au sein de leur propre groupe**.

# %%
# Distance au centre du groupe, exprimée en écarts-types du groupe.
distance_centre = np.linalg.norm(X - kmeans.cluster_centers_[kmeans.labels_], axis=1)
atypie = pd.DataFrame({"hostname": X_brut.index, "groupe": kmeans.labels_,
                       "distance": distance_centre})
atypie["z_intra_groupe"] = atypie.groupby("groupe")["distance"].transform(
    lambda s: (s - s.mean()) / s.std()
)

# Deuxième point de vue : facteur d'aberration locale, qui ne suppose pas de forme.
lof = LocalOutlierFactor(n_neighbors=12)
lof.fit_predict(X)
atypie["score_lof"] = -lof.negative_outlier_factor_

atypie = atypie.merge(verite, on="hostname")
suspects = atypie.sort_values("score_lof", ascending=False).head(12)
print("Hôtes les plus atypiques (colonne 'compromis' = vérité terrain, non utilisée) :")
suspects[["hostname", "groupe", "z_intra_groupe", "score_lof",
          "profil_usage", "compromis"]].round(2).to_string(index=False)

# %% [markdown]
# ### Exercice 8.1
#
# Le générateur a compromis 6 hôtes sur 140. Mesurez le **rappel dans les K
# premiers** pour chacun des deux scores (`z_intra_groupe` et `score_lof`),
# pour K = 10, 20 et 30, puis commentez : lequel utiliseriez-vous, et surtout,
# **que faudrait-il ajouter** pour que ce soit exploitable ?

# %% tags=["todo"]
# TODO : pour chaque score et chaque K, compter les hôtes compromis dans le top K.

# %% tags=["solution"]
n_compromis = int(atypie["compromis"].sum())
print(f"{n_compromis} hôtes compromis sur {len(atypie)}\n")
print(f"{'K':>4} | {'z intra-groupe':>15} | {'LOF':>10}")
print("-" * 36)
for K_top in (10, 20, 30):
    r_z = atypie.nlargest(K_top, "z_intra_groupe")["compromis"].sum()
    r_l = atypie.nlargest(K_top, "score_lof")["compromis"].sum()
    print(f"{K_top:>4} | {r_z:>7}/{n_compromis} ({r_z / n_compromis:>4.0%}) | "
          f"{r_l:>3}/{n_compromis} ({r_l / n_compromis:>4.0%})")

print(f"""
Lecture.

1. Le LOF retrouve les {n_compromis} hotes compromis dans les 10 premiers, la
   distance au centre du groupe non. Ce n'est pas un hasard : la distance au
   centroide suppose des groupes spheriques et de densite homogene, alors que le
   LOF compare la densite locale d'un point a celle de ses voisins. Un hote
   compromis reste PRES de son groupe d'origine — il ne s'en detache pas assez
   pour ressortir en distance, mais il s'installe dans une zone peu peuplee.

2. La precision reste faible : 6 vrais sur 10 remontes. A l'echelle d'un parc de
   10 000 machines, 40 % de faux positifs sur une liste de vérification est un
   cout de traitement considerable. Un score d'atypie est un outil de PRIORISATION,
   jamais une conclusion.

3. Le biais methodologique le plus important est ailleurs : nous avons agrege
   30 jours d'historique. En production, on ne dispose pas de ce recul — la
   compromission est en cours. La vraie question n'est pas « quelle machine est
   atypique aujourd'hui ? » mais « a partir de quel jour aurait-on pu le voir ? ».

Pour aller plus loin, il faudrait :
  * une dimension TEMPORELLE : comparer chaque hote a son propre passe plutot
    qu'a ses pairs (atelier 08) ;
  * des caracteristiques plus fines : arbre de processus, couples parent/enfant
    inhabituels, lignes de commande (atelier 06) ;
  * un enrichissement reseau : un poste d'administration legitime ne contacte pas
    une adresse externe inconnue de facon reguliere (atelier 08).
""")

# %% [markdown]
# ### Exercice 8.2 — quand aurait-on pu le voir ?
#
# Recalculez la vectorisation sur des fenêtres glissantes de 7 jours et suivez le
# score LOF de chaque hôte au fil du temps. Comparez la date de décrochage avec
# la colonne `jour_compromission` de la vérité terrain.

# %% tags=["todo"]
# TODO : boucler sur les fenêtres de 7 jours, vectoriser, calculer le LOF,
#        tracer la trajectoire des hôtes compromis contre celle des autres.

# %% tags=["solution"]
jour_zero = evenements["horodatage"].min().normalize()
evenements["jour_relatif"] = (evenements["horodatage"] - jour_zero).dt.days

trajectoires = []
for fin in range(7, int(evenements["jour_relatif"].max()) + 1):
    fenetre = evenements[evenements["jour_relatif"].between(fin - 7, fin - 1)]
    Xf = vectoriser_hotes(fenetre)
    Xf = Xf.reindex(X_brut.index).fillna(0)
    Xs = StandardScaler().fit_transform(Xf)
    l = LocalOutlierFactor(n_neighbors=12)
    l.fit_predict(Xs)
    trajectoires.append(pd.Series(-l.negative_outlier_factor_, index=Xf.index, name=fin))

traj = pd.concat(trajectoires, axis=1)
info = verite.set_index("hostname")

fig, ax = plt.subplots(figsize=(11, 4.4))
for hote in traj.index:
    if not info.loc[hote, "compromis"]:
        ax.plot(traj.columns, traj.loc[hote], color="lightgrey", lw=.7, alpha=.5)
for hote in traj.index[info.loc[traj.index, "compromis"]]:
    ax.plot(traj.columns, traj.loc[hote], lw=1.8, label=hote)
    ax.axvline(info.loc[hote, "jour_compromission"], ls=":", lw=.8, alpha=.5)
ax.set(xlabel="fin de la fenêtre glissante de 7 jours", ylabel="score LOF",
       title="Trajectoire d'atypie — en couleur : les hôtes compromis\n"
             "(pointillés : date réelle de compromission)")
ax.legend(fontsize=7, ncol=3)
ax.grid(alpha=.3)
plt.tight_layout()

detection = []
seuil_alerte = traj.stack().quantile(0.97)
for hote in traj.index[info.loc[traj.index, "compromis"]]:
    depassements = traj.columns[traj.loc[hote] > seuil_alerte]
    reels = info.loc[hote, "jour_compromission"]
    apres = [d for d in depassements if d >= reels]
    detection.append({"hote": hote, "compromission_jour": reels,
                      "premiere_alerte": apres[0] if apres else None,
                      "delai_jours": (apres[0] - reels) if apres else None})
print(f"Seuil d'alerte (97ᵉ centile des scores) : {seuil_alerte:.2f}\n")
print(pd.DataFrame(detection).to_string(index=False))

# %% [markdown]
# **Lecture du tableau.** Une partie des compromissions est détectée avec un délai
# de 0 à 3 jours ; les autres ne le sont pas du tout, parce qu'elles surviennent
# trop près de la fin de la période observée : la fenêtre de 7 jours n'a pas encore
# accumulé assez d'événements attaquants pour faire décrocher le score.
#
# C'est la contrainte fondamentale de la détection comportementale : **il faut du
# signal accumulé pour détecter, donc du temps — et ce temps est celui pendant
# lequel l'attaquant agit.** Réduire la fenêtre améliore la réactivité et dégrade
# la précision. Ce compromis se règle par cas d'usage, pas une fois pour toutes.

# %% [markdown]
# ## 9. Synthèse et travail personnel
#
# **À retenir**
#
# 1. En non supervisé, **la vectorisation est le modèle**. Le choix de l'unité
#    d'observation et des caractéristiques compte plus que l'algorithme.
# 2. La normalisation n'est pas une formalité : sans elle, la partition est celle
#    de l'unité de mesure.
# 3. Coude et silhouette **orientent** le choix de k ; l'interprétabilité tranche.
# 4. Les k-moyennes affectent tout le monde ; DBSCAN sait laisser des points de
#    côté — ce qui, en sécurité, est souvent l'information recherchée.
# 5. Une segmentation devient utile quand elle sert de **référence de normalité
#    par groupe**, pas quand elle produit un joli nuage de points.
#
# **Travail personnel (≥ 4 h)**
#
# - Refaites la vectorisation à l'échelle **hôte × jour** (au lieu de hôte).
#   Les groupes changent-ils de nature ? Que devient la détection d'atypies ?
# - Comparez `KMeans` et `GaussianMixture` : que gagne-t-on à disposer d'une
#   probabilité d'appartenance plutôt que d'une affectation dure ?
# - Rédigez la fiche de restitution destinée au responsable d'exploitation :
#   les cinq profils, leurs effectifs, et les trois hôtes à vérifier en priorité.
#
# **Suite :** atelier 06 — réseaux de neurones et représentation apprise.
