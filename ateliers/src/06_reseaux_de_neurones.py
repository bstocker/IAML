# ---
# Atelier 06 — Temps 3 : Machine Learning (3/4) — semaine 8
# ---

# %% [markdown]
# # Atelier 06 — Réseaux de neurones : du perceptron à la modélisation de séquences
#
# > **Temps 3 — Machine Learning** (1 UT sur 4) · **semaine 8** · 2 h de TP
#
# ## Objectifs
#
# 1. Relier le **perceptron** à la régression logistique de l'atelier 04 : même
#    objet, vocabulaire différent.
# 2. Mesurer honnêtement ce qu'un **perceptron multicouche** apporte — et
#    n'apporte pas — sur des données tabulaires de sécurité.
# 3. Comprendre le vrai apport de l'apprentissage profond en cybersécurité :
#    la **représentation apprise** sur des données séquentielles.
# 4. Construire un modèle de **prédiction du prochain événement** dans un journal
#    et s'en servir comme détecteur (approche de type *DeepLog*).
# 5. Utiliser un **auto-encodeur** comme détecteur d'anomalies par erreur de
#    reconstruction.
# 6. Savoir dire **quand ne pas** utiliser de réseau de neurones.
#
# > **Note d'implémentation.** Nous utilisons `scikit-learn` (`MLPClassifier`,
# > `MLPRegressor`), suffisant pour les principes et installable en quelques
# > secondes. Pour des architectures récurrentes ou attentionnelles réelles
# > (LSTM, *transformers*), on passerait à PyTorch — la démarche et les pièges
# > restent identiques.

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.preprocessing import MinMaxScaler, StandardScaler

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
ALEA = 42
rng = np.random.default_rng(ALEA)

# %% [markdown]
# ## 1. Le perceptron : une régression logistique en costume
#
# Un neurone calcule `σ(w·x + b)`. C'est **exactement** la régression logistique
# de l'atelier 04. La différence tient à l'empilement : plusieurs couches
# permettent de représenter des frontières non linéaires que la régression
# logistique ne peut pas exprimer.
#
# Vérifions-le sur un cas artificiel où la frontière est un XOR — la situation
# typique en sécurité : *« un accès administrateur est normal depuis le réseau
# d'administration, et normal en heures ouvrables, mais anormal s'il est
# externe ET nocturne »*.

# %%
n = 1500
externe = rng.integers(0, 2, n)
nocturne = rng.integers(0, 2, n)
bruit = rng.normal(0, .22, (n, 2))
Xd = np.c_[externe, nocturne] + bruit
yd = (externe ^ nocturne)  # ou exclusif : non linéairement séparable

from sklearn.linear_model import LogisticRegression

lin = LogisticRegression().fit(Xd, yd)
mlp = MLPClassifier(hidden_layer_sizes=(8,), max_iter=3000,
                    random_state=ALEA).fit(Xd, yd)
print(f"Régression logistique (1 couche) : exactitude = {lin.score(Xd, yd):.3f}")
print(f"Perceptron multicouche (8 neurones cachés) : exactitude = {mlp.score(Xd, yd):.3f}")

fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
grille = np.mgrid[-.6:1.6:200j, -.6:1.6:200j].reshape(2, -1).T
for ax, modele, titre in [(axes[0], lin, "Régression logistique"),
                          (axes[1], mlp, "Perceptron multicouche")]:
    zz = modele.predict_proba(grille)[:, 1].reshape(200, 200)
    ax.contourf(np.linspace(-.6, 1.6, 200), np.linspace(-.6, 1.6, 200), zz.T,
                levels=20, cmap="RdYlBu_r", alpha=.65)
    ax.scatter(Xd[:, 0], Xd[:, 1], c=yd, cmap="RdYlBu_r", s=8, edgecolor="k", lw=.2)
    ax.set(xlabel="source externe", ylabel="hors heures ouvrables", title=titre)
plt.tight_layout()

# %% [markdown]
# > **Ce que ça veut dire concrètement.** Un modèle linéaire ne peut pas apprendre
# > « externe ET nocturne » sans qu'on lui fabrique explicitement la variable
# > d'interaction. Un réseau la construit tout seul. C'est son unique avantage
# > structurel — et il faut savoir combien il coûte.

# %% [markdown]
# ## 2. Sur données tabulaires, le réseau gagne-t-il ?
#
# Reprenons exactement le problème de l'atelier 04 et comparons honnêtement.

# %%
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

alertes = (pd.read_csv(DATA / "alertes_siem.csv", parse_dates=["horodatage"])
           .drop_duplicates(subset="alert_id").sort_values("horodatage")
           .reset_index(drop=True))
y = (alertes["verdict"] == "vrai_positif").astype(int)

X = pd.DataFrame({
    "severite_siem": alertes["severite_siem"],
    "reputation_source": alertes["reputation_source"],
    "criticite_actif": alertes["criticite_actif"],
    "evenements_correles": alertes["evenements_correles"],
    "log_octets": np.log1p(alertes["octets_transferes"]),
    "duree_fenetre_s": alertes["duree_fenetre_s"],
    "alertes_hote_24h": alertes["alertes_hote_24h"],
    "alertes_compte_24h": alertes["alertes_compte_24h"],
    "port_destination": alertes["port_destination"],
    "heure": alertes["horodatage"].dt.hour,
    "source_externe": alertes["source_externe"].astype(int),
    "compte_admin": alertes["compte_admin"].astype(int),
    "mfa_actif": alertes["mfa_actif"].astype(int),
    "agent_edr": alertes["agent_edr"].astype(int),
    "hors_heures_ouvrables": alertes["hors_heures_ouvrables"].astype(int),
    "famille_regle": alertes["famille_regle"],
    "zone": alertes["zone"],
})
CAT = ["famille_regle", "zone"]
NUM = [c for c in X.columns if c not in CAT]

pre = ColumnTransformer([
    ("num", Pipeline([("imp", SimpleImputer(strategy="median")),
                      ("norm", StandardScaler())]), NUM),
    ("cat", OneHotEncoder(handle_unknown="ignore", min_frequency=30), CAT),
])

coupure = alertes["horodatage"].quantile(0.7)
tr, te = alertes["horodatage"] < coupure, alertes["horodatage"] >= coupure

candidats = {
    "Gradient boosting": HistGradientBoostingClassifier(max_iter=300,
                                                        learning_rate=.08,
                                                        random_state=ALEA),
    "MLP (32,)": MLPClassifier(hidden_layer_sizes=(32,), max_iter=400,
                               early_stopping=True, random_state=ALEA),
    "MLP (64, 32)": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=400,
                                  early_stopping=True, alpha=1e-3, random_state=ALEA),
    "MLP (128, 64, 32)": MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=400,
                                       early_stopping=True, alpha=1e-2,
                                       random_state=ALEA),
}

import time

for nom, estimateur in candidats.items():
    pipe = Pipeline([("pre", pre), ("modele", estimateur)])
    t0 = time.perf_counter()
    pipe.fit(X[tr], y[tr])
    duree = time.perf_counter() - t0
    p = pipe.predict_proba(X[te])[:, 1]
    print(f"{nom:20s} AUC-PR={average_precision_score(y[te], p):.3f}  "
          f"AUC-ROC={roc_auc_score(y[te], p):.3f}  ({duree:.1f} s d'entraînement)")
print(f"\nTaux de base : {y[te].mean():.3f}")

# %% [markdown]
# ### Le résultat qu'il faut accepter
#
# Sur des données tabulaires hétérogènes de taille modeste, le *gradient boosting*
# égale ou dépasse le réseau de neurones, s'entraîne plus vite, ne demande aucun
# réglage d'architecture et reste interprétable. C'est un résultat **robuste**,
# régulièrement confirmé dans la littérature.
#
# > **Conséquence pratique.** Choisir un réseau de neurones pour un problème
# > tabulaire de SOC, c'est en général payer de la complexité, du temps de calcul
# > et de l'opacité pour rien. L'apprentissage profond se justifie quand la donnée
# > a une **structure** que l'on ne sait pas encoder à la main : séquences, texte,
# > graphes, images.
#
# Passons donc à ce pour quoi il est réellement utile.

# %% [markdown]
# ## 3. Modéliser une séquence de journaux
#
# **Idée** (celle de *DeepLog*, Du et al., CCS 2017, simplifiée) : un système sain
# produit des enchaînements très réguliers — une ouverture de session est suivie
# de lancements de processus, un échec d'authentification en appelle un autre, une
# élévation de privilèges précède une modification du registre. On apprend à
# prédire le **prochain** événement à partir des `K` précédents.
#
# Aucune étiquette d'attaque n'est nécessaire : **on apprend le normal**.

# %%
evenements = pd.read_csv(DATA / "evenements_systeme.csv", parse_dates=["horodatage"])
verite = pd.read_csv(DATA / "verite_terrain" / "profils_hotes.csv")

TYPES = sorted(evenements["type_evenement"].unique())
index_type = {t: i for i, t in enumerate(TYPES)}
evenements["code"] = evenements["type_evenement"].map(index_type)

jour_zero = evenements["horodatage"].min().normalize()
evenements["jour"] = (evenements["horodatage"] - jour_zero).dt.days

print(f"{len(TYPES)} types d'événements : {TYPES}")
print(f"{len(evenements):,} événements sur {evenements['jour'].max() + 1} jours")

# %% [markdown]
# ### 3.1 Fenêtres glissantes
#
# Le découpage se fait **par hôte** : concaténer les journaux de deux machines
# créerait des transitions qui n'ont jamais eu lieu.

# %%
K = 5  # longueur du contexte


def sequences(df: pd.DataFrame, k: int = K):
    """Renvoie (contextes, cible, hôte, jour) pour chaque fenêtre glissante."""
    contextes, cibles, hotes, jours = [], [], [], []
    for hote, groupe in df.sort_values("horodatage").groupby("hostname", observed=True):
        codes = groupe["code"].to_numpy()
        js = groupe["jour"].to_numpy()
        if len(codes) <= k:
            continue
        fenetres = np.lib.stride_tricks.sliding_window_view(codes, k + 1)
        contextes.append(fenetres[:, :k])
        cibles.append(fenetres[:, k])
        hotes.append(np.repeat(hote, len(fenetres)))
        jours.append(js[k:])
    return (np.vstack(contextes), np.concatenate(cibles),
            np.concatenate(hotes), np.concatenate(jours))


def encoder(C: np.ndarray) -> np.ndarray:
    """Encodage positionnel : la position dans le contexte est une information."""
    E = np.zeros((len(C), K * len(TYPES)), dtype=np.float32)
    for position in range(K):
        E[np.arange(len(C)), position * len(TYPES) + C[:, position]] = 1.0
    return E


# Protocole strict : on n'apprend le « normal » que sur des hôtes réputés sains
# et sur une période antérieure à toute compromission.
JOUR_FIN_APPRENTISSAGE = 12
JOUR_DEBUT_SURVEILLANCE = 18
sains = set(verite.loc[~verite["compromis"], "hostname"])

appr = evenements[(evenements["jour"] < JOUR_FIN_APPRENTISSAGE) &
                  evenements["hostname"].isin(sains)]
Ctr, ytr_seq, _, _ = sequences(appr)
Cte, yte_seq, hote_te, jour_te = sequences(
    evenements[evenements["jour"] >= JOUR_FIN_APPRENTISSAGE]
)
print(f"Apprentissage : {len(Ctr):,} fenêtres (jours 0-{JOUR_FIN_APPRENTISSAGE - 1}, "
      f"hôtes sains)")
print(f"Suite         : {len(Cte):,} fenêtres (jours {JOUR_FIN_APPRENTISSAGE}+, tous les hôtes)")

# %% [markdown]
# ### Exercice 3.1
#
# Entraînez un `MLPClassifier` à prédire le type d'événement suivant, puis mesurez
# l'exactitude **top-1** et **top-2**. Comparez à deux références :
#
# - la classe majoritaire (prédire toujours le type le plus fréquent) ;
# - un **contrôle par permutation** : les mêmes contextes, mélangés au hasard. Si
#   la performance ne baisse pas, c'est que le contexte n'apportait rien.

# %% tags=["todo"]
# TODO : entraîner, prédire, calculer top-1 / top-2, puis le contrôle par permutation.

# %% tags=["solution"]
Etr, Ete = encoder(Ctr), encoder(Cte)

reseau = MLPClassifier(hidden_layer_sizes=(64,), max_iter=80, early_stopping=True,
                       n_iter_no_change=5, random_state=ALEA)
reseau.fit(Etr, ytr_seq)

probas = reseau.predict_proba(Ete)
classes = reseau.classes_
rangs = np.argsort(-probas, axis=1)
top1 = classes[rangs[:, 0]] == yte_seq
top2 = (classes[rangs[:, :2]] == yte_seq[:, None]).any(axis=1)

majoritaire = np.bincount(ytr_seq).argmax()
print(f"Exactitude top-1            : {top1.mean():.1%}")
print(f"Exactitude top-2            : {top2.mean():.1%}")
print(f"Référence classe majoritaire: {(yte_seq == majoritaire).mean():.1%} "
      f"(« {TYPES[majoritaire]} »)")

# Contrôle : on casse le lien entre le contexte et sa cible.
melange = rng.permutation(len(Ete))
top1_melange = (classes[np.argsort(-reseau.predict_proba(Ete[melange]),
                                   axis=1)[:, 0]] == yte_seq).mean()
print(f"\nContrôle (contextes permutés) : {top1_melange:.1%}")
print(f"→ Le contexte apporte {top1.mean() - top1_melange:+.1%} d'exactitude : "
      f"la structure séquentielle est bien apprise.")

# %% [markdown]
# ### 3.2 Ce que le réseau a appris
#
# Interrogeons le modèle sur des contextes artificiels d'un seul type répété : la
# matrice de transition qu'il a intériorisée devient lisible.

# %%
contextes_purs = np.array([[i] * K for i in range(len(TYPES))])
transitions_apprises = pd.DataFrame(
    reseau.predict_proba(encoder(contextes_purs)),
    index=[f"après {t}" for t in TYPES],
    columns=[TYPES[c] for c in classes],
)

fig, ax = plt.subplots(figsize=(8.5, 5.5))
im = ax.imshow(transitions_apprises.to_numpy(), cmap="YlOrRd", aspect="auto")
ax.set_xticks(range(len(transitions_apprises.columns)))
ax.set_xticklabels(transitions_apprises.columns, rotation=45, ha="right", fontsize=8)
ax.set_yticks(range(len(transitions_apprises.index)))
ax.set_yticklabels(transitions_apprises.index, fontsize=8)
for i in range(transitions_apprises.shape[0]):
    for j in range(transitions_apprises.shape[1]):
        v = transitions_apprises.iat[i, j]
        if v > .12:
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=7)
ax.set_title("Matrice de transition apprise par le réseau\n"
             "(probabilité du prochain type d'événement)")
fig.colorbar(im, ax=ax, shrink=.8)
plt.tight_layout()

# %% [markdown]
# ## 4. Du modèle prédictif au détecteur
#
# Le score naturel est la **log-vraisemblance négative** de l'événement réellement
# observé : « à quel point le modèle était-il surpris ? ». Moyennée par hôte, elle
# mesure à quel point une machine est devenue imprévisible.

# %%
probabilite_reelle = probas[np.arange(len(yte_seq)),
                            np.searchsorted(classes, yte_seq)]
surprise = -np.log(np.clip(probabilite_reelle, 1e-9, None))

par_evenement = pd.DataFrame({"hostname": hote_te, "jour": jour_te,
                              "surprise": surprise})

# Deux périodes : une référence propre à chaque hôte, puis la surveillance.
reference = (par_evenement[par_evenement["jour"] < JOUR_DEBUT_SURVEILLANCE]
             .groupby("hostname")["surprise"].mean().rename("surprise_reference"))
surveillance = (par_evenement[par_evenement["jour"] >= JOUR_DEBUT_SURVEILLANCE]
                .groupby("hostname")["surprise"]
                .agg(surprise_observee="mean", n_evenements="size"))

scores = (surveillance.join(reference).dropna().query("n_evenements >= 50")
          .merge(verite, on="hostname"))
scores["ecart"] = scores["surprise_observee"] - scores["surprise_reference"]
n_comp = int(scores["compromis"].sum())

# %% [markdown]
# ### Exercice 4.1 — score absolu ou score relatif ?
#
# Comparez deux façons de classer les hôtes :
#
# - **score absolu** : `surprise_observee` — « cette machine est imprévisible » ;
# - **score relatif** : `ecart` — « cette machine est devenue plus imprévisible
#   qu'elle ne l'était ».
#
# Mesurez l'AUC et le rappel dans les 10 premiers pour chacun, puis expliquez
# l'écart.

# %% tags=["todo"]
# TODO : classer selon les deux scores, calculer AUC et rappel@10.

# %% tags=["solution"]
print(f"{n_comp} hôtes compromis parmi les {len(scores)} évalués\n")
for colonne, libelle in [("surprise_observee", "Score ABSOLU"),
                         ("ecart", "Score RELATIF (écart à sa propre référence)")]:
    classement = scores.sort_values(colonne, ascending=False)
    trouves = int(classement.head(10)["compromis"].sum())
    auc = roc_auc_score(scores["compromis"], scores[colonne])
    print(f"{libelle:46s} AUC={auc:.3f}  rappel@10 = {trouves}/{n_comp}")

print("\nDix premiers selon le score relatif :")
print(scores.sort_values("ecart", ascending=False)
      .head(10)[["hostname", "surprise_reference", "surprise_observee", "ecart",
                 "profil_usage", "compromis"]]
      .round(3).to_string(index=False))

# %% [markdown] tags=["solution"]
# #### Pourquoi le score relatif l'emporte
#
# Le score absolu classe en tête les hôtes des **profils minoritaires** (postes
# d'administration, serveurs de traitement par lots). Ils sont réellement
# imprévisibles pour un modèle appris sur la moyenne du parc — mais ils l'ont
# toujours été. Ce n'est pas une anomalie, c'est une **spécificité**.
#
# Le score relatif compare chaque machine à **elle-même**. Il élimine d'un coup
# tout le biais de profil, sans qu'on ait eu besoin de connaître les profils.
#
# > **Principe général de la détection comportementale :** la référence de
# > normalité doit être aussi proche que possible de l'entité surveillée.
# > Par ordre de préférence : l'entité elle-même > son groupe d'usage
# > (atelier 05) > le parc entier.

# %%
fig, ax = plt.subplots(figsize=(9, 5))
ax.scatter(scores.loc[~scores["compromis"], "surprise_reference"],
           scores.loc[~scores["compromis"], "surprise_observee"],
           s=26, alpha=.5, color="grey", label="hôtes sains")
ax.scatter(scores.loc[scores["compromis"], "surprise_reference"],
           scores.loc[scores["compromis"], "surprise_observee"],
           s=90, color="crimson", edgecolor="k", label="hôtes compromis", zorder=3)
limites = [scores["surprise_reference"].min() * .97, scores["surprise_observee"].max() * 1.03]
ax.plot(limites, limites, "k--", lw=1, label="pas de changement")
ax.set(xlabel="surprise moyenne AVANT (jours 12-17)",
       ylabel="surprise moyenne PENDANT (jours 18+)",
       title="Chaque hôte comparé à sa propre référence\n"
             "(au-dessus de la diagonale : le comportement a changé)")
ax.legend()
ax.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# ### Exercice 4.2 — discussion
#
# 1. La période de référence (jours 12-17) est supposée saine. Que se passe-t-il
#    si un hôte était **déjà** compromis pendant cette période ?
# 2. Comment intégreriez-vous ce détecteur au SOC : alerte unitaire, score
#    quotidien par hôte, ou revue hebdomadaire ? Justifiez.

# %% [markdown] tags=["solution"]
# #### Éléments de réponse
#
# **1.** C'est la faiblesse structurelle de toute détection par écart à une
# référence : si la référence est déjà contaminée, l'écart est nul et l'attaque
# devient invisible — le modèle a appris que l'anormal était normal. C'est le
# problème de l'**empoisonnement de la ligne de base**. Parades usuelles :
# constituer la référence sur une période auditée, la recalculer sur une fenêtre
# glissante longue (l'attaquant devrait alors rester furtif très longtemps), et
# croiser avec une référence de **pairs** — un hôte peut mentir sur son passé,
# difficilement sur sa ressemblance à ses semblables.
#
# **2.** L'alerte unitaire est à proscrire : la surprise d'un événement isolé n'a
# pas de sens statistique. Un **score quotidien par hôte**, comparé à la propre
# référence de l'hôte, offre le bon compromis : réactivité de 24 h, volume
# maîtrisé, et un score interprétable (« +0,4 nat de surprise par événement »).

# %% [markdown]
# ## 5. L'auto-encodeur : apprendre une représentation compressée
#
# Un auto-encodeur apprend à reconstruire son entrée après l'avoir fait passer par
# un **goulot d'étranglement**. Il en résulte deux usages :
#
# - la couche centrale est une **représentation compacte** apprise (comme une ACP,
#   mais non linéaire) ;
# - l'**erreur de reconstruction** est un score d'anomalie, si l'on n'a entraîné
#   que sur du normal.

# %%
def vectoriser_hote_jour(ev: pd.DataFrame) -> pd.DataFrame:
    ev = ev.copy()
    ev["heure"] = ev["horodatage"].dt.hour
    mix = pd.crosstab([ev["hostname"], ev["jour"]], ev["type_evenement"],
                      normalize="index")
    autres = ev.groupby(["hostname", "jour"]).agg(
        volume=("event_id", "size"),
        part_nuit=("heure", lambda s: (s < 7).mean()),
        processus_distincts=("processus", lambda s: s[s != ""].nunique()),
    )
    autres["volume"] = np.log1p(autres["volume"])
    return mix.join(autres).fillna(0)


HJ = vectoriser_hote_jour(evenements)
hotes_hj = HJ.index.get_level_values("hostname")
jours_hj = HJ.index.get_level_values("jour")
info = verite.set_index("hostname")

masque_normal = np.array([h in sains for h in hotes_hj]) & (jours_hj < JOUR_DEBUT_SURVEILLANCE)
echelle = MinMaxScaler().fit(HJ[masque_normal])
Z = echelle.transform(HJ)

auto = MLPRegressor(hidden_layer_sizes=(10, 3, 10), activation="relu",
                    max_iter=600, early_stopping=True, random_state=ALEA)
auto.fit(Z[masque_normal], Z[masque_normal])
print(f"Auto-encodeur entraîné sur {masque_normal.sum():,} couples (hôte, jour) sains.")
print(f"Compression : {Z.shape[1]} dimensions → 3 → {Z.shape[1]}")

# %% [markdown]
# ### 5.1 La représentation apprise
#
# Extrayons la couche centrale et comparons-la à une ACP à 3 composantes.

# %%
def couche_centrale(modele, Z):
    """Propagation avant jusqu'au goulot d'étranglement (2ᵉ couche cachée)."""
    a = Z
    for W, b in list(zip(modele.coefs_, modele.intercepts_))[:2]:
        a = np.maximum(a @ W + b, 0)  # ReLU
    return a


code = couche_centrale(auto, Z)
acp3 = PCA(n_components=3, random_state=ALEA).fit_transform(Z)

profil_hj = np.array([info.loc[h, "profil_usage"] for h in hotes_hj])
fig, axes = plt.subplots(1, 2, figsize=(12.5, 5))
for ax, coords, titre in [(axes[0], code, "Auto-encodeur (goulot à 3 neurones)"),
                          (axes[1], acp3, "ACP (3 composantes)")]:
    for profil in np.unique(profil_hj):
        m = profil_hj == profil
        ax.scatter(coords[m, 0], coords[m, 1], s=7, alpha=.35, label=profil)
    ax.set(title=titre, xlabel="dimension 1", ylabel="dimension 2")
    ax.grid(alpha=.3)
axes[1].legend(fontsize=7, markerscale=2)
plt.tight_layout()

# %% [markdown]
# ### 5.2 L'erreur de reconstruction comme détecteur
#
# ### Exercice 5.1
#
# Calculez l'erreur de reconstruction de chaque couple (hôte, jour), évaluez-la
# comme détecteur des jours **postérieurs à une compromission**, puis testez
# l'effet d'un **lissage** sur une fenêtre glissante de 3 jours. Commentez.

# %% tags=["todo"]
# TODO : erreur = ((Z - auto.predict(Z)) ** 2).mean(axis=1), AUC / AUC-PR,
#        puis moyenne glissante par hôte.

# %% tags=["solution"]
resultat = pd.DataFrame({
    "hostname": hotes_hj, "jour": jours_hj,
    "erreur": ((Z - auto.predict(Z)) ** 2).mean(axis=1),
}).sort_values(["hostname", "jour"])
resultat["compromis"] = [bool(info.loc[h, "compromis"]) for h in resultat["hostname"]]
resultat["jour_compromission"] = [int(info.loc[h, "jour_compromission"])
                                  for h in resultat["hostname"]]
resultat["cible"] = (resultat["compromis"] &
                     (resultat["jour"] >= resultat["jour_compromission"]))
resultat["erreur_lissee"] = resultat.groupby("hostname")["erreur"].transform(
    lambda s: s.rolling(3, min_periods=1).mean()
)

print(f"{int(resultat['cible'].sum())} couples (hôte, jour) postérieurs à une "
      f"compromission sur {len(resultat):,} — taux de base {resultat['cible'].mean():.2%}\n")
for colonne, libelle in [("erreur", "erreur brute (1 jour)"),
                         ("erreur_lissee", "erreur lissée sur 3 jours")]:
    print(f"{libelle:28s} AUC-ROC={roc_auc_score(resultat['cible'], resultat[colonne]):.3f}  "
          f"AUC-PR={average_precision_score(resultat['cible'], resultat[colonne]):.3f}")

# %% [markdown]
# #### Le résultat qu'il faut savoir critiquer
#
# L'AUC-ROC autour de 0,7-0,8 semble correcte ; l'AUC-PR, elle, reste très basse.
# Avec un taux de base de ~1 %, ce détecteur produirait un volume de faux positifs
# inacceptable. Trois causes, toutes instructives :
#
# 1. **L'agrégat journalier est bruité.** Une seule journée de comportement est un
#    échantillon trop petit ; le lissage sur 3 jours améliore l'AUC, au prix d'un
#    délai de détection.
# 2. **L'auto-encodeur n'a pas de référence par hôte.** Comme le score absolu de
#    la section 4, il compare tout le monde à la moyenne du parc.
# 3. **Le signal est faible par construction** : l'activité de l'attaquant ne
#    représente qu'un quart à la moitié des événements des jours concernés.
#
# > **Conclusion honnête** : sur ce jeu de données, le modèle de séquence avec
# > référence par hôte (§ 4) est nettement supérieur à l'auto-encodeur sur
# > agrégats. Ce n'est pas une propriété universelle des auto-encodeurs — c'est le
# > résultat de **ce** cadrage. La leçon transférable : sur des données
# > séquentielles, un modèle qui exploite l'ordre bat un modèle qui l'ignore.

# %%
fig, ax = plt.subplots(figsize=(10.5, 4.4))
normal = ~resultat["cible"]
ax.scatter(resultat.loc[normal, "jour"], resultat.loc[normal, "erreur_lissee"],
           s=5, alpha=.15, color="grey", label="normal")
ax.scatter(resultat.loc[resultat["cible"], "jour"],
           resultat.loc[resultat["cible"], "erreur_lissee"],
           s=38, color="crimson", label="après compromission", zorder=3)
seuil = np.quantile(resultat.loc[masque_normal, "erreur_lissee"], 0.99)
ax.axhline(seuil, ls="--", color="k", lw=1, label="seuil (99ᵉ centile du normal)")
ax.set(xlabel="jour", ylabel="erreur de reconstruction lissée",
       title="Auto-encodeur — erreur de reconstruction par couple (hôte, jour)")
ax.legend(fontsize=8)
ax.grid(alpha=.3)
plt.tight_layout()

remontes = resultat["erreur_lissee"] > seuil
print(f"Au 99ᵉ centile : {int(remontes.sum())} couples (hôte, jour) remontés, "
      f"dont {int((remontes & resultat['cible']).sum())} réellement compromis "
      f"→ précision {(remontes & resultat['cible']).sum() / max(remontes.sum(), 1):.1%}")

# %% [markdown]
# ## 5. Surapprentissage : la courbe qu'il faut toujours regarder

# %%
reseau_surdimensionne = MLPClassifier(hidden_layer_sizes=(256, 128, 64),
                                      max_iter=250, alpha=1e-6,
                                      early_stopping=False, random_state=ALEA)
Ztr, Zva, wtr, wva = train_test_split(Etr, ytr_seq, test_size=.25,
                                      random_state=ALEA, stratify=None)
reseau_surdimensionne.fit(Ztr, wtr)

fig, ax = plt.subplots(figsize=(8.5, 4))
ax.plot(reseau_surdimensionne.loss_curve_, label="perte sur l'apprentissage")
ax.set(xlabel="itération", ylabel="perte",
       title=f"Apprentissage — score train {reseau_surdimensionne.score(Ztr, wtr):.3f} "
             f"vs validation {reseau_surdimensionne.score(Zva, wva):.3f}")
ax.legend()
ax.grid(alpha=.3)
plt.tight_layout()

ecart = reseau_surdimensionne.score(Ztr, wtr) - reseau_surdimensionne.score(Zva, wva)
print(f"Écart train/validation : {ecart:+.3f}")
print("""
Comment lire ce chiffre :
  proche de 0      le réseau généralise ; la capacité n'est pas le facteur limitant
  franchement > 0  surapprentissage : le réseau mémorise l'historique au lieu
                   d'apprendre la régularité du système

Ici l'écart reste modéré parce que le problème est simple (5 positions × 8 types)
et le jeu d'apprentissage large. Refaites l'expérience en réduisant le jeu
d'apprentissage à 2 000 exemples : l'écart se creuse immédiatement, alors que la
perte sur l'apprentissage, elle, continue de baisser. C'est précisément pour cela
qu'on ne juge JAMAIS un modèle sur sa courbe de perte d'apprentissage seule.""")

# %% [markdown]
# ## 6. Quand ne PAS utiliser de réseau de neurones
#
# | Situation | Verdict | Pourquoi |
# |---|---|---|
# | Données tabulaires, < 100 k lignes | **non** | *gradient boosting* meilleur, plus rapide, interprétable |
# | Décision devant être justifiée à un analyste | **non** | opacité difficilement compatible avec la traçabilité |
# | Peu d'exemples positifs | **non** | l'apprentissage profond est vorace en données |
# | Séquences, texte, graphes, volumétrie massive | **oui** | la structure n'est pas encodable à la main |
# | Représentation à réutiliser (plongements) | **oui** | apport propre du réseau |
#
# > **Risque spécifique à la sécurité.** Un modèle profond est sensible aux
# > **exemples adverses** : un attaquant qui connaît le détecteur peut construire
# > une activité qui le contourne. Cette surface d'attaque doit figurer dans
# > l'analyse de risque du projet — un détecteur est lui-même un actif à protéger.

# %% [markdown]
# ## 7. Synthèse et travail personnel
#
# **À retenir**
#
# 1. Un neurone est une régression logistique ; c'est l'**empilement** qui apporte
#    la non-linéarité, et rien d'autre.
# 2. Sur du tabulaire de SOC, le réseau de neurones ne bat pas le *gradient
#    boosting*. Le reconnaître est un signe de maturité professionnelle.
# 3. Son apport réel : les **structures** (séquences, texte, graphes) et les
#    représentations apprises.
# 4. La prédiction du prochain événement transforme un modèle **prédictif** en
#    détecteur **non supervisé** : on apprend le normal, on mesure la surprise.
# 5. L'auto-encodeur suit la même logique par l'erreur de reconstruction — avec
#    la même exigence : n'entraîner que sur du normal vérifié.
#
# **Travail personnel (≥ 4 h)**
#
# - Entraînez **un modèle de séquence par profil d'usage** (ceux de l'atelier 05)
#   et mesurez le gain sur le taux de faux positifs. C'est le chaînage
#   non supervisé → séquentiel évoqué en 3.2.
# - Remplacez le sac de jetons par un encodage positionnel (jeton à la position
#   1, 2, …, K). Que gagne-t-on ? Que coûte-t-on en nombre de paramètres ?
# - Lecture : Du et al., *DeepLog: Anomaly Detection and Diagnosis from System Logs
#   through Deep Learning*, ACM CCS 2017. Repérez ce que notre version simplifiée
#   perd par rapport au LSTM d'origine.
#
# **Suite :** atelier 07 — process mining, ou comment analyser non plus les
# machines mais **le travail du SOC lui-même**.
