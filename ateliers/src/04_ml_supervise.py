# ---
# Atelier 04 — Temps 3 : Machine Learning (1/3)
# ---

# %% [markdown]
# # Atelier 04 — Apprentissage supervisé : le triage automatique des alertes
#
# > **Temps 3 — Machine Learning** (2 UT sur 4) — 2 × 2 h de TP
#
# ## Objectifs
#
# 1. Construire un moteur d'apprentissage **supervisé de bout en bout** :
#    données → prétraitement → caractéristiques → modèle → évaluation → intégration.
# 2. Détecter et éliminer une **fuite de données** (*data leakage*).
# 3. Choisir une **partition temporelle** plutôt qu'aléatoire, et comprendre pourquoi.
# 4. Évaluer un classifieur sur des **classes déséquilibrées** avec les bonnes
#    métriques, et convertir la performance statistique en **gain opérationnel**.
# 5. Fixer un seuil de décision à partir d'une **contrainte de capacité**, pas d'un 0,5 par défaut.
#
# ## Le problème
#
# 14 000 alertes sur six mois, 3 analystes, ~7 % de vrais positifs. On ne cherche
# pas à fermer automatiquement des alertes : on cherche à **ordonner la file** pour
# que ce qui compte soit traité en premier.

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, precision_recall_curve,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import TimeSeriesSplit, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
ALEA = 42

# %% [markdown]
# ## 1. Charger et nettoyer

# %%
alertes = pd.read_csv(DATA / "alertes_siem.csv", parse_dates=["horodatage"])
print(f"{len(alertes):,} lignes brutes")

alertes = alertes.drop_duplicates(subset="alert_id").sort_values("horodatage")
alertes = alertes.reset_index(drop=True)
y = (alertes["verdict"] == "vrai_positif").astype(int)

print(f"{len(alertes):,} lignes après déduplication")
print(f"Taux de vrais positifs : {y.mean():.2%}  →  1 alerte utile sur {1 / y.mean():.0f}")

# %% [markdown]
# ## 2. La fuite de données : le piège qui donne 99 % de précision
#
# Regardons la corrélation entre chaque variable numérique et la cible.

# %%
numeriques = alertes.select_dtypes(include=[np.number]).columns.tolist()
correlations = (
    alertes[numeriques].corrwith(y).abs().sort_values(ascending=False)
)
correlations.head(8).round(3)

# %% [markdown]
# `temps_traitement_analyste_min` domine tout. **Réfléchissez avant de continuer :
# quand cette valeur est-elle connue ?**
#
# Réponse : *après* que l'analyste a traité l'alerte. Au moment où le modèle doit
# prédire — à l'arrivée de l'alerte dans la file — elle n'existe pas. C'est une
# **fuite temporelle**. Un modèle qui l'utilise obtient un score spectaculaire en
# validation et une performance nulle en production.
#
# Démontrons-le.

# %%
def evaluer_rapide(colonnes, titre):
    X = alertes[colonnes].copy()
    for c in X.select_dtypes(include=["object", "bool"]).columns:
        X[c] = pd.factorize(X[c])[0]
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=.3, random_state=ALEA, stratify=y
    )
    modele = HistGradientBoostingClassifier(random_state=ALEA).fit(Xtr, ytr)
    p = modele.predict_proba(Xte)[:, 1]
    print(f"{titre:38s} AUC-ROC = {roc_auc_score(yte, p):.3f}   "
          f"AUC-PR = {average_precision_score(yte, p):.3f}")


base_colonnes = ["severite_siem", "reputation_source", "criticite_actif",
                 "evenements_correles", "octets_transferes", "alertes_hote_24h"]
evaluer_rapide(base_colonnes, "Sans la variable fuitée")
evaluer_rapide(base_colonnes + ["temps_traitement_analyste_min"], "AVEC la variable fuitée")

# %% [markdown]
# > **Règle à graver.** Pour chaque variable, posez la question :
# > *« cette information est-elle disponible à l'instant où le modèle doit décider ? »*
# > Si la réponse est non ou « ça dépend », la variable est écartée.
# >
# > Dans un SOC, les fuites classiques sont : le temps de traitement, le statut du
# > ticket, l'action de remédiation, le nom de l'analyste assigné, et toute
# > agrégation calculée sur une fenêtre qui déborde dans le futur.

# %% [markdown]
# ### Exercice 2.1
#
# Parcourez la liste complète des colonnes et classez-les en trois catégories :
# **utilisable**, **fuite**, **identifiant à exclure**. Justifiez les cas douteux.

# %%
print(alertes.columns.tolist())

# %% [markdown] tags=["solution"]
# #### Corrigé
#
# | Catégorie | Colonnes | Justification |
# |---|---|---|
# | **Fuite** | `temps_traitement_analyste_min`, `verdict` | connues après traitement |
# | **Identifiant** | `alert_id`, `source_ip`, `destination_ip`, `hostname`, `username` | haute cardinalité : le modèle mémoriserait des entités précises au lieu d'apprendre un comportement (et ne généraliserait pas à un nouvel hôte) |
# | **Utilisable** | tout le reste | disponible dès la réception de l'alerte |
#
# Cas douteux à discuter : `alertes_hote_24h` et `alertes_compte_24h` sont des
# compteurs sur fenêtre glissante. Ils sont légitimes **si** la fenêtre ne regarde
# que le passé. Dans notre générateur, le comptage porte sur la journée entière —
# donc partiellement sur le futur. En production, il faudrait les recalculer en
# fenêtre strictement rétrospective. On les conserve ici en signalant la réserve.

# %% [markdown]
# ## 3. Partition temporelle
#
# Un partage aléatoire mettrait dans l'ensemble d'apprentissage des alertes
# postérieures à celles de test. Or le modèle sera déployé pour prédire le
# **futur**. On coupe donc dans le temps.

# %%
COUPURE = alertes["horodatage"].quantile(0.7)
train = alertes["horodatage"] < COUPURE
test = ~train

print(f"Coupure : {COUPURE:%Y-%m-%d}")
print(f"Apprentissage : {train.sum():,} alertes  "
      f"({alertes.loc[train, 'horodatage'].min():%d/%m} → "
      f"{alertes.loc[train, 'horodatage'].max():%d/%m})  "
      f"taux VP = {y[train].mean():.2%}")
print(f"Test          : {test.sum():,} alertes  "
      f"({alertes.loc[test, 'horodatage'].min():%d/%m} → "
      f"{alertes.loc[test, 'horodatage'].max():%d/%m})  "
      f"taux VP = {y[test].mean():.2%}")

# %% [markdown]
# > Le taux de vrais positifs diffère entre les deux périodes : la distribution a
# > bougé. C'est normal — et c'est le sujet de l'atelier 10.

# %% [markdown]
# ## 4. Ingénierie des caractéristiques
#
# Le modèle ne verra que ce qu'on lui donne. Chaque caractéristique encode une
# hypothèse d'analyste.

# %%
def construire_caracteristiques(df: pd.DataFrame) -> pd.DataFrame:
    X = pd.DataFrame(index=df.index)

    # --- Ce que dit la règle ---------------------------------------------
    X["severite_siem"] = df["severite_siem"]
    X["famille_regle"] = df["famille_regle"]
    X["tactique_attack"] = df["tactique_attack"]

    # --- Ce que dit la source --------------------------------------------
    X["reputation_source"] = df["reputation_source"]
    X["source_externe"] = df["source_externe"].astype(int)
    X["port_destination"] = df["port_destination"]
    X["port_courant"] = df["port_destination"].isin([80, 443, 53]).astype(int)

    # --- Ce que dit la cible ----------------------------------------------
    X["criticite_actif"] = df["criticite_actif"]
    X["zone"] = df["zone"]
    X["agent_edr"] = df["agent_edr"].astype(int)
    X["compte_admin"] = df["compte_admin"].astype(int)
    X["mfa_actif"] = df["mfa_actif"].astype(int)

    # --- Ce que dit le contexte -------------------------------------------
    X["evenements_correles"] = df["evenements_correles"]
    X["log_octets"] = np.log1p(df["octets_transferes"])
    X["duree_fenetre_s"] = df["duree_fenetre_s"]
    X["hors_heures_ouvrables"] = df["hors_heures_ouvrables"].astype(int)
    X["alertes_hote_24h"] = df["alertes_hote_24h"]
    X["alertes_compte_24h"] = df["alertes_compte_24h"]
    X["heure"] = df["horodatage"].dt.hour
    X["jour_semaine"] = df["horodatage"].dt.weekday
    return X


X = construire_caracteristiques(alertes)
CAT = X.select_dtypes(include="object").columns.tolist()
NUM = [c for c in X.columns if c not in CAT]
print(f"{X.shape[1]} caractéristiques : {len(NUM)} numériques, {len(CAT)} catégorielles")

# %% [markdown]
# ### Exercice 4.1
#
# Ajoutez **deux** caractéristiques de votre invention et justifiez-les en une
# phrase d'analyste. Suggestions : interaction criticité × sévérité, écart entre
# le volume d'alertes de l'hôte et sa médiane historique, appartenance du port à
# une liste de ports d'administration…

# %% tags=["todo"]
# TODO : deux colonnes supplémentaires dans construire_caracteristiques,
#        ou ajoutées ici directement à X.

# %% tags=["solution"]
PORTS_ADMIN = [22, 135, 445, 3389, 5985]

# Hypothèse d'analyste n° 1 : une alerte sévère sur un actif critique n'est pas
# la somme des deux risques mais leur produit — c'est là que se concentre l'enjeu.
X["risque_combine"] = X["severite_siem"] * X["criticite_actif"]

# Hypothèse d'analyste n° 2 : un accès à un port d'administration depuis
# l'extérieur est un motif rare et fortement signant.
X["admin_depuis_exterieur"] = (
    X["port_destination"].isin(PORTS_ADMIN) & (X["source_externe"] == 1)
).astype(int)

NUM += ["risque_combine", "admin_depuis_exterieur"]
print(f"{X.shape[1]} caractéristiques")
print(f"Fréquence de 'admin_depuis_exterieur' : {X['admin_depuis_exterieur'].mean():.2%}")

# %% [markdown]
# ## 5. Le pipeline
#
# Tout le prétraitement doit vivre **dans** le pipeline : sinon les statistiques
# d'imputation et de normalisation calculées sur l'ensemble complet fuiteraient
# vers le test.

# %%
pretraitement = ColumnTransformer([
    ("num", Pipeline([("imputation", SimpleImputer(strategy="median")),
                      ("normalisation", StandardScaler())]), NUM),
    ("cat", OneHotEncoder(handle_unknown="ignore", min_frequency=30), CAT),
])

modeles = {
    "Référence (classe majoritaire)": DummyClassifier(strategy="prior"),
    "Régression logistique": LogisticRegression(max_iter=2000,
                                                class_weight="balanced",
                                                random_state=ALEA),
    "Forêt aléatoire": RandomForestClassifier(n_estimators=300, min_samples_leaf=5,
                                              class_weight="balanced_subsample",
                                              n_jobs=-1, random_state=ALEA),
    "Gradient boosting": HistGradientBoostingClassifier(max_iter=300,
                                                        learning_rate=.08,
                                                        random_state=ALEA),
}

Xtr, Xte = X[train], X[test]
ytr, yte = y[train], y[test]

resultats = {}
for nom, estimateur in modeles.items():
    pipe = Pipeline([("pretraitement", pretraitement), ("modele", estimateur)])
    pipe.fit(Xtr, ytr)
    scores = pipe.predict_proba(Xte)[:, 1]
    resultats[nom] = {"pipeline": pipe, "scores": scores,
                      "auc_roc": roc_auc_score(yte, scores),
                      "auc_pr": average_precision_score(yte, scores)}
    print(f"{nom:32s} AUC-ROC={resultats[nom]['auc_roc']:.3f}  "
          f"AUC-PR={resultats[nom]['auc_pr']:.3f}")

print(f"\nTaux de base (AUC-PR d'un modèle aléatoire) : {yte.mean():.3f}")

# %% [markdown]
# ### Pourquoi l'AUC-PR et pas seulement l'AUC-ROC
#
# Avec 7 % de positifs, l'AUC-ROC est optimiste : elle est dominée par la facilité
# à écarter les négatifs, dont il y a une masse. L'AUC-PR se compare au taux de
# base et mesure ce qui nous intéresse : **parmi ce que je remonte, combien est utile ?**

# %%
meilleur = max(resultats, key=lambda k: resultats[k]["auc_pr"])
scores = resultats[meilleur]["scores"]
print(f"Modèle retenu : {meilleur}")

fig, axes = plt.subplots(1, 2, figsize=(12, 4.4))
for nom, r in resultats.items():
    if "Référence" in nom:
        continue
    fpr, tpr, _ = roc_curve(yte, r["scores"])
    axes[0].plot(fpr, tpr, label=f"{nom} ({r['auc_roc']:.3f})")
    prec, rapp, _ = precision_recall_curve(yte, r["scores"])
    axes[1].plot(rapp, prec, label=f"{nom} ({r['auc_pr']:.3f})")

axes[0].plot([0, 1], [0, 1], "k--", lw=.8)
axes[0].set(xlabel="Taux de faux positifs", ylabel="Taux de vrais positifs",
            title="Courbe ROC")
axes[1].axhline(yte.mean(), color="k", ls="--", lw=.8, label=f"base ({yte.mean():.3f})")
axes[1].set(xlabel="Rappel", ylabel="Précision", title="Courbe précision-rappel")
for a in axes:
    a.legend(fontsize=8)
    a.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# ## 6. Du score au seuil : la contrainte de capacité
#
# Le seuil de 0,5 par défaut n'a **aucun** sens ici. Le vrai critère est :
# *combien d'alertes mes analystes peuvent-ils traiter par jour ?*

# %%
JOURS_TEST = (alertes.loc[test, "horodatage"].max()
              - alertes.loc[test, "horodatage"].min()).days
# 3 analystes qui investiguent chacun ~5 alertes par jour de façon approfondie.
CAPACITE_JOUR = 15
budget = CAPACITE_JOUR * JOURS_TEST

ordre = np.argsort(-scores)
k = min(budget, len(scores))
seuil = scores[ordre[k - 1]]

remontees = scores >= seuil
vp = int((remontees & (yte == 1)).sum())
total_vp = int(yte.sum())

print(f"Période de test : {JOURS_TEST} jours · capacité {CAPACITE_JOUR} alertes/jour "
      f"→ budget {budget:,} alertes")
print(f"Seuil de décision : {seuil:.4f}\n")
print(f"Avec le modèle      : {vp}/{total_vp} vrais positifs trouvés "
      f"({vp / total_vp:.0%} de rappel), précision {vp / remontees.sum():.1%}")

# Comparaison : la pratique actuelle, trier par sévérité SIEM puis par date.
tri_actuel = alertes.loc[test].assign(cible=yte.to_numpy()).sort_values(
    ["severite_siem", "horodatage"], ascending=[False, True]
)
vp_actuel = int(tri_actuel.head(budget)["cible"].sum())
print(f"Tri par sévérité SIEM : {vp_actuel}/{total_vp} vrais positifs "
      f"({vp_actuel / total_vp:.0%} de rappel), précision {vp_actuel / budget:.1%}")
print(f"\nGain : ×{vp / max(vp_actuel, 1):.1f} sur le nombre d'incidents réels détectés "
      f"à charge de travail constante.")

# %% [markdown]
# ### Exercice 6.1 — la courbe de décision opérationnelle
#
# Tracez, pour une capacité variant de 5 à 100 alertes/jour, le rappel obtenu
# par le modèle et par le tri actuel. C'est **le** graphique à présenter à un
# responsable de SOC : il traduit la performance statistique en décision de
# dimensionnement d'équipe.

# %% tags=["todo"]
# TODO : boucle sur les capacités, calcul du rappel dans les K premiers.

# %% tags=["solution"]
capacites = np.arange(5, 101, 5)
rappel_modele, rappel_actuel = [], []
yte_np = yte.to_numpy()
cible_triee = tri_actuel["cible"].to_numpy()

for cap in capacites:
    kk = min(cap * JOURS_TEST, len(scores))
    rappel_modele.append(yte_np[ordre[:kk]].sum() / total_vp)
    rappel_actuel.append(cible_triee[:kk].sum() / total_vp)

fig, ax = plt.subplots(figsize=(9, 4.6))
ax.plot(capacites, np.array(rappel_modele) * 100, marker="o",
        label="File ordonnée par le modèle")
ax.plot(capacites, np.array(rappel_actuel) * 100, marker="s",
        label="Tri actuel (sévérité SIEM)")
ax.axvline(CAPACITE_JOUR, color="grey", ls=":", label=f"capacité actuelle ({CAPACITE_JOUR}/j)")
ax.set(xlabel="Capacité de traitement (alertes par jour)",
       ylabel="Vrais positifs détectés (%)",
       title="Ce que le modèle change, à effectif constant")
ax.legend()
ax.grid(alpha=.3)
plt.tight_layout()

idx = list(capacites).index(CAPACITE_JOUR)
print(f"À {CAPACITE_JOUR} alertes/jour : {rappel_modele[idx]:.0%} contre "
      f"{rappel_actuel[idx]:.0%} aujourd'hui.")
print(f"Pour atteindre {rappel_modele[idx]:.0%} avec le tri actuel, il faudrait "
      f"environ {capacites[np.argmax(np.array(rappel_actuel) >= rappel_modele[idx])]} "
      f"alertes/jour, soit "
      f"{capacites[np.argmax(np.array(rappel_actuel) >= rappel_modele[idx])] / CAPACITE_JOUR:.1f}× l'effectif.")

# %% [markdown]
# ## 7. Matrice de confusion et lecture métier

# %%
mc = confusion_matrix(yte, remontees)
(tn, fp), (fn, vp_) = mc
print("                  non remontée   remontée")
print(f"faux positif réel  {tn:>12,d} {fp:>10,d}")
print(f"vrai positif réel  {fn:>12,d} {vp_:>10,d}")
print()
print(classification_report(yte, remontees,
                            target_names=["faux positif", "vrai positif"],
                            digits=3))

print(f"⚠ {fn:,} incidents réels ne sont PAS remontés dans le budget.")
print("  C'est le coût assumé du dimensionnement, pas un défaut du modèle.")
print("  En production, ces alertes ne disparaissent pas : elles restent dans la")
print("  file, en attente, et alimentent la revue hebdomadaire des non-traitées.")

# %% [markdown]
# ## 8. Interpréter : pourquoi le modèle décide-t-il ainsi ?
#
# Un modèle de sécurité non interprétable est un modèle que personne n'appliquera.
# L'analyste doit pouvoir contester une priorisation.

# %%
pipe = resultats[meilleur]["pipeline"]
imp = permutation_importance(pipe, Xte, yte, n_repeats=5, random_state=ALEA,
                             scoring="average_precision", n_jobs=-1)
importance = (
    pd.Series(imp.importances_mean, index=X.columns)
    .sort_values(ascending=False).head(14)
)

fig, ax = plt.subplots(figsize=(8, 5))
importance.iloc[::-1].plot.barh(ax=ax, color="steelblue",
                                xerr=imp.importances_std[
                                    [X.columns.get_loc(c) for c in importance.index]][::-1])
ax.set_xlabel("Perte d'AUC-PR quand la variable est permutée")
ax.set_title("Importance par permutation (mesurée sur l'ensemble de test)")
ax.grid(axis="x", alpha=.3)
plt.tight_layout()

# %% [markdown]
# > **Pourquoi la permutation et non l'importance native de l'arbre ?**
# > L'importance native est calculée sur l'ensemble d'apprentissage et favorise
# > mécaniquement les variables à forte cardinalité. La permutation se mesure sur
# > les données de test, avec la métrique qui nous intéresse, et répond à la
# > bonne question : *que perd-on si cette information disparaît ?*

# %% [markdown]
# ### Exercice 8.1 — expliquer une décision individuelle
#
# Prenez l'alerte la mieux classée par le modèle et rédigez, en trois phrases,
# l'explication que vous donneriez à l'analyste qui la reçoit.

# %% tags=["todo"]
# TODO : récupérer la ligne d'alertes correspondant à ordre[0] et la commenter.

# %% tags=["solution"]
idx_top = alertes.loc[test].index[ordre[0]]
alerte = alertes.loc[idx_top]
print(f"Score du modèle : {scores[ordre[0]]:.3f}   (verdict réel : {alerte['verdict']})\n")
for champ in ["regle_nom", "famille_regle", "technique_attack", "severite_siem",
              "reputation_source", "hostname", "zone", "criticite_actif",
              "username", "compte_admin", "hors_heures_ouvrables",
              "evenements_correles", "octets_transferes"]:
    print(f"  {champ:24s} {alerte[champ]}")

print("""
Explication type pour l'analyste :
« Cette alerte est classée en tête parce qu'elle combine trois facteurs qui,
  ensemble, sont rares : une règle de la famille la plus signante, une source
  externe à mauvaise réputation, et une cible à criticité maximale. Prise
  isolément, aucune de ces conditions ne déclencherait une priorité haute dans
  les règles actuelles du SIEM ; c'est leur conjonction qui est significative.
  Vérifiez en priorité l'activité du compte sur les 24 h précédentes. »
""")

# %% [markdown]
# ## 9. Validation croisée temporelle
#
# Une seule coupure peut être chanceuse. `TimeSeriesSplit` répète l'exercice sur
# plusieurs découpes glissantes, toujours en respectant l'ordre du temps.

# %%
pipe_final = Pipeline([
    ("pretraitement", pretraitement),
    ("modele", HistGradientBoostingClassifier(max_iter=300, learning_rate=.08,
                                              random_state=ALEA)),
])
cv = TimeSeriesSplit(n_splits=5)
scores_cv = cross_val_score(pipe_final, X, y, cv=cv, scoring="average_precision", n_jobs=-1)
for i, s in enumerate(scores_cv, 1):
    print(f"  pli {i} : AUC-PR = {s:.3f}")
print(f"\nMoyenne {scores_cv.mean():.3f} ± {scores_cv.std():.3f}")
print(f"Taux de base : {y.mean():.3f}  →  gain ×{scores_cv.mean() / y.mean():.1f}")

# %% [markdown]
# ## 10. Sauvegarder le modèle pour l'atelier 10

# %%
import joblib

SORTIE = RACINE / "artifacts"
SORTIE.mkdir(exist_ok=True)

# On sauvegarde le modèle entraîné sur la SEULE période d'apprentissage.
# En production réelle, on réentraînerait sur l'historique complet juste avant
# la bascule. Ici, garder la coupure temporelle permet à l'atelier 10 de mesurer
# une performance honnête, hors échantillon, sur les derniers mois.
pipe_final.fit(Xtr, ytr)
joblib.dump({"pipeline": pipe_final, "colonnes": X.columns.tolist(),
             "seuil": float(seuil),
             "date_entrainement": str(alertes.loc[train, "horodatage"].max()),
             "n_entrainement": int(train.sum()),
             "capacite_jour": CAPACITE_JOUR,
             "taux_base": float(ytr.mean())},
            SORTIE / "modele_triage.joblib")
print(f"Modèle sauvegardé : {SORTIE / 'modele_triage.joblib'}")
print(f"Entraîné sur les données jusqu'au "
      f"{alertes.loc[train, 'horodatage'].max():%Y-%m-%d} "
      f"({int(train.sum()):,} alertes)")

# %% [markdown]
# ## 11. Synthèse et travail personnel
#
# **À retenir**
#
# 1. La **fuite de données** est l'erreur la plus coûteuse et la plus discrète du
#    ML appliqué à la sécurité. Le test : *cette information existe-t-elle au
#    moment de la décision ?*
# 2. Sur des données horodatées, on partitionne **dans le temps**. Un partage
#    aléatoire surestime systématiquement la performance.
# 3. Avec des classes déséquilibrées, l'exactitude et l'AUC-ROC trompent :
#    on raisonne en **AUC-PR** et en **précision dans les K premiers**.
# 4. Le seuil de décision se déduit d'une **contrainte opérationnelle**, jamais
#    d'une valeur par défaut.
# 5. Le livrable n'est pas un score : c'est une **courbe de décision** qui traduit
#    la performance en effectif, en rappel et en risque assumé.
#
# **Travail personnel (≥ 4 h)**
#
# - Refaites l'atelier en recalculant `alertes_hote_24h` en fenêtre strictement
#   rétrospective. De combien la performance baisse-t-elle ? Commentez.
# - Étudiez l'effet du rééchantillonnage (`class_weight`, sous-échantillonnage,
#   SMOTE) sur l'AUC-PR. Conclusion attendue : sur données déséquilibrées, le
#   rééchantillonnage déplace les scores mais améliore rarement le classement.
# - Rédigez la **spécification de besoin** du service de scoring : entrées,
#   sorties, latence, disponibilité, procédure de repli si le modèle est indisponible.
#
# **Suite :** atelier 05 — et quand il n'y a **aucune** étiquette ?
