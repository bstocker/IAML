# ---
# Atelier 10 — Temps 3 : industrialisation
# ---

# %% [markdown]
# # Atelier 10 — Déployer, surveiller, maintenir : le modèle en production
#
# > **Temps 3 — Machine Learning / MLOps** — 2 h de TP
# >
# > Répond directement aux compétences attendues du marché : *« implémenter des
# > pipelines automatisés de déploiement et de surveillance des modèles (gestion
# > des alertes) »* et *« présenter et déployer un modèle auprès d'utilisateurs
# > finaux »*.
#
# ## Objectifs
#
# 1. Rédiger la **spécification** d'un service de scoring avant de l'écrire.
# 2. Exposer le modèle de l'atelier 04 derrière une **API** utilisable par le SIEM.
# 3. Détecter une **dérive de distribution** (*data drift*) et une **dérive de
#    performance**.
# 4. Concevoir la **boucle de retour** analyste → étiquettes → réentraînement.
# 5. Documenter le modèle (*model card*) et définir la procédure de repli.
#
# ## Le vrai sujet
#
# Un modèle qui n'est pas surveillé se dégrade en silence. En cybersécurité, la
# distribution des données change en permanence : nouvelles règles de détection,
# nouveaux actifs, nouveaux comportements — et adversaires qui s'adaptent.
# **La mise en production est le début du travail, pas la fin.**

# %%
import json
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from sklearn.metrics import average_precision_score, roc_auc_score

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
ARTEFACTS = RACINE / "artifacts"
SERVICE = RACINE / "service"
SERVICE.mkdir(exist_ok=True)

# %% [markdown]
# ## 1. Spécifier avant de coder
#
# La compétence attendue est explicite : *« développer des algorithmes […] en
# sachant rédiger une spécification des besoins »*. Voici la fiche minimale.
#
# ### Spécification — service de priorisation des alertes
#
# | Rubrique | Engagement |
# |---|---|
# | **Fonction** | Attribuer à chaque alerte un score de priorité dans [0, 1] |
# | **Ce que ce n'est pas** | Le service **ne ferme aucune alerte**. Il ordonne une file. |
# | **Entrée** | Un objet alerte JSON, champs disponibles à la réception |
# | **Sortie** | `{score, priorite, version_modele, explication}` |
# | **Latence** | p95 < 100 ms par alerte, < 5 s pour un lot de 1 000 |
# | **Disponibilité** | 99,5 % — en cas d'indisponibilité, **repli sur le tri par sévérité SIEM** |
# | **Volumétrie** | ~80 alertes/jour en régime nominal, pics à 500/jour |
# | **Traçabilité** | Chaque score journalisé avec la version du modèle et les entrées |
# | **Réentraînement** | Trimestriel, ou déclenché par une alerte de dérive |
# | **Retrait** | Si l'AUC-PR mensuelle passe sous 2 × le taux de base |
#
# > **Le point le plus important du tableau est la ligne « Ce que ce n'est pas ».**
# > Un modèle de sécurité doit avoir un périmètre d'autorité écrit. Sans elle,
# > l'usage dérive vers la fermeture automatique et le premier incident manqué
# > détruit la confiance dans l'outil pour des années.

# %% [markdown]
# ## 2. Charger le modèle produit à l'atelier 04

# %%
chemin_modele = ARTEFACTS / "modele_triage.joblib"
assert chemin_modele.exists(), (
    "Exécutez d'abord le corrigé de l'atelier 04 : il produit artifacts/modele_triage.joblib"
)
paquet = joblib.load(chemin_modele)
modele = paquet["pipeline"]
COLONNES = paquet["colonnes"]
SEUIL = paquet["seuil"]

print(f"Modèle entraîné jusqu'au {paquet['date_entrainement'][:10]} "
      f"sur {paquet['n_entrainement']:,} alertes")
print(f"{len(COLONNES)} caractéristiques attendues · seuil de remontée {SEUIL:.3f}")
print(f"Taux de base à l'entraînement : {paquet['taux_base']:.2%}")

# %% [markdown]
# ## 3. La fonction de scoring
#
# Point critique : la **transformation appliquée en production doit être
# exactement celle de l'entraînement**. C'est la première cause d'écart
# entre les performances mesurées et les performances constatées
# (*training/serving skew*). On la centralise donc dans un seul module,
# importé des deux côtés.

# %%
(SERVICE / "caracteristiques.py").write_text('''"""Construction des caracteristiques — module PARTAGE entre l'entrainement et
le service. Toute modification ici doit declencher un reentrainement."""

import numpy as np
import pandas as pd

PORTS_ADMIN = [22, 135, 445, 3389, 5985]


def construire(df: pd.DataFrame) -> pd.DataFrame:
    """Transforme des alertes brutes en matrice de caracteristiques."""
    X = pd.DataFrame(index=df.index)
    X["severite_siem"] = df["severite_siem"]
    X["famille_regle"] = df["famille_regle"]
    X["tactique_attack"] = df["tactique_attack"]
    X["reputation_source"] = df["reputation_source"]
    X["source_externe"] = df["source_externe"].astype(int)
    X["port_destination"] = df["port_destination"]
    X["port_courant"] = df["port_destination"].isin([80, 443, 53]).astype(int)
    X["criticite_actif"] = df["criticite_actif"]
    X["zone"] = df["zone"]
    X["agent_edr"] = df["agent_edr"].astype(int)
    X["compte_admin"] = df["compte_admin"].astype(int)
    X["mfa_actif"] = df["mfa_actif"].astype(int)
    X["evenements_correles"] = df["evenements_correles"]
    X["log_octets"] = np.log1p(df["octets_transferes"])
    X["duree_fenetre_s"] = df["duree_fenetre_s"]
    X["hors_heures_ouvrables"] = df["hors_heures_ouvrables"].astype(int)
    X["alertes_hote_24h"] = df["alertes_hote_24h"]
    X["alertes_compte_24h"] = df["alertes_compte_24h"]
    X["heure"] = pd.to_datetime(df["horodatage"]).dt.hour
    X["jour_semaine"] = pd.to_datetime(df["horodatage"]).dt.weekday
    X["risque_combine"] = X["severite_siem"] * X["criticite_actif"]
    X["admin_depuis_exterieur"] = (
        X["port_destination"].isin(PORTS_ADMIN) & (X["source_externe"] == 1)
    ).astype(int)
    return X
''', encoding="utf-8")

import sys

sys.path.insert(0, str(RACINE))
from service.caracteristiques import construire  # noqa: E402

alertes = (pd.read_csv(DATA / "alertes_siem.csv", parse_dates=["horodatage"])
           .drop_duplicates(subset="alert_id").sort_values("horodatage")
           .reset_index(drop=True))
X = construire(alertes)[COLONNES]
print(f"Caractéristiques reconstruites : {X.shape}")
print("Colonnes identiques à l'entraînement :", list(X.columns) == COLONNES)

# %% [markdown]
# ## 4. Exposer le modèle : une API

# %%
(SERVICE / "api.py").write_text('''"""Service de priorisation des alertes SIEM.

Lancement en Codespace :
    uvicorn service.api:app --host 0.0.0.0 --port 8000 --reload

Le port 8000 est redirige automatiquement (voir .devcontainer/devcontainer.json).
Documentation interactive : /docs
"""

from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from service.caracteristiques import construire

RACINE = Path(__file__).resolve().parent.parent
PAQUET = joblib.load(RACINE / "artifacts" / "modele_triage.joblib")
MODELE, COLONNES, SEUIL = PAQUET["pipeline"], PAQUET["colonnes"], PAQUET["seuil"]
VERSION = PAQUET["date_entrainement"][:10]

app = FastAPI(title="Priorisation des alertes SIEM", version=VERSION)


class Alerte(BaseModel):
    alert_id: str
    horodatage: str
    severite_siem: int = Field(ge=1, le=4)
    famille_regle: str
    tactique_attack: str
    reputation_source: float | None = None
    source_externe: bool
    port_destination: int
    criticite_actif: int = Field(ge=1, le=4)
    zone: str
    agent_edr: bool
    compte_admin: bool
    mfa_actif: bool
    evenements_correles: int
    octets_transferes: int
    duree_fenetre_s: float
    hors_heures_ouvrables: bool
    alertes_hote_24h: int
    alertes_compte_24h: int


class Score(BaseModel):
    alert_id: str
    score: float
    priorite: str
    remonter: bool
    version_modele: str


def _niveau(score: float) -> str:
    if score >= 0.75:
        return "critique"
    if score >= SEUIL:
        return "elevee"
    if score >= SEUIL / 2:
        return "moyenne"
    return "faible"


@app.get("/sante")
def sante():
    """Sonde de disponibilite pour l'orchestrateur."""
    return {"statut": "ok", "version_modele": VERSION, "seuil": SEUIL}


@app.post("/scorer", response_model=list[Score])
def scorer(alertes: list[Alerte]):
    """Score un lot d'alertes. Le service NE FERME AUCUNE alerte."""
    if not alertes:
        raise HTTPException(400, "Lot vide")
    if len(alertes) > 1000:
        raise HTTPException(413, "Lot limite a 1000 alertes")
    brut = pd.DataFrame([a.model_dump() for a in alertes])
    try:
        X = construire(brut)[COLONNES]
        scores = MODELE.predict_proba(X)[:, 1]
    except KeyError as e:  # schema d'entree incompatible avec le modele
        raise HTTPException(422, f"Champ manquant ou invalide : {e}") from e
    return [
        Score(alert_id=a.alert_id, score=round(float(s), 4), priorite=_niveau(s),
              remonter=bool(s >= SEUIL), version_modele=VERSION)
        for a, s in zip(alertes, scores)
    ]
''', encoding="utf-8")
print(f"Service écrit dans {SERVICE}/api.py")

# %%
from fastapi.testclient import TestClient

from service.api import app  # noqa: E402

client = TestClient(app)
print("GET /sante :", client.get("/sante").json())

CHAMPS = ["alert_id", "horodatage", "severite_siem", "famille_regle",
          "tactique_attack", "reputation_source", "source_externe",
          "port_destination", "criticite_actif", "zone", "agent_edr",
          "compte_admin", "mfa_actif", "evenements_correles",
          "octets_transferes", "duree_fenetre_s", "hors_heures_ouvrables",
          "alertes_hote_24h", "alertes_compte_24h"]

lot = alertes.tail(5)[CHAMPS].copy()
lot["horodatage"] = lot["horodatage"].astype(str)
lot["reputation_source"] = lot["reputation_source"].where(
    lot["reputation_source"].notna(), None
)
reponse = client.post("/scorer", json=lot.to_dict("records"))
print(f"\nPOST /scorer → {reponse.status_code}")
for s in reponse.json():
    print(f"  {s['alert_id']}  score={s['score']:.3f}  {s['priorite']:9s} "
          f"remonter={s['remonter']}")

# %% [markdown]
# ### Exercice 4.1 — tester ce qui casse
#
# Un service exposé au SIEM doit se comporter correctement sur des entrées
# invalides. Vérifiez trois cas :
#
# 1. un lot vide ;
# 2. une sévérité hors bornes (`severite_siem = 9`) ;
# 3. un champ manquant.
#
# Quel code HTTP est renvoyé dans chaque cas ? Est-ce le bon comportement ?

# %% tags=["todo"]
# TODO : trois appels client.post et lecture des codes de retour.

# %% tags=["solution"]
cas = {
    "lot vide": [],
    "sévérité hors bornes": [{**lot.to_dict("records")[0], "severite_siem": 9}],
    "champ manquant": [{k: v for k, v in lot.to_dict("records")[0].items()
                        if k != "criticite_actif"}],
}
for libelle, charge in cas.items():
    r = client.post("/scorer", json=charge)
    print(f"{libelle:24s} → HTTP {r.status_code}")

print("""
Analyse.
  400 (lot vide) et 422 (validation Pydantic) sont les bons codes : l'appelant
  est informé que SA requête est invalide, sans que le service tombe.

  Le point à ne jamais rater : un service de sécurité doit ÉCHOUER DE FAÇON
  VISIBLE. Le pire comportement serait de renvoyer un score par défaut sur une
  entrée invalide — le SIEM continuerait de trier une file avec des scores faux
  sans que personne ne s'en aperçoive.
""")

# %% [markdown]
# ## 5. Détecter la dérive des données
#
# Le modèle a été entraîné sur une période. Le monde a changé depuis. Comparons
# la période de référence et la période récente, **variable par variable**.

# %%
FIN = alertes["horodatage"].max()
recente = alertes[alertes["horodatage"] > FIN - pd.Timedelta(days=30)]
reference = alertes[alertes["horodatage"] <= FIN - pd.Timedelta(days=90)]
print(f"Référence : {len(reference):,} alertes (jusqu'au "
      f"{reference['horodatage'].max():%d/%m})")
print(f"Récente   : {len(recente):,} alertes (depuis le "
      f"{recente['horodatage'].min():%d/%m})")

# %% [markdown]
# ### L'indice de stabilité de population (PSI)
#
# Le PSI est l'indicateur standard du secteur pour la dérive d'une variable.
# Convention d'interprétation usuelle :
#
# | PSI | Lecture |
# |---|---|
# | < 0,10 | pas de dérive significative |
# | 0,10 – 0,25 | dérive modérée, à surveiller |
# | > 0,25 | dérive forte, réentraînement à envisager |

# %%
def psi(attendu: pd.Series, observe: pd.Series, n_classes: int = 10) -> float:
    """Indice de stabilité de population entre deux échantillons."""
    attendu, observe = attendu.dropna(), observe.dropna()
    discrete = (not pd.api.types.is_numeric_dtype(attendu)
                or attendu.nunique() <= n_classes)
    if discrete:                                   # catégorielle ou peu de valeurs
        bornes = sorted(set(attendu.unique()) | set(observe.unique()))
        pa = np.array([(attendu == b).mean() for b in bornes])
        po = np.array([(observe == b).mean() for b in bornes])
    else:                                          # variable continue
        coupes = np.unique(np.quantile(attendu, np.linspace(0, 1, n_classes + 1)))
        pa = np.histogram(attendu, bins=coupes)[0] / len(attendu)
        po = np.histogram(observe, bins=coupes)[0] / len(observe)
    pa, po = np.clip(pa, 1e-4, None), np.clip(po, 1e-4, None)
    return float(np.sum((po - pa) * np.log(po / pa)))


# %% [markdown]
# ### Exercice 5.1
#
# Calculez le PSI de chaque caractéristique numérique entre la référence et la
# période récente, ajoutez un test de Kolmogorov-Smirnov, et classez par PSI
# décroissant. Identifiez la cause de la dérive dominante.

# %% tags=["todo"]
# TODO : boucler sur les colonnes numériques de X, calculer PSI et KS.
rapport_derive = None
rapport_derive

# %% tags=["solution"]
X_ref = construire(reference)[COLONNES]
X_rec = construire(recente)[COLONNES]
numeriques = X_ref.select_dtypes(include=[np.number]).columns

lignes = []
for c in numeriques:
    a, b = X_ref[c].dropna(), X_rec[c].dropna()
    if a.empty or b.empty:
        continue
    ks = ks_2samp(a, b)
    lignes.append({"variable": c, "psi": psi(a, b),
                   "ks_statistique": ks.statistic, "ks_p_valeur": ks.pvalue,
                   "moyenne_reference": a.mean(), "moyenne_recente": b.mean()})

rapport_derive = pd.DataFrame(lignes).sort_values("psi", ascending=False)
rapport_derive["verdict"] = pd.cut(
    rapport_derive["psi"], [-1, .1, .25, np.inf],
    labels=["stable", "à surveiller", "DÉRIVE"],
)
rapport_derive.head(10).round(4).to_string(index=False)

# %%
# Dérive des variables catégorielles : la répartition des règles a-t-elle bougé ?
categorielles = [c for c in X_ref.columns
                 if not pd.api.types.is_numeric_dtype(X_ref[c])]
for c in categorielles:
    print(f"{c} — PSI = {psi(X_ref[c], X_rec[c]):.3f}")

repartition = pd.DataFrame({
    "reference": reference["regle_nom"].value_counts(normalize=True),
    "recente": recente["regle_nom"].value_counts(normalize=True),
}).fillna(0)
repartition["ecart"] = repartition["recente"] - repartition["reference"]
print("\nRègles dont la part a le plus varié :")
print(repartition.reindex(repartition["ecart"].abs().sort_values(ascending=False).index)
      .head(6).round(3).to_string())

# %%
fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.2))
axes[0].barh(rapport_derive["variable"].head(10)[::-1],
             rapport_derive["psi"].head(10)[::-1],
             color=["crimson" if v > .25 else "orange" if v > .1 else "steelblue"
                    for v in rapport_derive["psi"].head(10)[::-1]])
axes[0].axvline(.1, ls="--", color="grey", lw=.8)
axes[0].axvline(.25, ls="--", color="crimson", lw=.8)
axes[0].set(xlabel="PSI", title="Dérive par variable")

axes[1].hist(reference["reputation_source"].dropna(), bins=40, alpha=.6,
             density=True, label="référence")
axes[1].hist(recente["reputation_source"].dropna(), bins=40, alpha=.6,
             density=True, label="30 derniers jours")
axes[1].set(xlabel="réputation de la source", ylabel="densité",
            title="Exemple de dérive de distribution")
axes[1].legend()
plt.tight_layout()

# %% [markdown]
# ## 6. Dérive de performance
#
# La dérive des données est un **signal avancé** ; ce qui compte vraiment est la
# performance. Elle n'est mesurable qu'avec un **délai**, le temps que les
# analystes rendent leur verdict.

# %%
alertes["score"] = modele.predict_proba(X)[:, 1]
y = (alertes["verdict"] == "vrai_positif").astype(int)

mensuel = (
    alertes.assign(cible=y, mois=alertes["horodatage"].dt.to_period("M"))
    .groupby("mois")
    .apply(lambda g: pd.Series({
        "n": len(g),
        "taux_base": g["cible"].mean(),
        "auc_pr": average_precision_score(g["cible"], g["score"])
        if g["cible"].nunique() > 1 else np.nan,
        "auc_roc": roc_auc_score(g["cible"], g["score"])
        if g["cible"].nunique() > 1 else np.nan,
        "score_moyen": g["score"].mean(),
    }), include_groups=False)
)
mensuel["gain_sur_base"] = mensuel["auc_pr"] / mensuel["taux_base"]
# Le modèle n'a vu que les mois antérieurs à sa date d'entraînement : seuls les
# mois suivants constituent une mesure honnête de la performance en production.
fin_apprentissage = pd.Period(paquet["date_entrainement"][:7])
mensuel["hors_echantillon"] = mensuel.index > fin_apprentissage
print(f"Modèle entraîné jusqu'à {fin_apprentissage} inclus.")
print("Seules les lignes 'hors_echantillon = True' mesurent la production.\n")
mensuel.round(3).to_string()

# %%
fig, axes = plt.subplots(1, 2, figsize=(12.5, 4))
x = range(len(mensuel))
premier_hors = int(np.argmax(mensuel["hors_echantillon"].to_numpy()))
for a in axes:
    a.axvspan(-0.5, premier_hors - 0.5, color="lightgrey", alpha=.45)
    a.text(premier_hors / 2 - .5, a.get_ylim()[1], "vu à l'entraînement",
           ha="center", va="top", fontsize=8, color="dimgrey")
axes[0].plot(x, mensuel["auc_pr"], marker="o", label="AUC-PR du modèle")
axes[0].plot(x, mensuel["taux_base"], marker="s", ls="--", label="taux de base")
axes[0].set_xticks(list(x))
axes[0].set_xticklabels([str(m) for m in mensuel.index], rotation=45, fontsize=8)
axes[0].set(ylabel="AUC-PR", title="Performance mois par mois")
axes[0].legend(fontsize=8)
axes[0].grid(alpha=.3)

axes[1].plot(x, mensuel["gain_sur_base"], marker="o", color="darkgreen")
axes[1].axhline(2, ls="--", color="crimson", label="seuil de retrait (×2)")
axes[1].set_xticks(list(x))
axes[1].set_xticklabels([str(m) for m in mensuel.index], rotation=45, fontsize=8)
axes[1].set(ylabel="AUC-PR / taux de base", title="Gain relatif — le vrai indicateur")
axes[1].legend(fontsize=8)
axes[1].grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# ### Deux lectures de ce tableau
#
# **1. L'AUC-PR proche de 1 sur les premiers mois ne signifie rien.** Ces mois
# font partie du jeu d'apprentissage : le modèle les a mémorisés. Toute métrique
# calculée sur des données vues à l'entraînement est un artefact. C'est
# exactement l'erreur que produit une surveillance mal conçue, qui recalcule les
# performances sur l'historique complet et conclut que « tout va bien ».
#
# **2. La chute hors échantillon est le vrai signal.** Le gain relatif passe
# d'environ ×15 (mémorisé) à ×4 (réel). Il reste au-dessus du seuil de retrait
# fixé à ×2 dans la spécification : le modèle est **dégradé mais toujours utile**.
# La décision qui en découle n'est pas de le retirer, mais de déclencher un
# réentraînement — et d'aller comprendre la dérive constatée en section 5.

# %% [markdown]
# > **Attention à ne pas mal lire une baisse d'AUC-PR.** L'AUC-PR dépend
# > mécaniquement du taux de base : si la proportion de vrais positifs chute
# > (par exemple parce qu'une nouvelle règle bruyante inonde le SOC), l'AUC-PR
# > baisse **sans que le modèle se soit dégradé**. C'est pourquoi on surveille le
# > **gain relatif** `AUC-PR / taux de base`, et non l'AUC-PR seule.

# %% [markdown]
# ## 7. La boucle de retour
#
# Les étiquettes de demain sont produites par les analystes d'aujourd'hui — mais
# **uniquement sur les alertes qu'ils voient**. Le modèle influence donc ses
# propres futures données d'entraînement : c'est un **biais de rétroaction**.

# %%
BUDGET_JOUR = 15
jours = (alertes["horodatage"].max() - alertes["horodatage"].min()).days
budget = BUDGET_JOUR * jours

vues = alertes.nlargest(budget, "score")
non_vues = alertes.drop(vues.index)

print(f"Sur {len(alertes):,} alertes, {len(vues):,} seraient traitées "
      f"({len(vues) / len(alertes):.0%}) et étiquetées.\n")
print("Composition des alertes ÉTIQUETÉES par familles de règles :")
print((vues["famille_regle"].value_counts(normalize=True) -
       alertes["famille_regle"].value_counts(normalize=True))
      .sort_values(ascending=False).round(3).to_string())

print(f"\nVrais positifs jamais étiquetés (invisibles au réentraînement) : "
      f"{int((non_vues['verdict'] == 'vrai_positif').sum())}")

# %% [markdown]
# ### Exercice 7.1 — concevoir la parade
#
# Le biais est structurel : le modèle ne recevra plus de retour que sur ce qu'il
# remonte déjà, et se renforcera dans ses propres préférences. Proposez trois
# mécanismes correctifs, avec leur coût.

# %% [markdown] tags=["solution"]
# #### Corrigé
#
# | Mécanisme | Principe | Coût |
# |---|---|---|
# | **Quota d'exploration** | 5 à 10 % de la file tirés au hasard hors du classement | 5-10 % de la capacité, réduction du rappel à court terme |
# | **Échantillonnage par incertitude** | inclure les alertes de score proche du seuil, là où le modèle apprend le plus | faible ; c'est l'apprentissage actif |
# | **Audit rétrospectif** | revue mensuelle d'un échantillon aléatoire de non-traitées | quelques heures/mois, mais donne une estimation non biaisée du rappel réel |
# | **Étiquettes externes** | incidents remontés par les utilisateurs, retours CERT, exercices de simulation | indépendantes du modèle : le seul contrôle vraiment externe |
#
# Le quota d'exploration n'est pas une bonne pratique optionnelle : sans lui,
# **on ne peut pas estimer le rappel réel du dispositif**, donc pas mesurer ce
# qu'on manque.

# %% [markdown]
# ## 8. Politique de réentraînement et fiche de modèle

# %%
POLITIQUE = {
    "declencheurs": [
        "planifie : tous les 3 mois",
        "derive de donnees : PSI > 0.25 sur au moins 2 caracteristiques",
        "derive de performance : gain relatif < 2.5 sur un mois complet",
        "changement de perimetre : nouvelle regle SIEM representant > 5 % du volume",
    ],
    "procedure": [
        "1. figer un instantane des donnees et sa somme de controle",
        "2. reentrainer avec le MEME code de caracteristiques (service/caracteristiques.py)",
        "3. evaluer sur une partition TEMPORELLE, jamais aleatoire",
        "4. comparer au modele en production sur la meme periode de test",
        "5. deployer en observation (scores journalises, non utilises) pendant 2 semaines",
        "6. bascule, avec conservation du modele precedent pour repli",
    ],
    "criteres_de_refus": [
        "gain relatif inferieur au modele en place",
        "degradation du rappel sur les alertes de priorite P1",
        "apparition d'une caracteristique non disponible a la reception de l'alerte",
    ],
}
print(json.dumps(POLITIQUE, ensure_ascii=False, indent=2))

# %%
hors = mensuel[mensuel["hors_echantillon"]]
fiche = f"""# Fiche de modèle — Priorisation des alertes SIEM

## Identification
- Version : {paquet['date_entrainement'][:10]}
- Type : classification binaire, gradient boosting sur histogrammes
- Entraîné sur : {paquet['n_entrainement']:,} alertes, période close le {paquet['date_entrainement'][:10]}

## Usage prévu
Ordonner la file de triage des analystes N1. **Le modèle ne ferme aucune alerte
et ne déclenche aucune action automatique.**

## Usages explicitement exclus
- Fermeture automatique d'alertes
- Évaluation individuelle du travail des analystes
- Application à un périmètre technique différent sans réentraînement

## Performance mesurée — HORS ÉCHANTILLON uniquement
- AUC-PR : {hors['auc_pr'].mean():.3f} (taux de base {hors['taux_base'].mean():.3f})
- Gain relatif : ×{hors['gain_sur_base'].mean():.1f}
- Mesurée sur : {", ".join(str(m) for m in hors.index)}
- À capacité de {BUDGET_JOUR} alertes/jour : rappel mesuré à l'atelier 04

Les mois antérieurs à la date d'entraînement ne sont volontairement pas
comptabilisés : le modèle les a vus.

## Limites connues
- Entraîné sur des étiquettes produites par les analystes : hérite de leurs
  biais, y compris de ce qu'ils ont manqué.
- Les compteurs `alertes_hote_24h` / `alertes_compte_24h` sont calculés sur la
  journée entière et non en fenêtre strictement rétrospective : léger
  optimisme attendu en production.
- Non évalué sur des attaques absentes de l'historique : par construction, un
  modèle supervisé ne détecte que ce qui ressemble au passé.

## Surveillance
- PSI hebdomadaire sur toutes les caractéristiques
- Gain relatif mensuel, seuil de retrait à ×2
- Quota d'exploration de 8 % pour estimer le rappel réel

## Repli
En cas d'indisponibilité ou de retrait : tri par sévérité SIEM puis par
ancienneté. Ce repli est testé à chaque mise en production.
"""
(ARTEFACTS / "fiche_modele.md").write_text(fiche, encoding="utf-8")
print(fiche)

# %% [markdown]
# ## 9. Lancer le service dans votre Codespace
#
# Dans un **terminal** (menu *Terminal → New Terminal*) :
#
# ```bash
# uvicorn service.api:app --host 0.0.0.0 --port 8000 --reload
# ```
#
# VS Code propose alors d'ouvrir le port 8000. La documentation interactive de
# l'API est sur `/docs`. Depuis un autre terminal :
#
# ```bash
# curl -s localhost:8000/sante | python -m json.tool
# ```

# %% [markdown]
# ## 10. Synthèse et travail personnel
#
# **À retenir**
#
# 1. La **spécification** précède le code, et sa ligne la plus importante est
#    « ce que le service n'est pas ».
# 2. Le code de construction des caractéristiques doit être **partagé** entre
#    entraînement et service : c'est la seule parade au *training/serving skew*.
# 3. Un service de sécurité doit **échouer visiblement**, jamais silencieusement.
# 4. PSI et KS détectent la dérive des **données** ; seul le **gain relatif**
#    mesure la dérive de **performance**.
# 5. La boucle de retour est **biaisée par construction** : sans quota
#    d'exploration, on ne sait pas ce qu'on manque.
# 6. Un modèle sans fiche, sans surveillance et sans procédure de repli n'est pas
#    déployable, quelles que soient ses performances.
#
# **Travail personnel (≥ 4 h)**
#
# - Ajoutez au service la **journalisation** de chaque score (horodatage, entrées,
#   score, version) dans un fichier JSONL, puis écrivez le script de surveillance
#   qui calcule le PSI hebdomadaire depuis ce journal.
# - Implémentez le **quota d'exploration** : 8 % de la file tirés aléatoirement.
#   Simulez six mois avec et sans, et mesurez l'écart d'estimation du rappel.
# - Écrivez le test automatisé qui vérifie qu'un modèle candidat ne peut pas être
#   déployé s'il utilise une caractéristique indisponible à la réception de
#   l'alerte (garde-fou anti-fuite).
#
# **Suite :** atelier 11 — Temps 5, la recherche bibliographique.
