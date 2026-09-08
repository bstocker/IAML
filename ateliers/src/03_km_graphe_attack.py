# ---
# Atelier 03 — Temps 2 : Gestion des connaissances (2/2)
# ---

# %% [markdown]
# # Atelier 03 — KM 2 : graphe de connaissances ATT&CK et aide à la décision SOC
#
# > **Temps 2 — Gestion des connaissances** (2 UT sur 4) — 2 × 2 h de TP
#
# ## Objectifs
#
# 1. Construire un **graphe de propriétés** multi-types (technique, groupe,
#    logiciel, mitigation, règle, actif) à partir d'ATT&CK et des données du SOC.
# 2. Lire un **format d'échange CTI** : le bundle STIX 2.1.
# 3. Exploiter les **métriques de graphe** (degré, intermédiarité, communautés)
#    pour produire une information que ni le SIEM ni un tableur ne donnent.
# 4. Livrer un **plan de développement de détection priorisé** — le vrai livrable
#    attendu d'un ingénieur en ingénierie de la connaissance cyber.
#
# ## RDF ou graphe de propriétés ?
#
# | | RDF/OWL (atelier 02) | Graphe de propriétés (ici) |
# |---|---|---|
# | Force | sémantique formelle, inférence, interopérabilité | calcul, algorithmique de graphe, performance |
# | Requêtes | SPARQL, motifs | parcours, plus courts chemins, centralités |
# | Usage SOC | fusionner des référentiels, raisonner | **prioriser, mesurer, visualiser** |
#
# Les deux sont complémentaires : on modélise en RDF, on **calcule** en graphe de
# propriétés.

# %%
import json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"

attack = json.loads((DATA / "attack" / "attack_subset.json").read_text(encoding="utf-8"))
print(f"{len(attack['techniques'])} techniques · {len(attack['groupes'])} groupes · "
      f"{len(attack['logiciels'])} logiciels · {len(attack['mitigations'])} mitigations · "
      f"{len(attack['relations'])} relations")

# %% [markdown]
# ## 1. Lire un bundle STIX 2.1
#
# STIX est le format d'échange normalisé de la CTI (MISP, plateformes TIP, flux
# éditeurs). Savoir en extraire un graphe est une compétence de base.

# %%
bundle = json.loads((DATA / "attack" / "attack_bundle_stix.json").read_text(encoding="utf-8"))
types_stix = Counter(o["type"] for o in bundle["objects"])
print("Objets du bundle par type :")
for t, n in types_stix.most_common():
    print(f"  {t:20s} {n:>5}")

exemple = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
print("\nExemple d'objet attack-pattern :")
print(json.dumps(exemple, ensure_ascii=False, indent=2)[:700])

# %% [markdown]
# ### Exercice 1.1
#
# Écrivez `identifiant_mitre(objet)` qui extrait l'identifiant MITRE (`T1059`,
# `G0016`…) depuis les `external_references` d'un objet STIX, et construisez le
# dictionnaire `stix_vers_mitre` qui associe chaque `id` STIX à son identifiant.
#
# Attention : les objets `relationship` n'ont pas de référence externe.

# %% tags=["todo"]
def identifiant_mitre(objet: dict) -> str | None:
    # TODO : parcourir external_references, retenir source_name == 'mitre-attack'
    return None


stix_vers_mitre = {}
print(len(stix_vers_mitre), "objets identifiés")

# %% tags=["solution"]
def identifiant_mitre(objet: dict) -> str | None:
    for ref in objet.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


stix_vers_mitre = {
    o["id"]: identifiant_mitre(o)
    for o in bundle["objects"]
    if identifiant_mitre(o) is not None
}
print(f"{len(stix_vers_mitre)} objets identifiés")

relations_stix = [
    (stix_vers_mitre.get(o["source_ref"]), o["relationship_type"],
     stix_vers_mitre.get(o["target_ref"]))
    for o in bundle["objects"] if o["type"] == "relationship"
]
print(f"{len(relations_stix)} relations reconstruites, exemple : {relations_stix[0]}")

# %% [markdown]
# ## 2. Construire le graphe de connaissances

# %%
def construire_graphe(attack: dict) -> nx.Graph:
    G = nx.Graph()

    for tac in attack["tactiques"]:
        G.add_node(tac["id"], type="tactique", label=tac["nom_fr"])
    for t in attack["techniques"]:
        G.add_node(t["id"], type="technique", label=t["nom"],
                   plateformes=t["plateformes"],
                   sources_donnees=t["sources_donnees"],
                   sous_technique=t["est_sous_technique"])
        for tac in t["tactiques"]:
            code = next(x["id"] for x in attack["tactiques"] if x["shortname"] == tac)
            G.add_edge(t["id"], code, relation="releve_de")
        if t["sous_technique_de"]:
            G.add_edge(t["id"], t["sous_technique_de"], relation="sous_technique_de")

    for gr in attack["groupes"]:
        G.add_node(gr["id"], type="groupe", label=gr["nom"], motivation=gr["motivation"])
    for lo in attack["logiciels"]:
        G.add_node(lo["id"], type="logiciel", label=lo["nom"], categorie=lo["categorie"])
    for mi in attack["mitigations"]:
        G.add_node(mi["id"], type="mitigation", label=mi["nom"])

    for rel in attack["relations"]:
        source = rel.get("groupe") or rel.get("logiciel") or rel.get("mitigation")
        G.add_edge(source, rel["technique"], relation=rel["type"])
    return G


G = construire_graphe(attack)
print(f"Graphe : {G.number_of_nodes()} nœuds, {G.number_of_edges()} arêtes")
print("Répartition :", Counter(nx.get_node_attributes(G, "type").values()).most_common())

# %% [markdown]
# ## 3. Y brancher la réalité du SOC
#
# Un graphe ATT&CK seul n'est qu'une copie du site du MITRE. Sa valeur vient de
# ce qu'on y **greffe notre propre situation** : nos règles, nos actifs, nos
# vulnérabilités.

# %%
alertes = pd.read_csv(DATA / "alertes_siem.csv", usecols=["regle_id", "regle_nom",
                                                          "technique_attack", "verdict"])
regles = (
    alertes.groupby(["regle_id", "regle_nom", "technique_attack"])
    .agg(volume=("verdict", "size"),
         taux_vp=("verdict", lambda s: (s == "vrai_positif").mean()))
    .reset_index()
)

for _, r in regles.iterrows():
    G.add_node(r["regle_id"], type="regle", label=r["regle_nom"],
               volume=int(r["volume"]), taux_vp=float(r["taux_vp"]))
    if r["technique_attack"] in G:
        G.add_edge(r["regle_id"], r["technique_attack"], relation="detecte")

cve = pd.read_csv(DATA / "cve.csv")
expo = pd.read_csv(DATA / "vulnerabilites_hotes.csv")
assets = pd.read_csv(DATA / "assets.csv")

exposition = (
    expo[~expo["corrigee"]]
    .merge(cve[["cve_id", "technique_attack", "cvss_v3", "exploite_dans_la_nature"]],
           on="cve_id")
    .merge(assets[["asset_id", "criticite"]], on="asset_id")
    .groupby("technique_attack")
    .agg(actifs_exposes=("asset_id", "nunique"),
         criticite_max=("criticite", "max"),
         cvss_max=("cvss_v3", "max"),
         exploite_ITW=("exploite_dans_la_nature", "any"))
)
print(f"{len(regles)} règles rattachées · "
      f"{len(exposition)} techniques portées par une CVE non corrigée")
exposition.head()

# %% [markdown]
# ## 4. Ce que les métriques de graphe révèlent
#
# ### 4.1 Techniques les plus « partagées » entre groupes
#
# Le degré vers les groupes mesure l'universalité d'une technique : la détecter,
# c'est couvrir beaucoup d'adversaires à la fois.

# %%
techniques = [n for n, d in G.nodes(data=True) if d["type"] == "technique"]

def voisins_de_type(G, n, t):
    return [v for v in G.neighbors(n) if G.nodes[v]["type"] == t]


tableau = pd.DataFrame({
    "technique": techniques,
    "nom": [G.nodes[t]["label"] for t in techniques],
    "nb_groupes": [len(voisins_de_type(G, t, "groupe")) for t in techniques],
    "nb_logiciels": [len(voisins_de_type(G, t, "logiciel")) for t in techniques],
    "nb_mitigations": [len(voisins_de_type(G, t, "mitigation")) for t in techniques],
    "nb_regles": [len(voisins_de_type(G, t, "regle")) for t in techniques],
}).set_index("technique")

tableau.sort_values("nb_groupes", ascending=False).head(10)

# %% [markdown]
# ### 4.2 Centralité d'intermédiarité
#
# L'intermédiarité (*betweenness*) mesure combien de plus courts chemins passent
# par un nœud. Sur un graphe de menace, une technique à forte intermédiarité est
# un **point de passage** entre familles d'adversaires : un bon investissement de
# détection.

# %%
intermediarite = nx.betweenness_centrality(G, normalized=True, seed=0)
tableau["intermediarite"] = [intermediarite[t] for t in tableau.index]
tableau.sort_values("intermediarite", ascending=False).head(8)[
    ["nom", "intermediarite", "nb_groupes", "nb_regles"]
].round(4)

# %% [markdown]
# ### 4.3 Couverture de détection par tactique
#
# La question que pose toute direction : *« sommes-nous couverts ? »*

# %%
lignes = []
for tac in attack["tactiques"]:
    techs = [t for t in voisins_de_type(G, tac["id"], "technique")]
    if not techs:
        continue
    couvertes = [t for t in techs if tableau.loc[t, "nb_regles"] > 0]
    lignes.append({"tactique": tac["nom_fr"], "techniques": len(techs),
                   "couvertes": len(couvertes),
                   "couverture": len(couvertes) / len(techs)})
couverture = pd.DataFrame(lignes).sort_values("couverture")

fig, ax = plt.subplots(figsize=(9, 5))
couleurs = ["crimson" if c < .34 else "orange" if c < .67 else "seagreen"
            for c in couverture["couverture"]]
ax.barh(couverture["tactique"], couverture["couverture"] * 100, color=couleurs)
for i, (_, r) in enumerate(couverture.iterrows()):
    ax.text(r["couverture"] * 100 + 1, i, f"{r['couvertes']}/{r['techniques']}",
            va="center", fontsize=8)
ax.set_xlabel("Techniques couvertes par au moins une règle (%)")
ax.set_title("Couverture de détection par tactique ATT&CK")
ax.set_xlim(0, 108)
ax.grid(axis="x", alpha=.3)
plt.tight_layout()

# %% [markdown]
# > **Attention à l'illusion de couverture.** « Une règle existe » ne signifie ni
# > qu'elle est efficace, ni que la source de données nécessaire est collectée.
# > Le tableau ci-dessous croise couverture **et** rendement.

# %%
qualite = []
for t in techniques:
    r_ids = voisins_de_type(G, t, "regle")
    if r_ids:
        qualite.append({
            "technique": t, "nom": G.nodes[t]["label"],
            "volume": sum(G.nodes[r]["volume"] for r in r_ids),
            "taux_vp_moyen": np.mean([G.nodes[r]["taux_vp"] for r in r_ids]),
        })
pd.DataFrame(qualite).sort_values("taux_vp_moyen").head(6).round(3)

# %% [markdown]
# ## 5. Exercice central — le plan de détection priorisé
#
# **Consigne.** Produisez un classement des techniques à instrumenter en priorité,
# à partir d'un score explicite combinant :
#
# | Facteur | Source | Effet |
# |---|---|---|
# | popularité chez les adversaires | `nb_groupes` | ↑ |
# | rôle de point de passage | `intermediarite` | ↑ |
# | exposition réelle de notre parc | `exposition['actifs_exposes']` | ↑ |
# | exploitation constatée dans la nature | `exposition['exploite_ITW']` | ↑ |
# | détection déjà en place | `nb_regles` | ↓ (annule) |
# | mesure d'atténuation disponible | `nb_mitigations` | ↓ (atténue) |
#
# **Le score n'est pas la réponse : c'est l'argumentaire.** Vous devrez justifier
# chaque pondération devant le responsable du SOC. Documentez vos choix.

# %% tags=["todo"]
# TODO :
#   1. joindre `tableau` et `exposition`
#   2. normaliser les composantes (min-max ou rang) pour qu'elles soient comparables
#   3. combiner en un score, annuler les techniques déjà couvertes
#   4. afficher le top 12 avec les colonnes qui justifient le classement
plan_detection = None
plan_detection

# %% tags=["solution"]
base = tableau.join(exposition, how="left").fillna(
    {"actifs_exposes": 0, "criticite_max": 0, "cvss_max": 0, "exploite_ITW": False}
)

def normaliser(s: pd.Series) -> pd.Series:
    """Min-max ; renvoie 0 si la série est constante."""
    etendue = s.max() - s.min()
    return (s - s.min()) / etendue if etendue else pd.Series(0.0, index=s.index)


# Pondérations : à assumer et à discuter, pas à optimiser.
POIDS = {"groupes": 0.25, "intermediarite": 0.15, "exposition": 0.30,
         "itw": 0.20, "criticite": 0.10}

base["s_groupes"] = normaliser(base["nb_groupes"])
base["s_intermediarite"] = normaliser(base["intermediarite"])
base["s_exposition"] = normaliser(np.log1p(base["actifs_exposes"]))
base["s_itw"] = base["exploite_ITW"].astype(float)
base["s_criticite"] = normaliser(base["criticite_max"])

base["score_brut"] = sum(POIDS[k] * base[f"s_{k}"] for k in POIDS)

# Une technique déjà détectée sort du plan ; une mitigation disponible réduit
# l'urgence de la détection sans l'annuler (la mesure peut ne pas être déployée).
base["score"] = (
    base["score_brut"]
    * (base["nb_regles"] == 0)
    * (1 - 0.25 * (base["nb_mitigations"] > 0))
)

plan_detection = (
    base.sort_values("score", ascending=False)
    .head(12)[["nom", "score", "nb_groupes", "intermediarite", "actifs_exposes",
               "exploite_ITW", "nb_mitigations"]]
    .round(3)
)
plan_detection

# %% [markdown]
# ### Lecture du résultat
#
# Pour chaque technique retenue, l'ingénieur doit encore répondre à trois
# questions avant d'ouvrir un ticket de développement :
#
# 1. **La source de données est-elle collectée ?** (`G.nodes[t]['sources_donnees']`)
# 2. **Quel volume d'alertes cette détection va-t-elle produire ?**
# 3. **Quelle réponse déclenchera-t-elle ?** Une détection sans procédure de
#    réponse associée n'est qu'une source de bruit supplémentaire.

# %%
for t in plan_detection.index[:5]:
    print(f"{t:11s} {G.nodes[t]['label'][:42]:44s} "
          f"sources requises : {', '.join(G.nodes[t]['sources_donnees'])}")

# %% [markdown]
# ## 6. Détection de communautés : lire la structure des adversaires
#
# Deux groupes qui partagent beaucoup de techniques forment une communauté :
# une détection efficace contre l'un l'est probablement contre l'autre.

# %%
# Graphe de similarité entre groupes : arête pondérée par le nombre de techniques
# partagées (indice de Jaccard).
groupes = [n for n, d in G.nodes(data=True) if d["type"] == "groupe"]
arsenal = {g: set(voisins_de_type(G, g, "technique")) for g in groupes}

S = nx.Graph()
S.add_nodes_from(groupes)
for i, a in enumerate(groupes):
    for b in groupes[i + 1:]:
        inter = len(arsenal[a] & arsenal[b])
        union = len(arsenal[a] | arsenal[b])
        if union and inter / union > 0.15:
            S.add_edge(a, b, weight=inter / union)

communautes = nx.community.louvain_communities(S, weight="weight", seed=0)
for i, com in enumerate(communautes, 1):
    noms = sorted(G.nodes[g]["label"] for g in com)
    print(f"Communauté {i} : {', '.join(noms)}")

# %% [markdown]
# ### Exercice 6.1
#
# Pour la communauté la plus large, identifiez les techniques utilisées par
# **tous** ses membres (intersection des arsenaux). Ce sont les détections à
# rendement maximal contre ce cluster d'adversaires.

# %% tags=["todo"]
# TODO : intersection des ensembles de techniques des membres de la communauté.

# %% tags=["solution"]
plus_grande = max(communautes, key=len)
commun = set.intersection(*(arsenal[g] for g in plus_grande))
frequentes = Counter()
for g in plus_grande:
    frequentes.update(arsenal[g])

print(f"Communauté de {len(plus_grande)} groupes : "
      f"{', '.join(sorted(G.nodes[g]['label'] for g in plus_grande))}")
print(f"\nTechniques communes à TOUS les membres : "
      f"{sorted(commun) if commun else 'aucune'}")
print("\nTechniques les plus partagées :")
for t, n in frequentes.most_common(8):
    couvert = "détectée" if tableau.loc[t, "nb_regles"] else "NON DÉTECTÉE"
    print(f"  {t:11s} {G.nodes[t]['label'][:38]:40s} {n}/{len(plus_grande)} groupes  [{couvert}]")

# %% [markdown]
# ## 7. Visualiser sans noyer le lecteur
#
# Le « graphe boule de poils » complet n'apprend rien à personne. On ne visualise
# qu'un **sous-graphe motivé par une question**.

# %%
cible = plan_detection.index[0]
voisinage = set(nx.single_source_shortest_path_length(G, cible, cutoff=1))
voisinage |= {v for u in list(voisinage)[:6] for v in list(G.neighbors(u))[:4]}
H = G.subgraph(voisinage)

COULEURS = {"technique": "#4C72B0", "tactique": "#DD8452", "groupe": "#C44E52",
            "logiciel": "#8172B3", "mitigation": "#55A868", "regle": "#937860"}
pos = nx.spring_layout(H, seed=3, k=0.55)

fig, ax = plt.subplots(figsize=(12, 8))
nx.draw_networkx_edges(H, pos, alpha=.25, ax=ax)
for typ, couleur in COULEURS.items():
    noeuds = [n for n in H if H.nodes[n]["type"] == typ]
    nx.draw_networkx_nodes(H, pos, nodelist=noeuds, node_color=couleur,
                           node_size=[520 if n == cible else 210 for n in noeuds],
                           label=typ, ax=ax)
nx.draw_networkx_labels(
    H, pos, ax=ax, font_size=7,
    labels={n: H.nodes[n]["label"][:20] for n in H},
)
ax.set_title(f"Voisinage de {cible} — {G.nodes[cible]['label']}\n"
             f"(technique prioritaire du plan de détection)")
ax.legend(scatterpoints=1, loc="upper left", fontsize=8)
ax.axis("off")
plt.tight_layout()

# %% [markdown]
# ## 8. Synthèse et travail personnel
#
# **À retenir**
#
# 1. La valeur d'un graphe de connaissances cyber ne vient pas du référentiel
#    importé mais de **ce qu'on y greffe** de notre propre situation.
# 2. Les métriques de graphe (degré, intermédiarité, communautés) transforment un
#    référentiel descriptif en **outil de priorisation**.
# 3. Un score de priorité est un **argumentaire explicite**, pas une vérité :
#    ses pondérations doivent être discutables et documentées.
# 4. Une couverture ATT&CK affichée à 80 % ne veut rien dire sans le rendement des
#    règles et la disponibilité effective des sources de données.
#
# **Travail personnel (≥ 4 h)**
#
# - Ajoutez au graphe les **sources de données** comme nœuds à part entière, puis
#   répondez : *quelle source, si nous la collections, débloquerait le plus de
#   détections prioritaires ?* C'est l'argument budgétaire d'un projet SOC.
# - Comparez votre classement avec la démarche du *MITRE ATT&CK Navigator* et
#   discutez ce qu'apporte le calcul de graphe par rapport à un simple tableur.
# - Exportez le graphe au format GraphML (`nx.write_graphml`) et ouvrez-le dans
#   Gephi ou Cytoscape.
#
# **Suite :** Temps 3 — atelier 04, apprentissage supervisé pour le triage des alertes.
