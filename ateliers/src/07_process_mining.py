# ---
# Atelier 07 — Temps 4 (option A) : Process Mining
# ---

# %% [markdown]
# # Atelier 07 — Process mining : analyser le processus de réponse à incident
#
# > **Temps 4 — Process Mining ou Détection d'Anomalies** (1 UT) — 2 h de TP
# >
# > Cet atelier traite l'option **process mining**. L'atelier 08 traite l'option
# > **détection d'anomalies**. Les deux peuvent être menés en survol, ou l'un des
# > deux approfondi (voir `docs/planning.md`).
#
# ## Objectifs
#
# 1. Comprendre ce qu'est un **journal d'événements de processus** et en quoi il
#    diffère d'un journal technique.
# 2. **Découvrir** automatiquement un modèle de processus à partir des traces
#    (algorithmes *alpha*, *heuristic miner*, *inductive miner*).
# 3. Mesurer la **conformité** entre le processus réel et le processus prescrit.
# 4. Identifier **goulets d'étranglement**, **boucles de reprise** et **variantes**.
# 5. Produire des recommandations d'amélioration chiffrées — le livrable attendu.
#
# ## Pourquoi c'est un sujet de cybersécurité
#
# Le process mining ne s'applique pas ici aux attaquants mais au **SOC lui-même**.
# La question : *où passe réellement le temps de traitement d'un incident, et
# quelle étape faut-il corriger en priorité ?* C'est aussi un outil d'audit : un
# écart entre le processus prescrit et le processus observé est un constat
# objectif, opposable, tiré des données.
#
# La même démarche s'applique ensuite aux journaux techniques (séquences
# d'actions d'un attaquant, chaînes de processus), sans changer d'outillage.

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"

journal = pd.read_csv(DATA / "journal_incidents.csv", parse_dates=["horodatage"])
print(f"{len(journal):,} événements · {journal['case_id'].nunique()} incidents · "
      f"{journal['activite'].nunique()} activités · "
      f"{journal['ressource'].nunique()} intervenants")
journal.head(10)

# %% [markdown]
# ## 1. Les trois colonnes obligatoires
#
# Un journal exploitable en process mining exige exactement trois informations :
#
# | Rôle | Notre colonne | Convention XES |
# |---|---|---|
# | **Cas** — l'objet qui suit le processus | `case_id` | `case:concept:name` |
# | **Activité** — ce qui a été fait | `activite` | `concept:name` |
# | **Horodatage** — quand | `horodatage` | `time:timestamp` |
#
# Tout le reste (`ressource`, `priorite`, `type_incident`) est un attribut
# facultatif, précieux pour l'analyse organisationnelle.

# %%
import pm4py
from pm4py.util import constants

constants.SHOW_PROGRESS_BAR = False  # barres de progression inutiles en notebook

evenements = journal.rename(columns={
    "case_id": "case:concept:name",
    "activite": "concept:name",
    "horodatage": "time:timestamp",
    "ressource": "org:resource",
})
evenements = pm4py.format_dataframe(
    evenements, case_id="case:concept:name",
    activity_key="concept:name", timestamp_key="time:timestamp",
)
print("Activités de départ :", pm4py.get_start_activities(evenements))
print("Activités de fin    :", pm4py.get_end_activities(evenements))

# %% [markdown]
# ## 2. Les variantes : combien de façons de traiter un incident ?
#
# Une **variante** est une séquence d'activités distincte. Leur distribution est
# la première chose à regarder : un processus sain concentre l'essentiel du
# volume sur quelques variantes.

# %%
variantes = pm4py.get_variants(evenements)
tri = sorted(variantes.items(), key=lambda kv: -(len(kv[1]) if hasattr(kv[1], "__len__") else kv[1]))


def effectif(v):
    return len(v) if hasattr(v, "__len__") else int(v)


total = sum(effectif(v) for v in variantes.values())
print(f"{len(variantes)} variantes pour {journal['case_id'].nunique()} incidents\n")
cumul = 0
for i, (chemin, cas) in enumerate(tri[:8], 1):
    n = effectif(cas)
    cumul += n
    print(f"{i}. {n:>4} incidents ({n / total:>5.1%}, cumul {cumul / total:>5.1%})")
    print("   " + " → ".join(chemin))

print(f"\nQueue longue : {sum(1 for _, v in tri if effectif(v) == 1)} variantes "
      f"n'apparaissent qu'une seule fois.")

# %% [markdown]
# ## 3. Découverte du modèle de processus
#
# Trois familles d'algorithmes, trois compromis.

# %%
reseau, marquage_initial, marquage_final = pm4py.discover_petri_net_inductive(
    evenements, noise_threshold=0.2
)
print(f"Réseau de Petri (inductive miner) : {len(reseau.places)} places, "
      f"{len(reseau.transitions)} transitions, {len(reseau.arcs)} arcs")

carte_heuristique = pm4py.discover_heuristics_net(evenements, dependency_threshold=0.9)
print("Carte heuristique construite (robuste au bruit, lisible).")

# %%
# Le graphe « directement suivi de » (DFG) : la représentation la plus lisible
# pour discuter avec des non-spécialistes.
dfg, activites_debut, activites_fin = pm4py.discover_dfg(evenements)
arcs = pd.DataFrame(
    [{"de": a, "vers": b, "occurrences": n} for (a, b), n in dfg.items()]
).sort_values("occurrences", ascending=False)
print("Transitions les plus fréquentes :")
arcs.head(12).to_string(index=False)

# %% [markdown]
# ### Exercice 3.1 — visualiser le DFG
#
# Tracez le graphe « directement suivi de » avec `networkx`, en ne gardant que les
# arcs représentant au moins 3 % du volume. Épaisseur de l'arc proportionnelle au
# nombre d'occurrences.
#
# **Pourquoi filtrer ?** Un DFG complet sur un processus réel est illisible
# (« spaghetti »). Le filtrage n'est pas une commodité : c'est la condition pour
# que le modèle soit interprétable.

# %% tags=["todo"]
# TODO : construire un DiGraph networkx à partir de `arcs`, filtrer, tracer.

# %% tags=["solution"]
import networkx as nx

SEUIL = 0.03 * len(journal)
arcs_filtres = arcs[arcs["occurrences"] >= SEUIL]

G = nx.DiGraph()
for _, r in arcs_filtres.iterrows():
    G.add_edge(r["de"], r["vers"], weight=r["occurrences"])

frequence = journal["activite"].value_counts()
pos = nx.spring_layout(G, seed=7, k=2.4, iterations=250)

fig, ax = plt.subplots(figsize=(13, 8))
poids = np.array([G[u][v]["weight"] for u, v in G.edges()])
nx.draw_networkx_edges(G, pos, ax=ax, width=1 + 5 * poids / poids.max(),
                       alpha=.45, edge_color="grey",
                       arrowsize=16, connectionstyle="arc3,rad=0.08")
nx.draw_networkx_nodes(G, pos, ax=ax,
                       node_size=[380 + 9 * frequence.get(n, 0) for n in G.nodes()],
                       node_color=[frequence.get(n, 0) for n in G.nodes()],
                       cmap="YlOrRd", edgecolors="k", linewidths=.6)
nx.draw_networkx_labels(G, pos, ax=ax, font_size=8)
nx.draw_networkx_edge_labels(
    G, pos, ax=ax, font_size=6,
    edge_labels={(u, v): int(G[u][v]["weight"]) for u, v in G.edges()},
)
ax.set_title(f"Processus réel de traitement d'incident\n"
             f"(arcs représentant ≥ 3 % du volume — {len(arcs_filtres)}/{len(arcs)} arcs)")
ax.axis("off")
plt.tight_layout()

# %% [markdown]
# ## 4. Performance : où passe le temps ?
#
# C'est l'apport décisif du process mining par rapport à un simple diagramme :
# chaque transition porte une **durée**.

# %%
journal = journal.sort_values(["case_id", "horodatage"])
journal["activite_suivante"] = journal.groupby("case_id")["activite"].shift(-1)
journal["attente_h"] = (
    journal.groupby("case_id")["horodatage"].shift(-1) - journal["horodatage"]
).dt.total_seconds() / 3600

transitions = (
    journal.dropna(subset=["activite_suivante"])
    .groupby(["activite", "activite_suivante"])
    .agg(occurrences=("attente_h", "size"),
         attente_mediane_h=("attente_h", "median"),
         attente_p90_h=("attente_h", lambda s: s.quantile(.9)),
         temps_total_h=("attente_h", "sum"))
    .reset_index()
    .sort_values("temps_total_h", ascending=False)
)
print("Transitions consommant le plus de temps cumulé :")
transitions.head(10).round(1).to_string(index=False)

# %% [markdown]
# ### Exercice 4.1 — identifier le goulet d'étranglement
#
# Deux notions à ne pas confondre :
#
# - la transition la plus **lente** (attente médiane la plus élevée) ;
# - la transition qui coûte le plus de **temps cumulé** (lenteur × fréquence).
#
# C'est la seconde qui doit être corrigée en priorité. Identifiez-la, quantifiez
# le gain d'une réduction de 50 % de son attente médiane, et exprimez-le en
# journées-homme.

# %% tags=["todo"]
# TODO : identifier la transition, calculer le temps cumulé, en déduire le gain.

# %% tags=["solution"]
plus_lente = transitions.nlargest(1, "attente_mediane_h").iloc[0]
plus_couteuse = transitions.iloc[0]

print(f"Transition la plus LENTE   : {plus_lente['activite']} → "
      f"{plus_lente['activite_suivante']}")
print(f"   {plus_lente['attente_mediane_h']:.1f} h de médiane, "
      f"{int(plus_lente['occurrences'])} occurrences\n")

print(f"Transition la plus COÛTEUSE : {plus_couteuse['activite']} → "
      f"{plus_couteuse['activite_suivante']}")
print(f"   {plus_couteuse['attente_mediane_h']:.1f} h de médiane × "
      f"{int(plus_couteuse['occurrences'])} occurrences "
      f"= {plus_couteuse['temps_total_h']:,.0f} h cumulées")

gain_h = plus_couteuse["temps_total_h"] * 0.5
print(f"\nRéduire de 50 % l'attente de cette transition libère "
      f"{gain_h:,.0f} h sur 6 mois,")
print(f"soit {gain_h / 7:,.0f} journées-homme, ou "
      f"{gain_h / (6 * 151):.2f} équivalent temps plein.")
print("\n→ C'est le chiffre à mettre dans une demande d'arbitrage.")

# %% [markdown]
# ## 5. Les boucles de reprise
#
# Une activité répétée dans un même cas est une **reprise** (*rework*) : du travail
# refait. C'est l'indicateur de qualité de processus le plus parlant.

# %%
repetitions = (
    journal.groupby(["case_id", "activite"]).size()
    .rename("occurrences").reset_index()
)
reprises = repetitions[repetitions["occurrences"] > 1]

synthese = (
    reprises.groupby("activite")
    .agg(cas_concernes=("case_id", "nunique"),
         repetitions_totales=("occurrences", "sum"))
    .assign(part_des_cas=lambda d: d["cas_concernes"] / journal["case_id"].nunique())
    .sort_values("cas_concernes", ascending=False)
)
print("Activités faisant l'objet de reprises :")
synthese.round(3).to_string()

# %%
cas_avec_reprise = set(reprises["case_id"])
duree_cas = (
    journal.groupby("case_id")["horodatage"].agg(["min", "max"])
    .assign(duree_h=lambda d: (d["max"] - d["min"]).dt.total_seconds() / 3600)
)
duree_cas["reprise"] = duree_cas.index.isin(cas_avec_reprise)

fig, ax = plt.subplots(figsize=(9, 4))
for valeur, libelle, couleur in [(False, "sans reprise", "seagreen"),
                                 (True, "avec reprise", "crimson")]:
    donnees = duree_cas.loc[duree_cas["reprise"] == valeur, "duree_h"]
    ax.hist(np.log10(donnees + 1), bins=50, alpha=.6, label=f"{libelle} (n={len(donnees)})",
            color=couleur, density=True)
ax.set(xlabel="log10(durée de traitement en heures)", ylabel="densité",
       title="Effet des boucles de reprise sur la durée de traitement")
ax.legend()
ax.grid(alpha=.3)
plt.tight_layout()

med_sans = duree_cas.loc[~duree_cas["reprise"], "duree_h"].median()
med_avec = duree_cas.loc[duree_cas["reprise"], "duree_h"].median()
print(f"Durée médiane sans reprise : {med_sans:>7.1f} h")
print(f"Durée médiane avec reprise : {med_avec:>7.1f} h  (×{med_avec / med_sans:.1f})")

# %% [markdown]
# ## 6. Conformité : le réel contre le prescrit
#
# La procédure du SOC prescrit un enchaînement. Mesurons l'écart.

# %%
qualite = pm4py.conformance_diagnostics_token_based_replay(
    evenements, reseau, marquage_initial, marquage_final
)
ajustement = np.mean([d["trace_fitness"] for d in qualite])
conformes = np.mean([d["trace_is_fit"] for d in qualite])
print(f"Ajustement moyen (trace fitness) : {ajustement:.3f}")
print(f"Traces parfaitement conformes    : {conformes:.1%}")

print(f"\nSimplicité du modèle : {pm4py.fitness_token_based_replay(evenements, reseau, marquage_initial, marquage_final)['log_fitness']:.3f}")

# %% [markdown]
# ### Exercice 6.1 — les règles métier
#
# Vérifiez directement, sans passer par un modèle formel, trois règles de la
# procédure :
#
# 1. tout incident escaladé en N2 a été qualifié en N1 auparavant ;
# 2. aucune clôture n'intervient avant un confinement, pour les incidents qui en
#    ont eu un ;
# 3. les incidents P1 sont qualifiés en moins de 2 h.
#
# Pour chaque règle : taux de conformité et liste des cas en écart.

# %% tags=["todo"]
# TODO : trois vérifications sur les traces, à partir de `traces`.
traces = journal.groupby("case_id")["activite"].apply(list)

# %% tags=["solution"]
traces = journal.groupby("case_id")["activite"].apply(list)


def position(trace, activite):
    return trace.index(activite) if activite in trace else None


# Règle 1 — escalade N2 précédée d'une qualification N1
concernes_1 = [c for c, t in traces.items() if "Escalade N2" in t]
violations_1 = [
    c for c in concernes_1
    if position(traces[c], "Qualification N1") is None
    or position(traces[c], "Qualification N1") > position(traces[c], "Escalade N2")
]

# Règle 2 — pas de clôture avant confinement
concernes_2 = [c for c, t in traces.items() if "Confinement" in t and "Cloture" in t]
violations_2 = [
    c for c in concernes_2
    if position(traces[c], "Cloture") < position(traces[c], "Confinement")
]

# Règle 3 — P1 qualifiés en moins de 2 h
p1 = journal[journal["priorite"] == "P1"]
delais = (
    p1[p1["activite"].isin(["Detection", "Qualification N1"])]
    .pivot_table(index="case_id", columns="activite", values="horodatage", aggfunc="min")
    .dropna()
)
delais["delai_h"] = (
    delais["Qualification N1"] - delais["Detection"]
).dt.total_seconds() / 3600
violations_3 = delais[delais["delai_h"] > 2]

for i, (libelle, concernes, violations) in enumerate([
    ("Escalade N2 précédée d'une qualification N1", concernes_1, violations_1),
    ("Aucune clôture avant confinement", concernes_2, violations_2),
    ("P1 qualifiés en moins de 2 h", delais, violations_3),
], 1):
    n_c, n_v = len(concernes), len(violations)
    print(f"Règle {i} — {libelle}")
    print(f"   {n_c - n_v}/{n_c} conformes ({(n_c - n_v) / n_c:.1%})")
    if n_v:
        exemples = (list(violations.index) if isinstance(violations, pd.DataFrame)
                    else list(violations))[:5]
        print(f"   écarts : {exemples}")
    print()

print(f"Délai médian de qualification des P1 : {delais['delai_h'].median():.1f} h "
      f"(90ᵉ centile : {delais['delai_h'].quantile(.9):.1f} h)")

# %% [markdown]
# ## 7. Analyse organisationnelle
#
# L'attribut `org:resource` permet de passer du processus aux **personnes** : qui
# travaille avec qui, où se forme la file d'attente.

# %%
charge = (
    journal.groupby(["niveau", "ressource"])
    .agg(activites=("activite", "size"),
         cas=("case_id", "nunique"))
    .reset_index()
)
print(charge.groupby("niveau")[["activites", "cas"]].agg(["sum", "mean"]).round(0))

# Réseau de passation : qui transmet à qui.
journal["ressource_suivante"] = journal.groupby("case_id")["ressource"].shift(-1)
passations = (
    journal.dropna(subset=["ressource_suivante"])
    .query("ressource != ressource_suivante")
    .groupby(["niveau", "ressource_suivante"]).size()
    .rename("passations").reset_index()
)
niveau_de = journal.drop_duplicates("ressource").set_index("ressource")["niveau"]
passations["niveau_cible"] = passations["ressource_suivante"].map(niveau_de)
print("\nPassations entre niveaux :")
passations.groupby(["niveau", "niveau_cible"])["passations"].sum().to_string()

# %% [markdown]
# ### Effet du travail hors heures ouvrables

# %%
journal["heure"] = journal["horodatage"].dt.hour
journal["hors_ouvrable"] = (
    (journal["heure"] < 7) | (journal["heure"] > 19) |
    (journal["horodatage"].dt.weekday >= 5)
)
effet = (
    journal.dropna(subset=["attente_h"])
    .groupby("hors_ouvrable")["attente_h"]
    .agg(["median", "mean", "size"]).round(2)
)
effet.index = ["heures ouvrables", "hors heures ouvrables"]
print(effet)
print(f"\nRapport des médianes : "
      f"×{effet.loc['hors heures ouvrables', 'median'] / effet.loc['heures ouvrables', 'median']:.1f}")
print("→ Argument objectif pour dimensionner une astreinte ou une équipe de nuit.")

# %% [markdown]
# ## 8. Exercice de synthèse — la note de recommandation
#
# **Consigne.** Rédigez une note d'une page à destination du responsable du SOC,
# structurée ainsi :
#
# 1. **Constat** — trois faits chiffrés issus de cette analyse.
# 2. **Diagnostic** — la cause la plus probable de chacun.
# 3. **Recommandations** — trois actions, avec le gain estimé en heures ou en ETP.
# 4. **Mesure** — pour chaque action, l'indicateur qui permettra de vérifier
#    qu'elle a produit l'effet attendu.
#
# Contrainte : chaque affirmation doit être adossée à un calcul reproductible du
# notebook. Une recommandation non chiffrée n'est pas recevable.

# %% [markdown] tags=["solution"]
# ### Trame de correction (à confronter à vos propres résultats)
#
# | Constat | Diagnostic | Recommandation | Indicateur de suivi |
# |---|---|---|---|
# | Plus de la moitié des incidents se terminent en « clôture faux positif » dès le N1 | règles de détection trop bruyantes en amont | brancher le scoring de l'atelier 04 en pré-tri | part des faux positifs qualifiés en N1 |
# | La transition la plus coûteuse concentre plusieurs centaines d'heures cumulées | file d'attente entre niveaux, pas lenteur de l'acte | plage de prise en charge garantie, ou automatisation de l'enrichissement | temps cumulé de cette transition, mois par mois |
# | Les cas avec reprise durent plusieurs fois plus longtemps | information insuffisante transmise lors de l'escalade | modèle d'escalade imposant les éléments minimaux | part des cas avec au moins une reprise |
# | Les attentes hors heures ouvrables sont plusieurs fois supérieures | absence de couverture nocturne | astreinte ciblée sur les P1/P2 uniquement | délai de qualification des P1 la nuit |

# %% [markdown]
# ## 9. Synthèse et travail personnel
#
# **À retenir**
#
# 1. Le process mining part de trois colonnes seulement : **cas, activité, temps**.
# 2. La **découverte** produit un modèle à partir du réel ; la **conformité** le
#    confronte au prescrit ; la **performance** y ajoute le temps.
# 3. Le goulet d'étranglement est la transition au plus grand **temps cumulé**,
#    pas la plus lente.
# 4. Les **boucles de reprise** sont le meilleur indicateur de qualité d'un
#    processus, et le plus facile à expliquer à une direction.
# 5. Appliqué au SOC lui-même, il fournit des arguments **chiffrés et opposables**
#    pour l'organisation et le dimensionnement.
#
# > **Licence.** `pm4py` est distribué sous licence **AGPL v3**. Usage
# > pédagogique et recherche sans difficulté ; en contexte industriel, vérifier
# > la compatibilité avec la politique de votre organisation.
#
# **Travail personnel (≥ 4 h)**
#
# - Rédigez la note de recommandation de la section 8.
# - Comparez les modèles obtenus par `discover_petri_net_alpha`,
#   `discover_petri_net_inductive` et `discover_heuristics_net` sur le même
#   journal : lequel est le plus lisible ? le plus fidèle ? Pourquoi ces deux
#   qualités s'opposent-elles ?
# - **Transposition sécurité** : appliquez la même démarche au fichier
#   `evenements_systeme.csv` en prenant `hostname` comme cas et `type_evenement`
#   comme activité. Que révèle le modèle découvert ? Quelles en sont les limites ?
#
# **Suite :** atelier 08 — détection d'anomalies sur les flux réseau.
