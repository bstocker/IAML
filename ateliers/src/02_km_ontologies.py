# ---
# Atelier 02 — Temps 2 : Gestion des connaissances (1/2)
# ---

# %% [markdown]
# # Atelier 02 — KM 1 : modéliser la connaissance cyber (ontologies, RDF, SPARQL)
#
# > **Temps 2 — Gestion des connaissances** (2 UT sur 4) — 2 × 2 h de TP
#
# ## Objectifs
#
# 1. Distinguer **donnée**, **information**, **connaissance** — et voir ce que
#    cette distinction change concrètement dans un SOC.
# 2. Comprendre les **langages semi-formels** du web sémantique : RDF, RDFS, OWL.
# 3. Construire une **ontologie cyber** minimale et la peupler avec les données
#    du SOC (actifs, vulnérabilités, techniques ATT&CK).
# 4. Interroger cette base de connaissances en **SPARQL** et exploiter
#    l'**inférence** pour déduire des faits qui n'ont jamais été écrits.
#
# ## Pourquoi un SOC a besoin d'ontologies
#
# Un SIEM répond à *« combien d'alertes sur ce serveur ? »*. Il ne sait pas
# répondre à *« quels de nos actifs sont exposés à une technique employée par un
# groupe qui cible notre secteur, et pour laquelle nous n'avons ni détection ni
# mesure d'atténuation ? »* — parce que cette question traverse cinq référentiels
# hétérogènes. C'est un problème de **représentation des connaissances**, pas de
# recherche dans des journaux.

# %%
import json
from pathlib import Path

import pandas as pd
from rdflib import Graph, Literal, Namespace, RDF, RDFS, OWL, XSD, URIRef
from rdflib.namespace import DCTERMS

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"

# %% [markdown]
# ## 1. Donnée, information, connaissance
#
# | Niveau | Exemple | Support |
# |---|---|---|
# | **Donnée** | `4625, srv-0042, 03:14:07` | ligne de journal |
# | **Information** | « 12 échecs d'authentification sur srv-0042 cette nuit » | agrégation, requête |
# | **Connaissance** | « srv-0042 est un contrôleur de domaine ; les échecs répétés sur un contrôleur relèvent de T1110 ; T1110 est atténuée par M1032 que nous n'avons pas déployée ici » | **modèle formel de relations** |
#
# Le passage information → connaissance suppose des **entités**, des **relations
# typées** et des **règles**. C'est précisément ce que fournit RDF.

# %% [markdown]
# ## 2. RDF : tout est un triplet
#
# `(sujet, prédicat, objet)`. Rien d'autre. Cette simplicité est ce qui permet de
# fusionner des référentiels qui n'ont pas été conçus ensemble.

# %%
CYBER = Namespace("https://iaml.example/ontologie/cyber#")
RES = Namespace("https://iaml.example/ressource/")

g = Graph()
g.bind("cyber", CYBER)
g.bind("res", RES)
g.bind("owl", OWL)
g.bind("dcterms", DCTERMS)

# Un premier fait, écrit à la main.
g.add((RES["srv-0042"], RDF.type, CYBER.Serveur))
g.add((RES["srv-0042"], CYBER.hebergeService, Literal("annuaire")))
g.add((RES["srv-0042"], CYBER.criticite, Literal(4, datatype=XSD.integer)))

print(g.serialize(format="turtle"))

# %% [markdown]
# ## 3. RDFS et OWL : donner un sens aux relations
#
# Un graphe de triplets sans schéma n'est qu'un tableau déguisé. Le **schéma**
# (RDFS/OWL) déclare les classes, leur hiérarchie, le domaine et la portée des
# propriétés — et rend possible l'**inférence**.

# %%
def definir_ontologie(g: Graph) -> Graph:
    """Ontologie cyber minimale : 7 classes, 8 propriétés."""
    # --- Classes ---------------------------------------------------------
    classes = {
        "Actif": "Tout élément du système d'information sous responsabilité du SOC",
        "Serveur": "Actif de type serveur",
        "PosteTravail": "Actif de type poste de travail utilisateur",
        "Vulnerabilite": "Faiblesse identifiée d'un produit (CVE)",
        "Technique": "Technique adverse au sens MITRE ATT&CK",
        "Tactique": "Objectif tactique poursuivi par l'adversaire",
        "Mitigation": "Mesure d'atténuation applicable à une technique",
        "Groupe": "Groupe d'attaquants suivi par la CTI",
        "RegleDetection": "Règle de détection déployée dans le SIEM",
    }
    for nom, commentaire in classes.items():
        g.add((CYBER[nom], RDF.type, OWL.Class))
        g.add((CYBER[nom], RDFS.label, Literal(nom, lang="fr")))
        g.add((CYBER[nom], RDFS.comment, Literal(commentaire, lang="fr")))

    # --- Hiérarchie : c'est elle qui portera l'inférence -------------------
    g.add((CYBER.Serveur, RDFS.subClassOf, CYBER.Actif))
    g.add((CYBER.PosteTravail, RDFS.subClassOf, CYBER.Actif))

    # --- Propriétés (domaine → portée) ------------------------------------
    proprietes = [
        ("estAffectePar", CYBER.Actif, CYBER.Vulnerabilite),
        ("exploitePar", CYBER.Vulnerabilite, CYBER.Technique),
        ("relevantDe", CYBER.Technique, CYBER.Tactique),
        ("attenuePar", CYBER.Technique, CYBER.Mitigation),
        ("utilisePar", CYBER.Technique, CYBER.Groupe),
        ("detectePar", CYBER.Technique, CYBER.RegleDetection),
        ("sousTechniqueDe", CYBER.Technique, CYBER.Technique),
    ]
    for nom, domaine, portee in proprietes:
        g.add((CYBER[nom], RDF.type, OWL.ObjectProperty))
        g.add((CYBER[nom], RDFS.domain, domaine))
        g.add((CYBER[nom], RDFS.range, portee))

    for nom, portee in [("criticite", XSD.integer), ("scoreCVSS", XSD.decimal),
                        ("hebergeService", XSD.string), ("zone", XSD.string),
                        ("identifiantMitre", XSD.string)]:
        g.add((CYBER[nom], RDF.type, OWL.DatatypeProperty))
        g.add((CYBER[nom], RDFS.range, portee))

    return g


g = definir_ontologie(g)
print(f"{len(g)} triplets après définition de l'ontologie")

# %% [markdown]
# ## 4. Peupler l'ontologie avec les données du SOC
#
# C'est l'étape d'**instanciation** : on transforme des lignes de CSV en individus
# de l'ontologie. Elle est fastidieuse et c'est normal — c'est là que se joue la
# qualité de la base de connaissances.

# %%
assets = pd.read_csv(DATA / "assets.csv")
cve = pd.read_csv(DATA / "cve.csv")
expo = pd.read_csv(DATA / "vulnerabilites_hotes.csv")
attack = json.loads((DATA / "attack" / "attack_subset.json").read_text(encoding="utf-8"))

# On travaille sur un sous-ensemble pour garder le graphe lisible en TP.
assets_ech = assets[assets["criticite"] >= 3].head(60)
expo_ech = expo[expo["asset_id"].isin(assets_ech["asset_id"]) & ~expo["corrigee"]]
cve_ech = cve[cve["cve_id"].isin(expo_ech["cve_id"])]

print(f"{len(assets_ech)} actifs, {len(cve_ech)} vulnérabilités non corrigées, "
      f"{len(expo_ech)} expositions")

# %%
def peupler_actifs(g: Graph, assets: pd.DataFrame) -> Graph:
    for _, a in assets.iterrows():
        uri = RES[a["hostname"]]
        classe = CYBER.PosteTravail if a["zone"] == "poste_travail" else CYBER.Serveur
        g.add((uri, RDF.type, classe))
        g.add((uri, RDFS.label, Literal(a["hostname"])))
        g.add((uri, CYBER.criticite, Literal(int(a["criticite"]), datatype=XSD.integer)))
        g.add((uri, CYBER.zone, Literal(a["zone"])))
    return g


def peupler_attack(g: Graph, attack: dict) -> Graph:
    for tac in attack["tactiques"]:
        uri = RES[tac["id"]]
        g.add((uri, RDF.type, CYBER.Tactique))
        g.add((uri, RDFS.label, Literal(tac["nom_fr"], lang="fr")))
        g.add((uri, CYBER.identifiantMitre, Literal(tac["id"])))

    court = {t["shortname"]: t["id"] for t in attack["tactiques"]}
    for tech in attack["techniques"]:
        uri = RES[tech["id"]]
        g.add((uri, RDF.type, CYBER.Technique))
        g.add((uri, RDFS.label, Literal(tech["nom"])))
        g.add((uri, CYBER.identifiantMitre, Literal(tech["id"])))
        for t in tech["tactiques"]:
            g.add((uri, CYBER.relevantDe, RES[court[t]]))
        if tech["sous_technique_de"]:
            g.add((uri, CYBER.sousTechniqueDe, RES[tech["sous_technique_de"]]))

    for m in attack["mitigations"]:
        g.add((RES[m["id"]], RDF.type, CYBER.Mitigation))
        g.add((RES[m["id"]], RDFS.label, Literal(m["nom"], lang="fr")))
    for gr in attack["groupes"]:
        g.add((RES[gr["id"]], RDF.type, CYBER.Groupe))
        g.add((RES[gr["id"]], RDFS.label, Literal(gr["nom"])))

    for rel in attack["relations"]:
        cible = RES[rel["technique"]]
        if rel["type"] == "attenue":
            g.add((cible, CYBER.attenuePar, RES[rel["mitigation"]]))
        elif rel["type"] == "utilise":
            g.add((cible, CYBER.utilisePar, RES[rel["groupe"]]))
    return g


g = peupler_actifs(g, assets_ech)
g = peupler_attack(g, attack)
print(f"{len(g)} triplets")

# %% [markdown]
# ### Exercice 4.1
#
# Complétez le peuplement avec les **vulnérabilités** :
#
# - chaque CVE de `cve_ech` devient un individu de classe `cyber:Vulnerabilite`,
#   portant son `cyber:scoreCVSS` et un `rdfs:label` ;
# - le lien `cyber:exploitePar` relie la CVE à la technique ATT&CK de la colonne
#   `technique_attack` ;
# - le lien `cyber:estAffectePar` relie l'actif à la CVE, en utilisant `expo_ech`
#   (attention : la clé y est `asset_id`, pas `hostname`).

# %% tags=["todo"]
def peupler_vulnerabilites(g, cve_df, expo_df, assets_df):
    # TODO : 1) les individus Vulnerabilite ; 2) exploitePar ; 3) estAffectePar
    return g


g = peupler_vulnerabilites(g, cve_ech, expo_ech, assets_ech)
print(f"{len(g)} triplets")

# %% tags=["solution"]
def peupler_vulnerabilites(g, cve_df, expo_df, assets_df):
    for _, c in cve_df.iterrows():
        uri = RES[c["cve_id"]]
        g.add((uri, RDF.type, CYBER.Vulnerabilite))
        g.add((uri, RDFS.label, Literal(c["cve_id"])))
        g.add((uri, CYBER.scoreCVSS,
               Literal(float(c["cvss_v3"]), datatype=XSD.decimal)))
        g.add((uri, DCTERMS.description, Literal(c["description"], lang="fr")))
        g.add((uri, CYBER.exploitePar, RES[c["technique_attack"]]))

    # La correspondance asset_id → hostname est indispensable : les URI d'actifs
    # ont été construites sur le hostname.
    id_vers_hote = dict(zip(assets_df["asset_id"], assets_df["hostname"]))
    for _, e in expo_df.iterrows():
        hote = id_vers_hote.get(e["asset_id"])
        if hote is None:
            continue
        g.add((RES[hote], CYBER.estAffectePar, RES[e["cve_id"]]))
    return g


g = peupler_vulnerabilites(g, cve_ech, expo_ech, assets_ech)
print(f"{len(g)} triplets")

# %% [markdown]
# ## 5. Interroger en SPARQL
#
# SPARQL est à RDF ce que SQL est aux tables — à une différence majeure près :
# on interroge un **motif de graphe**, ce qui permet de traverser des relations
# sans écrire de jointure.

# %%
def sparql(g: Graph, requete: str) -> pd.DataFrame:
    """Exécute une requête SELECT et renvoie un DataFrame."""
    resultats = g.query(requete)
    return pd.DataFrame(
        [[str(v) if v is not None else None for v in ligne] for ligne in resultats],
        columns=[str(v) for v in resultats.vars],
    )


REQ_ACTIFS_CRITIQUES = """
PREFIX cyber: <https://iaml.example/ontologie/cyber#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?actif ?zone ?criticite
WHERE {
  ?a a cyber:Serveur ;
     rdfs:label      ?actif ;
     cyber:zone      ?zone ;
     cyber:criticite ?criticite .
  FILTER (?criticite >= 4)
}
ORDER BY DESC(?criticite) ?actif
LIMIT 10
"""
sparql(g, REQ_ACTIFS_CRITIQUES)

# %% [markdown]
# ### La requête qu'un SIEM ne sait pas écrire
#
# *« Quels actifs sont exposés à une technique utilisée par APT29, et cette
# technique dispose-t-elle d'une mesure d'atténuation connue ? »*
#
# Cette question traverse quatre relations : actif → CVE → technique → groupe, et
# technique → mitigation. En SQL, c'est cinq jointures et un schéma figé. En
# SPARQL, c'est un motif.

# %%
REQ_CHEMIN_MENACE = """
PREFIX cyber: <https://iaml.example/ontologie/cyber#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?actif ?cve ?score ?technique ?mitigation
WHERE {
  ?a  cyber:estAffectePar ?v ;
      rdfs:label          ?actif .
  ?v  cyber:exploitePar   ?t ;
      rdfs:label          ?cve ;
      cyber:scoreCVSS     ?score .
  ?t  rdfs:label          ?technique ;
      cyber:utilisePar    ?groupe .
  ?groupe rdfs:label "APT29" .
  OPTIONAL { ?t cyber:attenuePar ?m . ?m rdfs:label ?mitigation }
  FILTER (?score >= 7.0)
}
ORDER BY DESC(?score)
LIMIT 15
"""
sparql(g, REQ_CHEMIN_MENACE)

# %% [markdown]
# ### Exercice 5.1
#
# Écrivez la requête qui répond à : *« quelles techniques affectant nos actifs
# n'ont **aucune** mitigation déclarée ? »* — autrement dit, notre angle mort.
#
# Indication : `FILTER NOT EXISTS { ... }`.

# %% tags=["todo"]
REQ_ANGLES_MORTS = """
PREFIX cyber: <https://iaml.example/ontologie/cyber#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?technique
WHERE {
  # TODO
}
"""
# sparql(g, REQ_ANGLES_MORTS)

# %% tags=["solution"]
REQ_ANGLES_MORTS = """
PREFIX cyber: <https://iaml.example/ontologie/cyber#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?identifiant ?technique (COUNT(DISTINCT ?a) AS ?nb_actifs)
WHERE {
  ?a cyber:estAffectePar ?v .
  ?v cyber:exploitePar   ?t .
  ?t rdfs:label              ?technique ;
     cyber:identifiantMitre  ?identifiant .
  FILTER NOT EXISTS { ?t cyber:attenuePar ?m }
}
GROUP BY ?identifiant ?technique
ORDER BY DESC(?nb_actifs)
"""
angles_morts = sparql(g, REQ_ANGLES_MORTS)
print("Techniques exploitables sur nos actifs et sans mitigation déclarée :")
angles_morts

# %% [markdown]
# ## 6. L'inférence : déduire ce qui n'est pas écrit
#
# Nous n'avons **jamais** écrit qu'un serveur est un actif : nous avons écrit que
# `Serveur` est une sous-classe d'`Actif`. Un moteur d'inférence RDFS en tire les
# conséquences et matérialise les triplets manquants.

# %%
import owlrl

REQ_TOUS_ACTIFS = """
PREFIX cyber: <https://iaml.example/ontologie/cyber#>
SELECT (COUNT(DISTINCT ?a) AS ?nb) WHERE { ?a a cyber:Actif }
"""

print("Avant inférence — individus de type cyber:Actif :",
      sparql(g, REQ_TOUS_ACTIFS).iloc[0, 0])

g_inf = Graph()
for t in g:
    g_inf.add(t)
owlrl.DeductiveClosure(owlrl.RDFS_Semantics).expand(g_inf)

print("Après inférence — individus de type cyber:Actif :",
      sparql(g_inf, REQ_TOUS_ACTIFS).iloc[0, 0])
print(f"\nTriplets : {len(g):,} → {len(g_inf):,} "
      f"(+{len(g_inf) - len(g):,} déduits)")

# %% [markdown]
# > **Ce que cela change dans un SOC.** Une règle métier écrite une seule fois
# > (« tout serveur est un actif », « toute sous-technique hérite de la tactique de
# > sa technique parente ») se propage automatiquement à l'ensemble de la base.
# > C'est ce qui permet de faire évoluer un référentiel sans réécrire les requêtes.

# %% [markdown]
# ### Exercice 6.1 — une règle métier propagée par inférence
#
# Déclarez `cyber:sousTechniqueDe` comme propriété **transitive**
# (`OWL.TransitiveProperty`) puis, avec `owlrl.OWLRL_Semantics`, vérifiez qu'une
# sous-sous-technique est bien reliée à sa technique racine.
#
# Puis discutez : quelles autres propriétés de votre modèle mériteraient d'être
# déclarées transitives, symétriques ou inverses ? Quel risque y a-t-il à en
# déclarer trop ?

# %% tags=["todo"]
# TODO : ajouter la déclaration OWL puis relancer une clôture déductive OWL-RL.

# %% tags=["solution"]
g2 = Graph()
for t in g:
    g2.add(t)
g2.add((CYBER.sousTechniqueDe, RDF.type, OWL.TransitiveProperty))

# Chaîne artificielle T1059.001 → T1059 pour observer la propagation.
owlrl.DeductiveClosure(owlrl.OWLRL_Semantics).expand(g2)

REQ_HIERARCHIE = """
PREFIX cyber: <https://iaml.example/ontologie/cyber#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?fille ?parente WHERE {
  ?f cyber:sousTechniqueDe ?p .
  ?f cyber:identifiantMitre ?fille .
  ?p cyber:identifiantMitre ?parente .
} ORDER BY ?fille LIMIT 12
"""
print(f"Triplets après clôture OWL-RL : {len(g2):,}")
sparql(g2, REQ_HIERARCHIE)

# %% [markdown] tags=["solution"]
# **Éléments de discussion.**
# `attenuePar` gagnerait une propriété inverse `attenue` pour naviguer dans les
# deux sens sans dupliquer les faits. `sousTechniqueDe` est naturellement
# transitive. En revanche, déclarer trop d'axiomes a deux coûts : l'explosion
# combinatoire de la clôture déductive (le nombre de triplets peut être multiplié
# par 10 à 100 sur un graphe réel), et surtout la production de **fausses
# déductions** si la modélisation initiale est approximative — une erreur de
# modélisation se propage alors à toute la base.

# %% [markdown]
# ## 7. Sauvegarder la base de connaissances

# %%
SORTIE = RACINE / "artifacts"
SORTIE.mkdir(exist_ok=True)
g.serialize(destination=SORTIE / "base_connaissances.ttl", format="turtle")
print(f"Base sauvegardée : {SORTIE / 'base_connaissances.ttl'} "
      f"({(SORTIE / 'base_connaissances.ttl').stat().st_size / 1024:.0f} ko, "
      f"{len(g):,} triplets)")

# %% [markdown]
# ## 8. Synthèse et travail personnel
#
# **À retenir**
#
# 1. RDF réduit toute connaissance à des triplets ; c'est cette uniformité qui
#    permet de **fusionner des référentiels hétérogènes** sans schéma commun préalable.
# 2. RDFS/OWL ajoutent la sémantique : hiérarchies, domaines, portées, axiomes.
#    Sans schéma, un graphe n'est qu'un tableau compliqué.
# 3. SPARQL interroge des **motifs de graphe** : les questions transversales
#    coûteuses en SQL deviennent naturelles.
# 4. L'inférence matérialise les conséquences des axiomes — puissance réelle,
#    mais qui amplifie aussi les erreurs de modélisation.
#
# **Limite honnête de cette approche.** Construire et maintenir une ontologie
# coûte cher en temps d'expert. Elle se justifie quand la connaissance est
# **stable, partagée et transversale** (référentiels de menace, inventaires). Pour
# des données volatiles et volumineuses, un graphe de propriétés (atelier 03) ou
# une base classique reste plus adapté.
#
# **Travail personnel (≥ 4 h)**
#
# - Étendez l'ontologie avec la classe `RegleDetection` et la propriété
#   `detectePar`, en la peuplant depuis les règles du fichier `alertes_siem.csv`
#   (colonnes `regle_id`, `technique_attack`).
# - Écrivez la requête SPARQL qui liste les techniques **couvertes par aucune
#   règle** et **portées par des CVE non corrigées** : c'est le plan de
#   développement de détection du trimestre.
# - Lecture : les spécifications W3C RDF 1.1 Primer et SPARQL 1.1 (sections 1 à 3).
#
# **Suite :** atelier 03 — le même corpus vu comme un graphe de propriétés, pour
# calculer des priorités de détection.
