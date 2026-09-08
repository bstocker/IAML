# ---
# Atelier 09 — Temps 1/3 : données non structurées
# ---

# %% [markdown]
# # Atelier 09 — Données non structurées : rapports d'incident, IoC et classification
#
# > **Compétence 3.1 — « prétraiter et analyser des données non structurées
# > (texte, images) pour obtenir un jeu de données exploitable »**
# > 2 h de TP, à placer en fin de Temps 1 ou dans le Temps 3.
#
# ## Objectifs
#
# 1. Extraire des **entités structurées** (IoC, identifiants ATT&CK, CVE) d'un
#    corpus de texte libre.
# 2. Construire une représentation vectorielle d'un texte (**sac de mots**,
#    **TF-IDF**) et en comprendre les limites.
# 3. Entraîner un **classifieur de texte** pour catégoriser automatiquement les
#    rapports d'incident.
# 4. Regrouper des documents sans étiquette (**partitionnement de texte**).
# 5. Alimenter le graphe de connaissances de l'atelier 03 avec ce qui a été
#    extrait — la boucle *texte → connaissance*.
#
# ## Pourquoi c'est central en cybersécurité
#
# L'essentiel de la connaissance cyber circule en **texte libre** : rapports
# d'incident, bulletins CERT, publications de la menace, tickets, échanges. Un SOC
# qui ne sait pas exploiter ce gisement se prive de la moitié de sa mémoire.

# %%
import re
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_predict, train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"
ALEA = 42

index = pd.read_csv(DATA / "rapports_index.csv")
index["texte"] = [
    (DATA / "rapports" / f).read_text(encoding="utf-8") for f in index["fichier"]
]
print(f"{len(index)} rapports d'incident")
print(index["type_incident"].value_counts().to_string())
print("\n--- Exemple ---")
print(index["texte"].iloc[0])

# %% [markdown]
# ## 1. Extraire des entités : les expressions régulières d'abord
#
# Avant tout apprentissage, une part importante de l'information d'un rapport de
# sécurité est **structurellement régulière** : adresses IP, empreintes, CVE,
# identifiants ATT&CK. Une expression régulière bien écrite y est plus fiable,
# plus rapide et plus explicable que n'importe quel modèle.

# %%
MOTIFS = {
    "adresse_ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "technique_attack": r"\bT\d{4}(?:\.\d{3})?\b",
    "domaine": r"\b(?:[a-z0-9-]+\.)+(?:example|com|net|org|fr)\b",
    "url_defangee": r"hxxps?://[^\s]+",
    "port": r"\bport\s+(\d{1,5})\b",
    "compte": r"\b[a-z]{2}user\d{3}\b",
}


def extraire(texte: str) -> dict:
    return {nom: sorted(set(re.findall(motif, texte)))
            for nom, motif in MOTIFS.items()}


exemple = extraire(index["texte"].iloc[0])
for nom, valeurs in exemple.items():
    if valeurs:
        print(f"{nom:18s} {valeurs}")

# %% [markdown]
# ### Exercice 1.1
#
# Appliquez l'extraction à tout le corpus et produisez :
#
# 1. le nombre d'IoC de chaque type ;
# 2. les 10 techniques ATT&CK les plus fréquemment citées ;
# 3. un tableau `case_id × technique` prêt à être injecté dans le graphe de
#    connaissances de l'atelier 03.
#
# **Attention aux faux positifs de la regex** : combien d'« adresses IP » extraites
# sont en réalité des numéros de version ou des dates ? Vérifiez.

# %% tags=["todo"]
# TODO : extraction sur tout le corpus, comptages, tableau de liaison.
extraits = None

# %% tags=["solution"]
extraits = index.copy()
for nom in MOTIFS:
    extraits[nom] = [extraire(t)[nom] for t in extraits["texte"]]

print("Volume d'IoC extraits :")
for nom in MOTIFS:
    total = sum(len(v) for v in extraits[nom])
    documents = int((extraits[nom].str.len() > 0).sum())
    print(f"  {nom:18s} {total:>5} occurrences dans {documents:>4} rapports")

techniques = Counter(t for liste in extraits["technique_attack"] for t in liste)
print("\nTechniques ATT&CK les plus citées :")
for t, n in techniques.most_common(10):
    print(f"  {t:12s} {n}")

liaison = (
    extraits[["case_id", "technique_attack"]]
    .explode("technique_attack").dropna()
    .rename(columns={"technique_attack": "technique"})
    .drop_duplicates()
)
print(f"\n{len(liaison)} liens (incident → technique) prêts pour le graphe.")

# --- Contrôle qualité des regex ---
ips = [ip for liste in extraits["adresse_ip"] for ip in liste]
valides = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split("."))]
print(f"\nContrôle : {len(ips)} chaînes captées comme IP, "
      f"{len(ips) - len(valides)} invalides (octet > 255).")
print("→ Une regex qui « marche » sur trois exemples produit du bruit à l'échelle.")
print("   En production : valider le format ET filtrer les plages non routables.")

# %% [markdown]
# ## 2. Vectoriser un texte
#
# Un modèle ne consomme pas du texte mais des nombres. Deux représentations
# classiques, à connaître avant tout modèle de langue.

# %%
compteur = CountVectorizer(lowercase=True, min_df=3, max_df=0.85,
                           token_pattern=r"[a-zà-ÿ]{3,}")
sac = compteur.fit_transform(index["texte"])
print(f"Sac de mots : {sac.shape[0]} documents × {sac.shape[1]} termes "
      f"({sac.nnz / np.prod(sac.shape):.1%} de la matrice est non nulle)")

frequences = pd.Series(np.asarray(sac.sum(axis=0)).ravel(),
                       index=compteur.get_feature_names_out()).sort_values(ascending=False)
print("\nTermes les plus fréquents (le problème du sac de mots) :")
print(frequences.head(12).to_string())

# %% [markdown]
# Les termes les plus fréquents sont les moins informatifs. **TF-IDF** corrige ce
# biais en pondérant chaque terme par sa rareté dans le corpus.

# %%
tfidf = TfidfVectorizer(lowercase=True, min_df=3, max_df=0.85,
                        token_pattern=r"[a-zà-ÿ]{3,}", sublinear_tf=True)
V = tfidf.fit_transform(index["texte"])
termes = tfidf.get_feature_names_out()

# Termes les plus discriminants pour chaque type d'incident
print("Termes de plus fort poids TF-IDF moyen, par type d'incident :\n")
for type_inc in sorted(index["type_incident"].unique()):
    masque = (index["type_incident"] == type_inc).to_numpy()
    moyennes = np.asarray(V[masque].mean(axis=0)).ravel()
    top = termes[np.argsort(-moyennes)[:7]]
    print(f"  {type_inc:26s} {', '.join(top)}")

# %% [markdown]
# ## 3. Classifier automatiquement les rapports
#
# **Cas d'usage** : un analyste rédige un rapport en texte libre ; le système
# propose la catégorie d'incident, pour alimenter les statistiques et le
# rattachement au référentiel.

# %% [markdown]
# ### Exercice 3.1
#
# Comparez trois classifieurs (`ComplementNB`, `LogisticRegression`, `LinearSVC`)
# sur une chaîne TF-IDF, en validation croisée. Affichez le rapport de
# classification du meilleur et sa matrice de confusion.
#
# `ComplementNB` est la variante de Bayes naïf adaptée aux classes déséquilibrées.

# %% tags=["todo"]
# TODO : trois Pipeline(TfidfVectorizer, classifieur), cross_val_predict, comparaison.

# %% tags=["solution"]
y = index["type_incident"]
candidats = {
    "Bayes naïf complémenté": ComplementNB(),
    "Régression logistique": LogisticRegression(max_iter=2000, C=5,
                                                class_weight="balanced",
                                                random_state=ALEA),
    "SVM linéaire": LinearSVC(C=1, class_weight="balanced", random_state=ALEA),
}

predictions = {}
for nom, classifieur in candidats.items():
    chaine = Pipeline([
        ("tfidf", TfidfVectorizer(min_df=2, max_df=.85, sublinear_tf=True,
                                  token_pattern=r"[a-zà-ÿ]{3,}")),
        ("classifieur", classifieur),
    ])
    p = cross_val_predict(chaine, index["texte"], y, cv=5)
    predictions[nom] = p
    print(f"{nom:26s} exactitude = {(p == y).mean():.1%}")

meilleur = max(predictions, key=lambda k: (predictions[k] == y).mean())
print(f"\n=== {meilleur} ===")
print(classification_report(y, predictions[meilleur], digits=3, zero_division=0))

# %%
etiquettes = sorted(y.unique())
mc = confusion_matrix(y, predictions[meilleur], labels=etiquettes)

fig, ax = plt.subplots(figsize=(7.5, 6))
im = ax.imshow(mc, cmap="Blues")
ax.set_xticks(range(len(etiquettes)))
ax.set_xticklabels(etiquettes, rotation=45, ha="right", fontsize=8)
ax.set_yticks(range(len(etiquettes)))
ax.set_yticklabels(etiquettes, fontsize=8)
for i in range(len(etiquettes)):
    for j in range(len(etiquettes)):
        if mc[i, j]:
            ax.text(j, i, mc[i, j], ha="center", va="center", fontsize=9,
                    color="white" if mc[i, j] > mc.max() / 2 else "black")
ax.set(xlabel="prédit", ylabel="réel", title=f"Matrice de confusion — {meilleur}")
fig.colorbar(im, ax=ax, shrink=.8)
plt.tight_layout()

# %% [markdown]
# > **Mise en garde méthodologique importante.** Nos rapports sont générés à
# > partir de gabarits : chaque type d'incident possède un vocabulaire propre et
# > très régulier. Une exactitude élevée est donc **attendue et peu significative**.
# >
# > Sur des rapports réellement rédigés par des analystes, on observerait :
# > du vocabulaire partagé entre catégories, des abréviations personnelles, des
# > fautes, des rapports multi-catégories, et une exactitude bien plus modeste.
# > **Ne transposez jamais un résultat obtenu sur des données synthétiques sans
# > le dire.**

# %% [markdown]
# ## 4. Regrouper sans étiquette
#
# Quand aucune catégorie n'existe — le cas d'un corpus de bulletins CTI — on
# regroupe. LSA (`TruncatedSVD` sur TF-IDF) réduit d'abord la dimension.

# %%
lsa = TruncatedSVD(n_components=20, random_state=ALEA)
L = lsa.fit_transform(V)
print(f"TF-IDF {V.shape[1]} dimensions → LSA {L.shape[1]} dimensions "
      f"({lsa.explained_variance_ratio_.sum():.0%} de variance conservée)")

partition = KMeans(n_clusters=6, n_init=20, random_state=ALEA).fit(L)
index["groupe"] = partition.labels_

# Interprétation : les termes les plus caractéristiques de chaque groupe.
for g in range(6):
    masque = partition.labels_ == g
    moyennes = np.asarray(V[masque].mean(axis=0)).ravel()
    mots = termes[np.argsort(-moyennes)[:6]]
    dominant = index.loc[masque, "type_incident"].value_counts()
    print(f"Groupe {g} ({masque.sum():>3} rapports) : {', '.join(mots)}")
    print(f"            type dominant : {dominant.index[0]} "
          f"({dominant.iloc[0]}/{masque.sum()})")

# %%
fig, ax = plt.subplots(figsize=(9, 6))
for type_inc in sorted(index["type_incident"].unique()):
    m = (index["type_incident"] == type_inc).to_numpy()
    ax.scatter(L[m, 0], L[m, 1], s=42, alpha=.75, label=type_inc)
ax.set(xlabel="composante LSA 1", ylabel="composante LSA 2",
       title="Corpus projeté par analyse sémantique latente\n"
             "(couleurs : type réel, non utilisé pour la projection)")
ax.legend(fontsize=8)
ax.grid(alpha=.3)
plt.tight_layout()

# %% [markdown]
# ## 5. Boucler : du texte vers le graphe de connaissances
#
# L'extraction n'a de valeur que si elle **alimente** quelque chose. Réinjectons
# les techniques extraites dans un graphe reliant incidents, techniques et actifs.

# %%
import networkx as nx

G = nx.Graph()
for _, r in index.iterrows():
    G.add_node(r["case_id"], type="incident", categorie=r["type_incident"])
for _, r in liaison.iterrows():
    G.add_node(r["technique"], type="technique")
    G.add_edge(r["case_id"], r["technique"], relation="observee_dans")

techniques_noeuds = [n for n, d in G.nodes(data=True) if d["type"] == "technique"]
degres = sorted(((t, G.degree(t)) for t in techniques_noeuds),
                key=lambda x: -x[1])
print(f"Graphe : {G.number_of_nodes()} nœuds, {G.number_of_edges()} arêtes\n")
print("Techniques les plus observées dans nos incidents :")
for t, d in degres[:10]:
    print(f"  {t:12s} {d} incidents")

# %% [markdown]
# ### Exercice 5.1 — la question qui justifie tout l'atelier
#
# Croisez les techniques extraites des rapports avec le **plan de détection** de
# l'atelier 03 : existe-t-il des techniques **réellement observées dans nos
# incidents** mais absentes de notre couverture de détection ?
#
# C'est l'argument le plus fort qu'un ingénieur SOC puisse produire : non pas
# « le MITRE dit que c'est important », mais « **c'est arrivé chez nous** ».

# %% tags=["todo"]
# TODO : charger data/alertes_siem.csv, récupérer les techniques couvertes par
#        au moins une règle, et faire la différence avec les techniques observées.

# %% tags=["solution"]
alertes = pd.read_csv(DATA / "alertes_siem.csv", usecols=["regle_id", "technique_attack"])
couvertes = set(alertes["technique_attack"].unique())
observees = Counter(liaison["technique"])

manquantes = [(t, n) for t, n in observees.most_common() if t not in couvertes]
print(f"{len(observees)} techniques observées dans les rapports · "
      f"{len(couvertes)} techniques couvertes par une règle\n")
print("Techniques OBSERVÉES dans nos incidents et NON couvertes :")
for t, n in manquantes[:12]:
    print(f"  {t:12s} citée dans {n:>3} rapports")

print(f"\n→ {len(manquantes)} techniques à instrumenter, justifiées par des faits")
print("  internes et non par un référentiel externe. C'est le meilleur")
print("  argumentaire possible pour un plan de détection.")

# %% [markdown]
# ## 6. Limites du sac de mots et suite logique
#
# | Limite | Conséquence | Réponse |
# |---|---|---|
# | L'ordre des mots est perdu | « bloqué par le pare-feu » = « pare-feu bloqué par » | n-grammes, modèles séquentiels |
# | Aucune notion de synonymie | « maliciel » ≠ « malware » ≠ « logiciel malveillant » | plongements lexicaux, modèles de langue |
# | Aucune négation | « aucune exfiltration constatée » vu comme « exfiltration » | analyse syntaxique, modèles contextuels |
# | Vocabulaire figé à l'apprentissage | un terme nouveau est ignoré | sous-mots (*BPE*), modèles pré-entraînés |
#
# > **Et les modèles de langue ?** Un modèle pré-entraîné réglé finement lèverait
# > la plupart de ces limites. Trois réserves à garder en tête dans un SOC :
# > le **coût** (calcul, latence par document), la **confidentialité** (un rapport
# > d'incident ne s'envoie pas à un service tiers sans analyse de risque), et
# > l'**explicabilité** (justifier une classification devant un auditeur).
# > Sur un corpus régulier comme des rapports gabarités, TF-IDF + régression
# > logistique reste souvent le meilleur rapport qualité/coût. Commencez toujours
# > par la référence simple.

# %% [markdown]
# ## 7. Synthèse et travail personnel
#
# **À retenir**
#
# 1. Une part majeure de l'information d'un texte de sécurité est **régulière** :
#    commencez par les expressions régulières, validez-les à l'échelle.
# 2. TF-IDF corrige le biais de fréquence du sac de mots ; c'est la référence à
#    battre avant de sortir l'artillerie lourde.
# 3. Une exactitude élevée sur des données synthétiques ne prouve rien. **Dites-le.**
# 4. L'extraction n'a de valeur que si elle **alimente** une structure de
#    connaissance exploitable.
# 5. « Observé chez nous » est un argument plus fort que « recommandé par un
#    référentiel ».
#
# **Travail personnel (≥ 4 h)**
#
# - Ajoutez l'extraction des **dates** et construisez une chronologie d'incident
#   automatique à partir du texte.
# - Écrivez un détecteur de **négation** simple (fenêtre de 5 mots après
#   « aucun », « pas de », « sans ») et mesurez combien d'IoC extraits sont en
#   réalité niés dans le texte.
# - Comparez votre classifieur TF-IDF à une approche par plongements
#   (`sentence-transformers`, à installer séparément) sur les mêmes plis de
#   validation croisée. Le gain justifie-t-il le coût ?
#
# **Suite :** atelier 10 — mettre un modèle en production et le surveiller.
