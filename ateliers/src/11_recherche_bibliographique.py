# ---
# Atelier 11 — Temps 5 : Recherche bibliographique
# ---

# %% [markdown]
# # Atelier 11 — Recherche bibliographique : évaluer l'état de l'art
#
# > **Temps 5 — Recherche bibliographique : IA/ML pour la cyber** (4 UT)
# > Tutorat par un enseignant-chercheur. Cet atelier outille la démarche ; il ne
# > la remplace pas.
#
# ## Objectifs
#
# 1. Construire une **équation de recherche** et un protocole reproductible.
# 2. **Cribler** un corpus efficacement (titre → résumé → texte intégral).
# 3. Appliquer une **grille de lecture critique** adaptée à l'IA pour la sécurité.
# 4. Repérer les **défauts méthodologiques récurrents** de la littérature du
#    domaine — c'est la compétence la plus transférable de tout le cours.
# 5. Produire une **synthèse** et une fiche de lecture défendables.
#
# ## Pourquoi ce temps existe
#
# > *« On ne peut pas tout connaître ; on apprend à apprendre. »*
#
# Les outils vus dans les ateliers 01 à 10 seront périmés. La capacité à lire un
# article de 2029 et à décider en une heure s'il mérite votre attention ne le sera
# pas. C'est l'objectif ici.

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

RACINE = Path.cwd()
while not (RACINE / "data").exists() and RACINE != RACINE.parent:
    RACINE = RACINE.parent
DATA = RACINE / "data"

# %% [markdown]
# ## 1. Construire une équation de recherche
#
# Une recherche bibliographique n'est pas « taper des mots-clés ». C'est un
# **protocole**, écrit avant de commencer, et reproductible par un tiers.
#
# ### 1.1 Le protocole (à rédiger avant toute recherche)
#
# | Rubrique | Exemple |
# |---|---|
# | **Question** | Les méthodes de réduction des faux positifs par apprentissage supervisé sont-elles évaluées de façon réaliste en contexte SOC ? |
# | **Population** | alertes SIEM/EDR, journaux de sécurité en environnement opérationnel |
# | **Intervention** | apprentissage supervisé, priorisation, triage |
# | **Comparateur** | règles de corrélation, tri par sévérité |
# | **Résultat mesuré** | précision, rappel, charge analyste |
# | **Période** | 2021–2026 |
# | **Langues** | anglais, français |
# | **Critères d'inclusion** | évaluation quantitative ; jeu de données décrit |
# | **Critères d'exclusion** | pas d'évaluation ; jeu de données non identifiable ; article de vulgarisation |
#
# ### 1.2 Les bases à interroger
#
# | Base | Accès | Particularité |
# |---|---|---|
# | **Google Scholar** | libre | large, bruité, bon pour amorcer |
# | **arXiv** (cs.CR, cs.LG) | libre | préprints, très à jour, **non relus par les pairs** |
# | **HAL** | libre | production française, thèses |
# | **DBLP** | libre | métadonnées fiables, sert à vérifier le lieu de publication |
# | **IEEE Xplore / ACM DL** | abonnement | conférences de référence du domaine |
# | **Semantic Scholar** | libre + API | graphe de citations exploitable |
#
# ### 1.3 Une équation type
#
# ```
# ("intrusion detection" OR "security operations center" OR SIEM OR "alert triage")
# AND ("machine learning" OR "deep learning" OR "anomaly detection")
# AND ("false positive" OR precision OR "alert fatigue")
# AND PUBYEAR > 2020
# ```
#
# > **Consigne de traçabilité.** Notez pour chaque base : la date d'interrogation,
# > l'équation exacte, le nombre de résultats. Sans cela, votre revue n'est pas
# > reproductible — et une revue non reproductible n'a pas de valeur scientifique.

# %% [markdown]
# ## 2. Cribler un corpus
#
# > ### ⚠ Avertissement sur le corpus fourni
# >
# > Le fichier `corpus_fictif_pour_exercice.csv` est **entièrement inventé** :
# > titres, auteurs, résumés et lieux de publication. Tous les titres sont
# > préfixés par `[FICTIF]`.
# >
# > Il sert **uniquement** à s'entraîner à la mécanique du criblage sans
# > dépendre d'un accès réseau. **Aucune de ces références ne doit apparaître
# > dans un travail rendu.** Votre note de lecture porte sur de vrais articles,
# > que vous irez chercher vous-même dans les bases listées ci-dessus.

# %%
corpus = pd.read_csv(DATA / "corpus_fictif_pour_exercice.csv")
print(f"{len(corpus)} références FICTIVES")
print(corpus[["domaine", "type_publication"]].value_counts().to_string())
corpus.head(3)[["ref_id", "titre", "annee", "venue", "domaine"]]

# %% [markdown]
# ### Le criblage en trois passes
#
# | Passe | Support | Temps par référence | Taux de rejet typique |
# |---|---|---|---|
# | 1 | titre | 5 s | 60–80 % |
# | 2 | résumé | 60 s | 50 % du reste |
# | 3 | texte intégral | 30–60 min | 30 % du reste |
#
# On ne lit intégralement que 5 à 10 % du corpus initial. **Le criblage n'est pas
# une perte de temps : c'est la compétence.**

# %% [markdown]
# ### Exercice 2.1
#
# Implémentez les deux premières passes sur le corpus fictif :
#
# - **passe 1** : conserver les références dont le domaine est ML ou DA et
#   l'année ≥ 2022 ;
# - **passe 2** : parmi celles-ci, écarter celles dont le jeu de données est
#   « privé/non publié » ou « non précisé » — critère d'exclusion du protocole.
#
# Affichez l'entonnoir (effectif après chaque passe).

# %% tags=["todo"]
# TODO : deux filtrages successifs, affichage de l'entonnoir.

# %% tags=["solution"]
passe0 = corpus
passe1 = passe0[passe0["domaine"].isin(["ML", "DA"]) & (passe0["annee"] >= 2022)]
passe2 = passe1[~passe1["jeu_de_donnees"].isin(["prive/non publie", "non precise"])]

etapes = [("Corpus initial", len(passe0)),
          ("Passe 1 — titre / métadonnées", len(passe1)),
          ("Passe 2 — résumé / critères d'exclusion", len(passe2))]
for libelle, n in etapes:
    print(f"{libelle:44s} {n:>4} références ({n / len(passe0):>5.0%})")

fig, ax = plt.subplots(figsize=(8, 3.2))
ax.barh([e[0] for e in etapes][::-1], [e[1] for e in etapes][::-1],
        color=["seagreen", "orange", "steelblue"])
for i, (_, n) in enumerate(etapes[::-1]):
    ax.text(n + 1, i, str(n), va="center")
ax.set(xlabel="nombre de références", title="Entonnoir de criblage")
plt.tight_layout()

# %% [markdown]
# ## 3. La grille de lecture critique
#
# Le document `docs/grille-de-lecture.md` contient la grille complète, à remplir
# pour la note de lecture. En voici la structure et les points de vigilance
# **propres à l'IA pour la cybersécurité**.

# %%
GRILLE = {
    "1. Identification": [
        "Référence complète, DOI, type (revue à comité de lecture, conférence, préprint)",
        "Lieu de publication : reconnu dans le domaine ? (vérifier sur DBLP)",
        "Conflits d'intérêts, financement, affiliation industrielle",
    ],
    "2. Problème et positionnement": [
        "Quelle question de sécurité est réellement posée ?",
        "Cette question relève-t-elle du supervisé, du non supervisé, de la DA, du KM ?",
        "L'état de l'art cité est-il à jour et pertinent ?",
    ],
    "3. Données — LE point critique": [
        "Jeu de données : public ? synthétique ? interne non partagé ?",
        "Période couverte, volumétrie, taux de positifs réel",
        "Comment les étiquettes ont-elles été produites, et par qui ?",
        "Le jeu est-il représentatif d'un environnement opérationnel ?",
    ],
    "4. Méthode": [
        "Le prétraitement est-il décrit assez précisément pour être reproduit ?",
        "Partition train/test : temporelle ou aléatoire ?",
        "Y a-t-il un risque de fuite de données ? (variables postérieures à la décision)",
        "Les hyperparamètres ont-ils été réglés sur le jeu de test ?",
    ],
    "5. Évaluation": [
        "Métriques adaptées au déséquilibre de classes ? (AUC-PR plutôt qu'exactitude)",
        "Une référence naïve est-elle donnée ? (règle simple, classe majoritaire)",
        "Intervalles de confiance ou variabilité entre exécutions ?",
        "Le coût opérationnel est-il traduit ? (alertes/jour, temps analyste)",
    ],
    "6. Reproductibilité": [
        "Code disponible ? données disponibles ? graines fixées ?",
        "Les résultats sont-ils comparés à d'autres travaux sur le même jeu ?",
    ],
    "7. Limites et menaces": [
        "Les auteurs discutent-ils leurs propres limites ?",
        "Robustesse aux exemples adverses évoquée ?",
        "La dérive de distribution dans le temps est-elle prise en compte ?",
    ],
    "8. Transférabilité": [
        "Que faudrait-il pour appliquer cela dans NOTRE SOC ?",
        "Quelles données devrions-nous collecter et ne collectons-nous pas ?",
    ],
}
for section, questions in GRILLE.items():
    print(f"\n{section}")
    for q in questions:
        print(f"   □ {q}")

# %% [markdown]
# ## 4. Les six défauts récurrents de la littérature « IA et cybersécurité »
#
# Ce sont les biais que l'on rencontre le plus souvent. Savoir les repérer permet
# d'éliminer un article en quelques minutes.
#
# | Défaut | Signe qui doit alerter | Question à poser |
# |---|---|---|
# | **1. Jeux de données obsolètes** | KDD'99, NSL-KDD, parfois CIC-IDS2017 | Le trafic de ce jeu ressemble-t-il à un réseau d'aujourd'hui ? |
# | **2. Métriques trompeuses** | « 99,8 % d'exactitude » | Quel est le taux de base ? L'AUC-PR est-elle donnée ? |
# | **3. Partition aléatoire sur des données temporelles** | pas de mention de découpe temporelle | Le modèle a-t-il vu le futur ? |
# | **4. Fuite de données** | variables issues du traitement de l'alerte | Cette variable existe-t-elle au moment de la décision ? |
# | **5. Absence de référence naïve** | comparaison uniquement à d'autres modèles complexes | Une règle à seuil ferait-elle aussi bien ? |
# | **6. Aucun coût opérationnel** | pas de volumétrie d'alertes | Combien d'alertes/jour ce système produit-il ? |
#
# > **Le test des 5 minutes.** Sur un article inconnu, cherchez dans l'ordre :
# > le nom du jeu de données, le taux de positifs, le type de partition, la
# > métrique principale, la référence de comparaison. Si trois de ces cinq
# > éléments sont absents, l'article ne peut pas être évalué — et donc pas cité
# > comme preuve.

# %% [markdown]
# ### Exercice 4.1 — appliquer le test des 5 minutes
#
# Utilisez les métadonnées du corpus fictif comme substituts et calculez, pour
# chaque référence, un **score de fiabilité méthodologique** sur 4 points :
#
# - +1 si le jeu de données est identifiable (ni privé, ni non précisé) ;
# - +1 si le code est disponible ;
# - +1 si une évaluation comparative est présente ;
# - +1 si l'article est relu par les pairs (pas un préprint).
#
# Puis observez la distribution du score, et croisez-la avec le nombre de
# citations.

# %% tags=["todo"]
# TODO : construire le score, tracer sa distribution, croiser avec nb_citations.

# %% tags=["solution"]
corpus["donnees_identifiables"] = ~corpus["jeu_de_donnees"].isin(
    ["prive/non publie", "non precise"]
)
corpus["relu_par_pairs"] = corpus["type_publication"] != "preprint"
corpus["score_fiabilite"] = (
    corpus["donnees_identifiables"].astype(int)
    + corpus["code_disponible"].astype(int)
    + corpus["evaluation_comparative"].astype(int)
    + corpus["relu_par_pairs"].astype(int)
)

print("Distribution du score de fiabilité :")
print(corpus["score_fiabilite"].value_counts().sort_index().to_string())
print(f"\nRéférences à 4/4 : {(corpus['score_fiabilite'] == 4).sum()} "
      f"({(corpus['score_fiabilite'] == 4).mean():.0%})")

fig, axes = plt.subplots(1, 2, figsize=(12, 4))
axes[0].bar(*zip(*sorted(corpus["score_fiabilite"].value_counts().items())),
            color="steelblue")
axes[0].set(xlabel="score de fiabilité méthodologique (sur 4)",
            ylabel="références", title="Qualité méthodologique du corpus")

par_score = corpus.groupby("score_fiabilite")["nb_citations"].agg(["mean", "size"])
axes[1].bar(par_score.index, par_score["mean"], color="indianred")
axes[1].set(xlabel="score de fiabilité", ylabel="citations moyennes",
            title="Les articles les plus cités sont-ils les plus rigoureux ?")
plt.tight_layout()

correlation = corpus[["score_fiabilite", "nb_citations"]].corr().iloc[0, 1]
print(f"\nCorrélation fiabilité / citations : {correlation:+.3f}")
print("""
À discuter en séance : sur un corpus réel, cette corrélation est souvent faible
voire nulle. Le nombre de citations mesure la visibilité et l'ancienneté, pas la
rigueur. Ne l'utilisez jamais comme critère de qualité — au mieux comme critère
de notoriété, à mentionner comme tel.
""")

# %% [markdown]
# ## 5. Cartographier un domaine
#
# Une revue de littérature produit une **carte**, pas une liste. Deux axes
# suffisent souvent : la maturité méthodologique et la période.

# %%
carte = (
    corpus.groupby(["domaine", "annee"])
    .agg(n=("ref_id", "size"), fiabilite=("score_fiabilite", "mean"))
    .reset_index()
)

fig, ax = plt.subplots(figsize=(10, 5))
for domaine, g in carte.groupby("domaine"):
    ax.scatter(g["annee"], g["fiabilite"], s=g["n"] * 45, alpha=.65, label=domaine)
ax.set(xlabel="année de publication", ylabel="score de fiabilité moyen",
       title="Carte du corpus — taille : nombre de références\n"
             "(données FICTIVES, à titre d'exercice)")
ax.set_xticks(sorted(corpus["annee"].unique()))
ax.legend(title="domaine")
ax.grid(alpha=.3)
plt.tight_layout()

print("Répartition par domaine et période :")
print(pd.crosstab(corpus["domaine"], corpus["annee"]).to_string())

# %% [markdown]
# ## 6. Le livrable : la note de lecture
#
# **Consigne (évaluée).** Choisissez **un** article réel de moins de 3 ans
# reliant IA et cybersécurité, trouvé par vous-même dans une des bases de la
# section 1.2, et validé par votre encadrant. Rédigez 2 à 3 pages :
#
# 1. **Référence complète** et protocole de découverte (base, équation, date).
# 2. **Résumé en 10 lignes** — dans vos mots, sans reprendre le résumé de l'article.
# 3. **Grille de lecture** de la section 3, remplie intégralement.
# 4. **Analyse critique** : au moins deux forces, deux faiblesses, et pour chacune
#    l'élément précis de l'article sur lequel vous vous appuyez (section, figure,
#    tableau).
# 5. **Le test des 5 minutes** appliqué et commenté.
# 6. **Transférabilité** : que faudrait-il pour appliquer cette méthode dans le
#    SOC synthétique des ateliers 01 à 10 ? Quelles données manquent ?
# 7. **Une expérience de vérification** : décrivez — et si possible réalisez sur
#    nos jeux de données — une expérience simple qui testerait une des affirmations
#    de l'article.
#
# Le point 7 est ce qui distingue une fiche de lecture d'un résumé. **Barème
# détaillé dans `docs/bareme.md`.**

# %% [markdown]
# ## 7. Hygiène de la recherche documentaire
#
# ### 7.1 Gérer ses références
#
# Utilisez un gestionnaire (**Zotero** est libre et suffit largement). Exportez en
# BibTeX. Ne recopiez jamais une référence à la main.
#
# ### 7.2 Sur l'usage des assistants conversationnels
#
# Un modèle de langue est utile pour **reformuler**, **traduire**, **expliquer un
# concept** ou **suggérer des pistes**. Il ne l'est pas pour établir des faits
# bibliographiques : la fabrication de références plausibles mais inexistantes est
# un mode d'échec documenté et fréquent.
#
# **Règle de travail pour ce cours :** toute référence citée doit avoir été
# **ouverte et lue** par vous, et son DOI vérifié sur le site de l'éditeur. Si
# vous avez utilisé un assistant, indiquez-le en note méthodologique — c'est
# l'usage attendu dans une démarche scientifique honnête, pas une faute.
#
# ### 7.3 Préprint n'est pas publication
#
# arXiv est indispensable pour la veille, mais un préprint n'a **pas** été relu
# par les pairs. Citez-le en le qualifiant comme tel, et vérifiez sur DBLP s'il a
# depuis été publié dans une revue ou une conférence.

# %% [markdown]
# ## 8. Organiser sa veille dans la durée
#
# Le cours se termine ; la technologie continue. Un dispositif de veille tenable
# repose sur trois strates.
#
# | Strate | Fréquence | Sources | Temps |
# |---|---|---|---|
# | **Signal faible** | quotidien | flux arXiv cs.CR, CERT-FR, blogs éditeurs | 10 min |
# | **Approfondissement** | hebdomadaire | 1 article lu intégralement avec la grille | 1 h |
# | **Synthèse** | trimestriel | qu'est-ce qui a changé ? qu'est-ce que j'abandonne ? | 2 h |
#
# > Le plus difficile n'est pas de commencer une veille, c'est de **décider ce
# > qu'on arrête de suivre**. Une veille qui ne jette rien devient un bruit de
# > fond qu'on finit par ignorer entièrement.

# %% [markdown]
# ## 9. Synthèse
#
# **À retenir**
#
# 1. Une recherche bibliographique est un **protocole écrit avant** de commencer,
#    et reproductible.
# 2. Le **criblage** en trois passes est la compétence centrale : on ne lit
#    intégralement que 5 à 10 % de ce qu'on trouve.
# 3. Six défauts récurrents permettent d'écarter rapidement un article :
#    jeu de données obsolète, métrique trompeuse, partition aléatoire, fuite,
#    absence de référence naïve, absence de coût opérationnel.
# 4. Le nombre de citations mesure la notoriété, pas la rigueur.
# 5. Une fiche de lecture se distingue d'un résumé par la **critique appuyée sur
#    des éléments précis** et par la proposition d'une **expérience de vérification**.
#
# **Ce que vous emportez de ce cours.** Les bibliothèques utilisées ici
# changeront. La démarche — poser le problème, choisir la famille
# d'apprentissage, se méfier des fuites, partitionner dans le temps, mesurer avec
# les bonnes métriques, traduire en coût opérationnel, surveiller la dérive et
# lire l'état de l'art de façon critique — ne changera pas.
