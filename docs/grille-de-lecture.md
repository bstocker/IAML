# Grille de lecture critique — IA et cybersécurité

> Grille à remplir pour la **note de lecture** du Temps 5. Toute réponse doit
> renvoyer à un élément précis de l'article (section, figure, tableau, page).
> Une case « non précisé dans l'article » est une **réponse valide et
> informative** : ce sont ces cases qui fondent la critique.

---

## 0. Protocole de découverte

| Champ | Votre réponse |
|---|---|
| Base interrogée | |
| Équation de recherche exacte | |
| Date d'interrogation | |
| Nombre de résultats | |
| Rang de l'article dans les résultats | |
| Pourquoi celui-ci ? | |

---

## 1. Identification

| Question | Réponse | Élément d'appui |
|---|---|---|
| Référence complète (norme au choix, cohérente) | | |
| DOI ou URL pérenne | | |
| Type : revue à comité de lecture / conférence / préprint / rapport | | |
| Lieu de publication — reconnu dans le domaine ? (vérifier sur DBLP) | | |
| Année, et âge par rapport à l'état de l'art actuel | | |
| Affiliations : académique, industrielle, mixte | | |
| Financement et conflits d'intérêts déclarés | | |

> **Vigilance.** Un article publié par l'éditeur d'une solution commerciale n'est
> pas disqualifié, mais son évaluation comparative demande un examen renforcé.

---

## 2. Problème et positionnement

| Question | Réponse | Élément d'appui |
|---|---|---|
| Quelle question de **sécurité** est réellement posée ? | | |
| Quelle est l'unité d'observation ? | | |
| De quelle famille relève le problème : supervisé / non supervisé / DA / KM ? | | |
| Ce cadrage est-il justifié par les auteurs, ou implicite ? | | |
| L'état de l'art cité est-il à jour (< 3 ans) et pertinent ? | | |
| Qu'est-ce qui est annoncé comme nouveau ? | | |

---

## 3. Données — la section la plus discriminante

| Question | Réponse | Élément d'appui |
|---|---|---|
| Nom du ou des jeux de données | | |
| Public / synthétique / interne non partagé | | |
| Année de production des données | | |
| Volumétrie (observations, période couverte) | | |
| Taux de positifs réel | | |
| Comment les étiquettes ont-elles été produites ? Par qui ? | | |
| Le jeu est-il représentatif d'un environnement opérationnel actuel ? | | |
| Prétraitement décrit assez précisément pour être reproduit ? | | |

> **Signal d'alerte.** KDD'99 et NSL-KDD décrivent un trafic des années 1990.
> Un résultat obtenu sur ces jeux ne dit **rien** d'un réseau contemporain.
> CIC-IDS2017 et UNSW-NB15 sont plus récents mais restent des captures de
> laboratoire, sans la diversité ni le bruit d'un réseau réel.

---

## 4. Méthode

| Question | Réponse | Élément d'appui |
|---|---|---|
| Famille d'algorithmes retenue et justification | | |
| Caractéristiques utilisées — liste complète disponible ? | | |
| **Chaque caractéristique est-elle disponible au moment de la décision ?** | | |
| Partition apprentissage/test : temporelle ou aléatoire ? | | |
| Les données sont-elles horodatées ? Si oui, une partition aléatoire est-elle justifiée ? | | |
| Hyperparamètres : réglés sur un jeu de validation distinct du test ? | | |
| Gestion du déséquilibre de classes | | |

> **Les deux fautes les plus fréquentes** : la partition aléatoire sur données
> temporelles, et la fuite par une variable postérieure à la décision. Cherchez-les
> systématiquement — elles suffisent à invalider les résultats annoncés.

---

## 5. Évaluation

| Question | Réponse | Élément d'appui |
|---|---|---|
| Métriques rapportées | | |
| Sont-elles adaptées au déséquilibre ? (AUC-PR, précision @ K) | | |
| Le **taux de base** est-il donné ? | | |
| Une **référence naïve** est-elle évaluée ? (règle à seuil, classe majoritaire) | | |
| Variabilité rapportée ? (écarts-types, intervalles, plusieurs graines) | | |
| Comparaison à d'autres travaux **sur le même jeu de données** ? | | |
| Coût opérationnel traduit ? (alertes/jour, temps analyste, ETP) | | |
| Le seuil de décision est-il justifié ? | | |

---

## 6. Reproductibilité

| Question | Réponse | Élément d'appui |
|---|---|---|
| Code disponible ? URL, licence, état | | |
| Données disponibles ou reconstituables | | |
| Graines aléatoires fixées | | |
| Versions des bibliothèques précisées | | |
| Auriez-vous assez d'éléments pour refaire l'expérience ? | | |

---

## 7. Limites et menaces à la validité

| Question | Réponse | Élément d'appui |
|---|---|---|
| Les auteurs discutent-ils leurs propres limites ? | | |
| Robustesse aux exemples adverses évoquée ? | | |
| Dérive de distribution dans le temps prise en compte ? | | |
| Passage à l'échelle discuté (volumétrie réelle d'un SOC) ? | | |
| Explicabilité pour l'analyste abordée ? | | |
| Enjeux de confidentialité / conformité abordés ? | | |

---

## 8. Transférabilité

| Question | Réponse |
|---|---|
| Que faudrait-il pour appliquer cette méthode au SOC synthétique des ateliers ? | |
| Quelles données faudrait-il collecter et ne collectons-nous pas ? | |
| Quel volume d'alertes cette méthode produirait-elle chez nous ? | |
| Quelle procédure de réponse faudrait-il associer ? | |
| Quel serait le coût de mise en œuvre, et pour quel bénéfice attendu ? | |

---

## 9. Le test des 5 minutes

Avant toute lecture approfondie, cherchez ces cinq éléments. Si **trois d'entre
eux manquent**, l'article ne peut pas être évalué — et donc pas cité comme preuve.

| # | Élément | Présent ? | Où ? |
|---|---|---|---|
| 1 | Nom du jeu de données | ☐ | |
| 2 | Taux de positifs / taux de base | ☐ | |
| 3 | Type de partition (temporelle ou aléatoire) | ☐ | |
| 4 | Métrique principale et sa justification | ☐ | |
| 5 | Référence naïve de comparaison | ☐ | |

---

## 10. Synthèse

**Deux forces**, chacune adossée à un élément précis :
1.
2.

**Deux faiblesses**, chacune adossée à un élément précis :
1.
2.

**Une expérience de vérification.** Décrivez — et si possible réalisez sur les
jeux de données des ateliers — une expérience simple qui testerait une des
affirmations de l'article. Précisez : l'affirmation testée, le protocole, le
résultat attendu si l'affirmation est vraie, le résultat obtenu.

**Recommandation en une phrase** : cet article mérite-t-il d'être cité dans un
état de l'art ? Pour quoi exactement ?

---

## Note méthodologique obligatoire

Indiquez si vous avez utilisé un assistant conversationnel, et pour quoi
(traduction, reformulation, explication d'un concept, suggestion de pistes).
C'est un usage légitime, à condition d'être déclaré.

**Chaque référence citée doit avoir été ouverte et lue par vous, et son DOI
vérifié sur le site de l'éditeur.**
