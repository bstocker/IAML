# Barèmes d'évaluation

L'évaluation suit les trois modalités de la fiche projet : contrôle continu,
mini-projet, note de lecture.

| Modalité | Poids proposé | Support |
|---|---|---|
| Contrôle continu — notebooks de TP | **30 %** | ateliers 01 à 11 |
| Mini-projet | **45 %** | [mini-projet.md](mini-projet.md) |
| Note de lecture (Temps 5) | **25 %** | [grille-de-lecture.md](grille-de-lecture.md) |

> Ces pondérations sont indicatives : ajustez-les selon le montage retenu
> ([planning.md](planning.md)). Si le Temps 5 est réduit à 3 UT, ramenez la note
> de lecture à 20 % au profit du mini-projet.

---

## 1. Contrôle continu — notebooks de TP (30 %)

Les notebooks complétés sont relevés après chaque bloc. On n'évalue pas la
justesse du code seule, mais **le raisonnement écrit autour**.

| Critère | Points | Ce qu'on regarde |
|---|---|---|
| Exercices de code complétés et fonctionnels | 8 | le notebook s'exécute de bout en bout |
| Réponses aux questions de discussion | 8 | rédigées, argumentées, pas des mots-clés |
| Interprétation des résultats | 6 | chaque sortie est commentée ; les résultats décevants sont analysés, pas masqués |
| Exercices d'extension (« travail personnel ») | 4 | au moins un par bloc |
| Qualité du code | 2 | lisible, nommage explicite, pas de copier-coller massif |
| **Total** | **28** | ramené à 30 % |

**Bonus (+2)** : une critique pertinente d'un choix fait dans le corrigé, ou la
mise en évidence d'une limite du jeu de données synthétique.

---

## 2. Mini-projet (45 %)

### 2.1 Rapport et notebook — 30 points

| Critère | Pts | Excellent | Insuffisant |
|---|---|---|---|
| **Cadrage** | 6 | famille d'apprentissage justifiée par la disponibilité des étiquettes et la nature de la question ; unité d'observation et métrique déduites du besoin | « on a fait de la classification parce que c'est ce qu'on a vu en cours » |
| **Données** | 4 | qualité analysée, biais identifiés et documentés, choix d'agrégation justifié | chargement brut sans examen |
| **Caractéristiques** | 5 | chaque variable est une hypothèse énoncée ; contrôle anti-fuite explicite | liste de colonnes sans justification |
| **Modélisation** | 4 | référence naïve évaluée ; protocole de validation adapté aux données | un seul modèle, aucune comparaison |
| **Évaluation** | 6 | métriques justifiées, variabilité mesurée, limites du protocole reconnues | une seule métrique, aucun taux de base |
| **Traduction opérationnelle** | 5 | volume d'alertes, temps analyste, seuil justifié, procédure de réponse | s'arrête au score |
| **Total** | **30** | | |

**Malus rédhibitoires** (annulent les points de la rubrique concernée) :

- fuite de données non détectée → −6 sur « Caractéristiques » ;
- partition aléatoire sur données horodatées sans justification → −4 sur « Modélisation » ;
- aucune référence naïve → −4 sur « Modélisation » ;
- notebook non exécutable → −5 sur l'ensemble.

### 2.2 Restitution orale — 15 points

| Critère | Pts | Ce qu'on regarde |
|---|---|---|
| Adaptation à l'auditoire | 4 | un responsable de SOC non spécialiste comprend l'enjeu et la décision |
| Clarté de la décision proposée | 4 | « voici ce que je recommande, voici ce que ça coûte, voici ce que ça rapporte » |
| Honnêteté sur les limites | 4 | ce que la solution ne fait pas est annoncé **par vous** |
| Réponses aux questions | 3 | savoir dire « je ne sais pas, voici comment je le vérifierais » |
| **Total** | **15** | |

> Un binôme qui présente un résultat modeste en l'assumant et en expliquant
> pourquoi obtient plus qu'un binôme qui survend un résultat fragile.

---

## 3. Note de lecture (25 %)

| Critère | Pts | Excellent | Insuffisant |
|---|---|---|---|
| **Protocole de découverte** | 2 | base, équation, date, rang : reproductible | « trouvé sur internet » |
| **Choix de l'article** | 2 | pertinent, récent (< 3 ans), relu par les pairs ou préprint qualifié comme tel | hors sujet, ou article de vulgarisation |
| **Résumé personnel** | 3 | reformulation qui montre la compréhension | paraphrase du résumé de l'article |
| **Grille remplie** | 5 | complète, chaque réponse adossée à un élément précis | cases vides sans mention « non précisé » |
| **Analyse critique** | 6 | deux forces et deux faiblesses **étayées** ; les six défauts récurrents ont été cherchés | jugement général non appuyé |
| **Test des 5 minutes** | 2 | appliqué et commenté | absent |
| **Transférabilité** | 3 | ce qu'il faudrait pour l'appliquer chez nous, données manquantes comprises | « c'est applicable » |
| **Expérience de vérification** | 5 | protocole décrit, réalisé si possible sur les données du cours, résultat discuté | absente |
| **Forme et références** | 2 | références vérifiées, DOI contrôlés, note méthodologique sur l'usage d'assistants | références non vérifiables |
| **Total** | **30** | | ramené à 25 % |

### Malus spécifiques

| Fait constaté | Sanction |
|---|---|
| Référence citée inexistante ou DOI invalide | **−10** — c'est la faute la plus grave d'un travail bibliographique |
| Référence tirée du corpus fictif du dépôt | **−10** (l'avertissement est explicite dans l'atelier 11) |
| Usage d'un assistant conversationnel non déclaré | **−5** |
| Article de plus de 3 ans sans justification | **−3** |

> **Sur les références fabriquées.** Vérifier un DOI prend trente secondes. Une
> référence inexistante dans un travail scientifique n'est pas une inattention :
> c'est une affirmation non fondée présentée comme un fait. La sanction est
> lourde parce que l'enjeu — savoir ce qu'on sait et comment on le sait — est
> exactement l'objet du Temps 5.

---

## 4. Grille de synthèse pour l'enseignant

```
Étudiant / binôme : ______________________________

Contrôle continu       ___ / 28   → ___ / 30 %
Mini-projet (écrit)    ___ / 30
Mini-projet (oral)     ___ / 15
  sous-total projet    ___ / 45   → ___ / 45 %
Note de lecture        ___ / 30   → ___ / 25 %

TOTAL                                 ___ / 100

Compétences de la fiche projet — atteintes ?
  [ ] Poser un problème de sécurité comme un problème d'apprentissage
  [ ] Concevoir un moteur d'apprentissage simple de bout en bout
  [ ] Structurer et interroger la connaissance cyber
  [ ] Mettre en œuvre process mining ou détection d'anomalies
  [ ] Évaluer l'état de l'art de manière scientifique
  [ ] Restituer et déployer auprès d'utilisateurs finaux

Commentaire :
```
