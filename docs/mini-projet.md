# Mini-projet — modéliser un problème de sécurité comme un problème d'apprentissage

> Évaluation principale du cours, avec le contrôle continu (notebooks de TP) et
> la note de lecture du Temps 5. Barème détaillé : [bareme.md](bareme.md).

## 1. Objectif

Dérouler **la démarche complète** sur un problème de sécurité, de la
spécification du besoin à la restitution devant un « utilisateur final ».

Ce qui est évalué n'est **pas la performance du modèle** mais la qualité du
raisonnement : cadrage, choix justifiés, évaluation honnête, conscience des
limites, capacité à traduire un résultat statistique en décision opérationnelle.

> Un projet concluant à *« l'apprentissage automatique n'est pas la bonne réponse
> à cette question, voici pourquoi et voici ce que je propose à la place »* peut
> obtenir la note maximale. C'est même l'un des meilleurs résultats possibles.

## 2. Modalités

- **Binôme** (monôme accepté sur demande motivée).
- Démarrage semaine 5, rendu semaine 12 (ou 14 selon le montage retenu).
- Rendu : un dépôt Git contenant un notebook exécutable, un rapport de 6 à 10
  pages, et les supports de restitution.
- Soutenance : 15 minutes de présentation + 10 minutes de questions.

## 3. Sujets proposés

Les sujets s'appuient sur les jeux de données du dépôt. Vous pouvez aussi
**apporter votre propre jeu de données** (voir §4).

### Sujet A — Réduire la charge du SOC sans manquer d'incident

**Question.** Comment réorganiser la file de triage pour que trois analystes
traitent en priorité ce qui compte ?

Va plus loin que l'atelier 04 : optimiser le **couple modèle + politique de
seuil**, en intégrant la criticité métier des actifs et un traitement
différencié par famille de règle. Livrable attendu : la courbe de décision
opérationnelle et une recommandation de dimensionnement chiffrée.

*Données : `alertes_siem.csv`, `assets.csv`, `utilisateurs.csv`.*

### Sujet B — Détecter une compromission par le comportement

**Question.** Peut-on repérer une machine compromise sans signature, à partir de
son seul comportement ?

Combine les ateliers 05, 06 et 08 : construire une référence de normalité par
hôte, détecter les écarts, mesurer le délai de détection et le volume de faux
positifs. La vérité terrain (`verite_terrain/profils_hotes.csv`) sert
**uniquement** à l'évaluation finale.

*Données : `evenements_systeme.csv`, `netflow.csv`, `assets.csv`.*

### Sujet C — Prioriser les vulnérabilités par le risque réel

**Question.** Sur quelles vulnérabilités faut-il travailler cette semaine ?

Problème de **modélisation de connaissances** plus que de ML. Construire un
graphe reliant actifs, CVE, techniques ATT&CK, groupes et mitigations ; produire
un classement défendable ; le comparer à un tri par CVSS décroissant et montrer
ce que le contexte apporte.

*Données : `cve.csv`, `vulnerabilites_hotes.csv`, `assets.csv`, `attack/`.*

### Sujet D — Améliorer le processus de réponse à incident

**Question.** Où le SOC perd-il du temps, et quelle réorganisation proposer ?

Process mining approfondi (atelier 07) : analyse des variantes, des goulets, des
reprises et de l'effet des horaires. Livrable : une note de recommandation
chiffrée en heures et en ETP, avec les indicateurs de suivi associés.

*Données : `journal_incidents.csv`.*

### Sujet E — Capitaliser la connaissance des incidents passés

**Question.** Que sait-on de nos propres incidents, et comment le rendre
interrogeable ?

Chaîne complète texte → connaissance (ateliers 09, 02, 03) : extraction d'IoC et
de techniques depuis les rapports, construction d'une base de connaissances
interrogeable, croisement avec la couverture de détection.

*Données : `rapports/`, `rapports_index.csv`, `attack/`, `alertes_siem.csv`.*

### Sujet F — Surveiller un modèle en production

**Question.** Comment savoir qu'un modèle déployé s'est dégradé, et que faire ?

Prolonge l'atelier 10 : dispositif de surveillance complet, simulation d'une
dérive, politique de réentraînement, estimation du rappel réel avec quota
d'exploration. Livrable : le tableau de bord et la procédure d'exploitation.

*Données : `alertes_siem.csv` + le modèle de l'atelier 04.*

## 4. Apporter son propre jeu de données

Encouragé (stage, alternance, projet personnel, jeu public). Trois conditions
**impératives** :

1. **Aucune donnée réelle d'un système d'information tiers** sans autorisation
   écrite. En cas de doute : anonymisez, ou utilisez un jeu public.
2. **Aucune donnée personnelle** au sens du RGPD. Les journaux de sécurité en
   contiennent presque toujours (identifiants, adresses IP) : la
   pseudonymisation doit être décrite dans le rapport.
3. Validation du sujet par l'enseignant **avant la semaine 6**.

Jeux publics acceptables : CIC-IDS2017, UNSW-NB15, LANL Unified Host and Network,
CERT Insider Threat, BETH, Kaggle Microsoft Malware. Vous devrez alors critiquer
le jeu retenu (âge, représentativité, mode de production des étiquettes) —
c'est une partie du travail attendu.

## 5. Livrables

### 5.1 Notebook exécutable

- S'exécute de bout en bout dans le Codespace du cours, sans intervention.
- Graine aléatoire fixée ; deux exécutions donnent le même résultat.
- Structuré et commenté : un lecteur doit suivre le raisonnement sans vous.
- Aucun résultat affiché sans commentaire d'interprétation.

### 5.2 Rapport (6 à 10 pages)

| Section | Contenu attendu | Poids indicatif |
|---|---|---|
| **1. Spécification du besoin** | question métier, unité d'observation, cible, famille d'apprentissage **et sa justification**, métrique, coût d'erreur, contrainte opérationnelle | 20 % |
| **2. Données et prétraitement** | source, qualité, valeurs manquantes, doublons, biais identifiés, choix d'agrégation | 15 % |
| **3. Caractéristiques** | ce que chaque variable encode comme hypothèse d'analyste ; **contrôle explicite de l'absence de fuite** | 15 % |
| **4. Modélisation** | méthodes comparées, **référence naïve obligatoire**, protocole de validation | 15 % |
| **5. Évaluation critique** | métriques justifiées, variabilité, ce que le modèle ne sait pas faire | 20 % |
| **6. Restitution** | traduction en décision : volume d'alertes, temps analyste, seuil, procédure de réponse | 15 % |

### 5.3 Restitution orale

15 minutes **devant un « utilisateur final »** — un responsable de SOC, non
spécialiste du ML. Contraintes :

- pas d'équation, pas de nom d'algorithme dans les trois premières minutes ;
- une diapositive au maximum sur la méthode, le reste sur le problème et la décision ;
- annoncer explicitement ce que votre solution **ne fait pas** ;
- répondre à : *« qu'est-ce que ça change pour mon équipe lundi matin ? »*

## 6. Attendus explicites

Les points suivants sont **vérifiés systématiquement** :

- [ ] La famille d'apprentissage est justifiée, pas subie.
- [ ] Une référence naïve est évaluée et comparée.
- [ ] La partition est temporelle si les données sont horodatées.
- [ ] Chaque caractéristique est disponible au moment de la décision (anti-fuite).
- [ ] Les métriques sont adaptées au déséquilibre de classes.
- [ ] Le seuil de décision découle d'une contrainte opérationnelle explicite.
- [ ] Les limites sont énoncées par vous, avant qu'on ne vous les oppose.
- [ ] Le résultat est traduit en volume de travail et en risque assumé.

## 7. Ce qui fait perdre des points

| Erreur | Pourquoi c'est grave |
|---|---|
| Score annoncé sans taux de base | Le chiffre n'est pas interprétable |
| « 98 % d'exactitude » sur des classes déséquilibrées | Un modèle constant ferait mieux |
| Partition aléatoire sur des données horodatées | Le modèle a vu le futur |
| Variable indisponible à la décision | Le résultat est faux, pas seulement optimiste |
| Aucune référence naïve | On ne sait pas si le modèle sert à quelque chose |
| Aucune limite énoncée | Signale que l'analyse critique n'a pas eu lieu |
| Graphique sans commentaire | Un graphique qui ne répond à aucune question est du remplissage |
| Copie d'un notebook de TP avec les données changées | Aucune démarche propre |

## 8. Calendrier

| Échéance | Livrable |
|---|---|
| Semaine 5 | Choix du sujet et du binôme |
| Semaine 6 | **Fiche de cadrage** (§5.2, section 1) validée par l'enseignant |
| Semaine 9 | Point d'étape de 10 minutes : données, premières caractéristiques, référence naïve |
| Semaine 11 | Dépôt du notebook et du rapport |
| Semaine 12 | Soutenances |

La fiche de cadrage de la semaine 6 est **bloquante** : un projet mal cadré ne
peut pas être rattrapé par la qualité de son implémentation.
