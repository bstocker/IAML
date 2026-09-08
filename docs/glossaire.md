# Glossaire — ML / KM / PM / DA / SOC

Les termes sont donnés en français, avec l'équivalent anglais courant entre
parenthèses. L'atelier où le terme est mis en pratique est indiqué en fin de
définition.

---

## Sécurité opérationnelle

**SOC** *(Security Operations Center)* — Centre de sécurité opérationnelle.
Structure chargée de la surveillance, de la détection et de la réponse aux
incidents de sécurité. Organisé en niveaux : N1 (triage), N2 (analyse), N3
(expertise, forensic). → 01, 07

**SIEM** *(Security Information and Event Management)* — Plateforme de collecte,
de normalisation et de corrélation des journaux de sécurité. Historiquement
fondée sur des règles ; ses limites face aux comportements inédits justifient
l'apport du ML. → 01

**EDR** *(Endpoint Detection and Response)* — Agent installé sur les postes et
serveurs, produisant une télémétrie fine (processus, réseau, fichiers) et
capable d'actions de réponse. → 01, 05

**CTI** *(Cyber Threat Intelligence)* — Renseignement sur la menace : acteurs,
techniques, indicateurs. Se formalise notamment via ATT&CK et STIX. → 02, 03

**IoC** *(Indicator of Compromise)* — Indicateur de compromission : adresse IP,
domaine, empreinte de fichier, clé de registre. Facile à extraire d'un texte,
mais de durée de vie courte. → 09

**TTP** — Tactiques, techniques et procédures. Niveau d'abstraction supérieur à
l'IoC : décrit le *comportement* de l'adversaire, donc plus durable. → 02, 03

**ATT&CK** — Référentiel public du MITRE décrivant les techniques adverses
observées, organisées par tactiques. Identifiants `TAxxxx` (tactiques),
`Txxxx[.yyy]` (techniques), `Gxxxx` (groupes), `Mxxxx` (mitigations). → 02, 03

**STIX** *(Structured Threat Information eXpression)* — Format normalisé
d'échange de renseignement sur la menace, structuré en objets et relations. → 03

**CVE** *(Common Vulnerabilities and Exposures)* — Identifiant public d'une
vulnérabilité. Associé à un score **CVSS** de 0 à 10. → 02, 03

**CMDB** *(Configuration Management Database)* — Inventaire des actifs du
système d'information. Un actif absent de la CMDB est en soi un signal. → 01

**Vrai positif / faux positif** — Une alerte est un vrai positif si elle
correspond à une activité réellement malveillante ou anormale, un faux positif
sinon. Le **taux de faux positifs** est le premier facteur de charge d'un SOC. → 01, 04

**Fatigue d'alerte** *(alert fatigue)* — Dégradation de la vigilance des
analystes sous l'effet du volume d'alertes non pertinentes. → 01, 04

---

## Apprentissage automatique (ML)

**Apprentissage supervisé** — Apprendre une fonction entrée → sortie à partir
d'exemples **étiquetés**. En SOC : prédire le verdict d'une alerte à partir de
verdicts passés. → 04

**Apprentissage non supervisé** — Découvrir une structure dans des données **sans
étiquette** : partitionnement, réduction de dimension. → 05

**Détection d'anomalies (DA)** — Signaler ce qui s'écarte d'un modèle du normal.
Distincte du supervisé : on ne dispose pas d'exemples représentatifs de la classe
« anormale ». → 01, 08

**Caractéristique** *(feature)* — Variable d'entrée d'un modèle. L'**ingénierie
des caractéristiques** est la construction de ces variables ; c'est le plus
souvent l'étape la plus déterminante. → 04, 08

**Fuite de données** *(data leakage)* — Utilisation, à l'apprentissage, d'une
information indisponible au moment de la décision réelle. Produit des scores
excellents en validation et une performance nulle en production. Test : *« cette
information existe-t-elle à l'instant où le modèle doit décider ? »* → 04

**Partition temporelle** — Découpage apprentissage/test respectant l'ordre du
temps. Obligatoire sur des données horodatées ; un découpage aléatoire laisse le
modèle « voir le futur ». → 04

**Déséquilibre de classes** — Situation où une classe est très minoritaire (ici
~7 % de vrais positifs). Rend l'exactitude et l'AUC-ROC trompeuses. → 04

**AUC-ROC** — Aire sous la courbe taux de vrais positifs / taux de faux positifs.
Optimiste sur données déséquilibrées. → 04

**AUC-PR** *(average precision)* — Aire sous la courbe précision-rappel. Se
compare au **taux de base** (proportion de positifs). Métrique de référence sur
classes déséquilibrées. → 04

**Précision** — Parmi ce que le modèle remonte, quelle proportion est correcte.
**Rappel** — Parmi ce qu'il fallait trouver, quelle proportion a été trouvée. → 04

**Précision @ K** — Précision sur les K observations les mieux classées. En SOC,
K est la **capacité de traitement quotidienne** : c'est la métrique qui a un sens
opérationnel. → 04

**Seuil de décision** — Valeur au-dessus de laquelle un score devient une action.
Ne se déduit pas du modèle mais d'une contrainte opérationnelle. → 04, 08

**Surapprentissage** *(overfitting)* — Le modèle mémorise l'échantillon
d'apprentissage au lieu d'apprendre une régularité. Se détecte par l'écart entre
performance en apprentissage et en validation. → 06

**Validation croisée** — Évaluation sur plusieurs découpages. Sur données
temporelles, utiliser `TimeSeriesSplit` et non un découpage aléatoire. → 04

**Importance par permutation** — Mesure de l'apport d'une variable : on la
permute aléatoirement et on observe la perte de performance. Se calcule sur
l'ensemble de test, avec la métrique visée. → 04

**Gradient boosting** — Ensemble d'arbres construits séquentiellement, chacun
corrigeant les erreurs des précédents. Référence sur données tabulaires. → 04, 06

**k-moyennes** *(k-means)* — Partitionnement en k groupes minimisant l'inertie
intra-classe. Suppose des groupes sphériques et affecte **tous** les points. → 05

**DBSCAN** — Partitionnement par densité. Sait laisser des points hors de tout
groupe — propriété précieuse en sécurité. → 05

**Silhouette** — Mesure de cohésion/séparation d'une partition, entre −1 et 1.
Aide au choix de k, mais ne remplace pas l'interprétabilité. → 05

**ACP** *(analyse en composantes principales)* — Réduction linéaire de dimension
maximisant la variance conservée. → 05, 06

**LOF** *(Local Outlier Factor)* — Score d'anomalie fondé sur la densité locale
comparée à celle des voisins. Détecte des anomalies que la distance au centroïde
manque. → 05, 08

**Forêt d'isolement** *(Isolation Forest)* — Détecteur d'anomalies : un point
facile à isoler par des coupes aléatoires est probablement anormal. → 08

**Contamination** — Proportion d'anomalies supposée, paramètre des détecteurs
non supervisés. Inconnue en pratique : fixe en réalité un **volume d'alertes**. → 08

**Perceptron multicouche (MLP)** — Réseau de neurones à propagation avant. Un
neurone est une régression logistique ; l'empilement apporte la non-linéarité. → 06

**Auto-encodeur** — Réseau appris à reconstruire son entrée via un goulot
d'étranglement. Usages : représentation compressée, et erreur de reconstruction
comme score d'anomalie. → 06

**Log-vraisemblance négative** *(surprisal)* — `−log p(observé)`. Mesure la
surprise du modèle. Base des détecteurs séquentiels. → 06

**Exemple adverse** — Entrée conçue pour tromper un modèle. En sécurité, le
détecteur est lui-même une cible : cette surface d'attaque doit figurer dans
l'analyse de risque. → 06

**Dérive** *(drift)* — Évolution de la distribution des données (*data drift*) ou
de la performance (*concept drift*) après le déploiement. → 10

**PSI** *(Population Stability Index)* — Indicateur de dérive d'une variable.
Convention : < 0,10 stable ; 0,10–0,25 à surveiller ; > 0,25 dérive forte. → 10

**Écart entraînement/service** *(training–serving skew)* — Divergence entre les
transformations appliquées à l'apprentissage et en production. Parade :
partager le même code de construction des caractéristiques. → 10

**Fiche de modèle** *(model card)* — Documentation d'un modèle : usage prévu,
usages exclus, performance, limites, surveillance, procédure de repli. → 10

---

## Gestion des connaissances (KM)

**Ontologie** — Spécification formelle d'une conceptualisation : classes,
propriétés, contraintes d'un domaine. → 02

**RDF** *(Resource Description Framework)* — Modèle de données du web sémantique.
Tout fait est un **triplet** (sujet, prédicat, objet). → 02

**RDFS / OWL** — Langages de schéma pour RDF. RDFS : classes, sous-classes,
domaines, portées. OWL : axiomes plus riches (transitivité, symétrie, inverse). → 02

**SPARQL** — Langage d'interrogation de graphes RDF. Interroge des **motifs de
graphe** plutôt que des tables. → 02

**Inférence / clôture déductive** — Matérialisation des faits déduits des axiomes.
Puissante, mais amplifie aussi les erreurs de modélisation. → 02

**Graphe de propriétés** — Graphe dont nœuds et arêtes portent des attributs.
Moins formel que RDF, plus adapté au **calcul** (centralités, communautés). → 03

**Centralité d'intermédiarité** *(betweenness)* — Proportion de plus courts
chemins passant par un nœud. Sur un graphe de menace : point de passage entre
familles d'adversaires. → 03

**Détection de communautés** — Regroupement de nœuds densément connectés
(algorithme de Louvain). Sur ATT&CK : groupes d'adversaires aux arsenaux proches. → 03

**TF-IDF** — Pondération d'un terme par sa fréquence dans le document et sa
rareté dans le corpus. Référence à battre en classification de texte. → 09

**LSA** *(Latent Semantic Analysis)* — Réduction de dimension d'une matrice
TF-IDF par décomposition en valeurs singulières. → 09

---

## Process mining (PM)

**Journal d'événements de processus** — Journal comportant au minimum trois
colonnes : **cas**, **activité**, **horodatage**. Format normalisé : XES. → 07

**Cas** *(case)* — Instance du processus suivie de bout en bout (ici : un
incident). → 07

**Variante** — Séquence d'activités distincte. Un processus sain concentre
l'essentiel de son volume sur quelques variantes. → 07

**Découverte de processus** *(process discovery)* — Construction automatique d'un
modèle à partir des traces : *alpha miner*, *heuristic miner*, *inductive miner*. → 07

**DFG** *(Directly-Follows Graph)* — Graphe « directement suivi de ». La
représentation la plus lisible ; illisible sans filtrage sur un processus réel. → 07

**Réseau de Petri** — Formalisme de modélisation de processus concurrents,
produit par l'*inductive miner*. → 07

**Conformité** *(conformance checking)* — Mesure de l'écart entre le processus
observé et un modèle prescrit. L'**ajustement** (*fitness*) quantifie la part des
traces reproductibles par le modèle. → 07

**Reprise** *(rework)* — Répétition d'une activité au sein d'un même cas.
Meilleur indicateur de qualité d'un processus. → 07

**Goulet d'étranglement** — Transition consommant le plus de **temps cumulé**
(durée × fréquence), à ne pas confondre avec la transition la plus lente. → 07

---

## Détection d'anomalies (DA)

**Anomalie ponctuelle** — Observation isolée éloignée de la masse (transfert de
4 Go). → 01, 08

**Anomalie contextuelle** — Observation normale dans l'absolu, anormale dans son
contexte (200 Mo à 3 h du matin depuis un poste bureautique). → 01, 08

**Anomalie collective** — Ensemble d'observations individuellement banales dont
la **séquence** est anormale (balise C2 toutes les 60 s). Impose de changer
d'unité d'observation. → 01, 08

**Balise / *beaconing*** — Communication périodique d'un implant vers son serveur
de commande. Se détecte par la régularité, pas par le volume. → 08

**Tunnel DNS** — Exfiltration ou canal de commande encapsulé dans des requêtes
DNS. → 08

**Unité d'observation** — Objet décrit par une ligne du jeu de données (un flux ?
un couple source-destination ? un hôte ?). **Ce choix détermine ce qui sera
détectable.** → 01, 05, 08

**Référence de normalité** *(baseline)* — Modèle du comportement normal auquel on
compare. Par ordre de préférence : l'entité elle-même > son groupe d'usage > le
parc entier. → 05, 06

**Empoisonnement de la ligne de base** — Contamination de la période de référence
par une activité malveillante déjà présente : l'écart devient nul et l'attaque
invisible. → 06

---

## Méthode scientifique

**Référence naïve** *(baseline)* — Méthode simple servant de point de comparaison
obligatoire (classe majoritaire, règle à seuil, tri par sévérité). Un résultat
sans référence naïve n'est pas interprétable. → 04, 06, 09

**Reproductibilité** — Possibilité pour un tiers d'obtenir les mêmes résultats :
graine fixée, versions figées, données et code disponibles. → tous

**Criblage** *(screening)* — Filtrage progressif d'un corpus bibliographique
(titre → résumé → texte intégral). On ne lit intégralement que 5 à 10 %. → 11

**Préprint** — Article déposé avant relecture par les pairs (arXiv). Utile pour
la veille, à citer en le qualifiant comme tel. → 11
