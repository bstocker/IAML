#!/usr/bin/env bash
# Provisionnement du Codespace : dépendances + génération des jeux de données.
set -euo pipefail

echo "==> Mise à jour de pip"
python -m pip install --upgrade pip wheel >/dev/null

echo "==> Installation des dépendances (2 à 4 minutes la première fois)"
python -m pip install -r requirements.txt

echo "==> Génération des jeux de données synthétiques SOC"
python tools/generate_soc_data.py --out data --seed 42

echo "==> Vérification de l'environnement"
python tools/check_env.py

cat <<'BANNER'

  ============================================================
   Environnement IAML prêt.

   Ouvrez  notebooks/enonces/01_donnees_soc.ipynb  pour démarrer.
   Les corrigés sont dans notebooks/corriges/ (accès enseignant).

   Commandes utiles :
     make data       régénère les données synthétiques
     make build      régénère les notebooks depuis ateliers/src/
     make test       exécute tous les corrigés (vérifie que tout tourne)
  ============================================================

BANNER
