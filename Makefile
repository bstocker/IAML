# Atelier IAML — commandes courantes
.PHONY: help install data build check test clean tout

PYTHON ?= python

help:                ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:             ## Installe les dépendances Python
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt

data:                ## (Re)génère les jeux de données synthétiques
	$(PYTHON) tools/generate_soc_data.py --out data --seed 42

build:               ## Reconstruit les notebooks depuis ateliers/src/
	$(PYTHON) tools/build_notebooks.py

check:               ## Vérifie l'environnement et les données
	$(PYTHON) tools/check_env.py
	$(PYTHON) tools/build_notebooks.py --check

test:                ## Exécute tous les corrigés (garde-fou du dépôt)
	$(PYTHON) tools/run_notebooks.py

clean:               ## Supprime les artefacts générés
	rm -rf artifacts .ipynb_checkpoints notebooks/**/.ipynb_checkpoints
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

tout: install data build check test  ## Chaîne complète, comme en CI
