# Environnement de développement

Ce répertoire configure le conteneur utilisé par GitHub Codespaces et par
VS Code Dev Containers.

| Fichier | Rôle |
|---|---|
| `devcontainer.json` | image Python 3.11, extensions VS Code, ports redirigés |
| `postCreate.sh` | installe les dépendances puis génère les jeux de données |

## Ce qui se passe à la création du Codespace

1. Démarrage de l'image `mcr.microsoft.com/devcontainers/python:1-3.11-bookworm`.
2. `pip install -r requirements.txt` (2 à 4 minutes la première fois).
3. `python tools/generate_soc_data.py --out data --seed 42` — les données ne
   sont pas versionnées, elles sont reconstruites à l'identique.
4. `python tools/check_env.py` — diagnostic ; toute anomalie est affichée.

## Ports

| Port | Usage |
|---|---|
| 8000 | API de scoring de l'atelier 10 (`uvicorn service.api:app`) |
| 8888 | JupyterLab, si vous préférez l'ouvrir hors de VS Code |

## En cas de problème

```bash
python tools/check_env.py          # diagnostic complet
make install                       # réinstalle les dépendances
make data                          # régénère les jeux de données
```

Si un notebook refuse de démarrer : *Command Palette* →
**Jupyter: Select Interpreter to Start Jupyter Server** → `/usr/local/bin/python`.
