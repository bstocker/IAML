#!/usr/bin/env python3
"""Verifie que l'environnement IAML est complet et que les donnees sont presentes.

A executer apres la creation du Codespace, ou en cas de doute pendant un TP.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MODULES = [
    ("numpy", "socle numerique"),
    ("pandas", "manipulation de donnees"),
    ("matplotlib", "graphiques"),
    ("sklearn", "machine learning (ateliers 04-06, 08-09)"),
    ("scipy", "statistiques (ateliers 08, 10)"),
    ("networkx", "graphes (ateliers 03, 07, 09)"),
    ("rdflib", "RDF / SPARQL (atelier 02)"),
    ("owlrl", "inference RDFS/OWL (atelier 02)"),
    ("pm4py", "process mining (atelier 07)"),
    ("fastapi", "service de scoring (atelier 10)"),
    ("joblib", "serialisation de modeles"),
    ("jupyterlab", "environnement de notebooks"),
]

FICHIERS = [
    "data/assets.csv",
    "data/utilisateurs.csv",
    "data/alertes_siem.csv",
    "data/evenements_systeme.csv",
    "data/netflow.csv",
    "data/journal_incidents.csv",
    "data/cve.csv",
    "data/vulnerabilites_hotes.csv",
    "data/rapports_index.csv",
    "data/corpus_fictif_pour_exercice.csv",
    "data/attack/attack_subset.json",
    "data/attack/attack_bundle_stix.json",
    "data/verite_terrain/profils_hotes.csv",
    "data/verite_terrain/netflow_etiquettes.csv",
]


def main() -> int:
    print(f"Python {sys.version.split()[0]}\n")
    problemes = []

    print("Bibliotheques")
    for module, usage in MODULES:
        try:
            m = importlib.import_module(module)
            version = getattr(m, "__version__", "?")
            print(f"  [ok]  {module:12s} {version:12s} {usage}")
        except ImportError:
            print(f"  [KO]  {module:12s} {'absent':12s} {usage}")
            problemes.append(f"module manquant : {module}")

    print("\nJeux de donnees")
    for f in FICHIERS:
        chemin = ROOT / f
        if chemin.exists():
            print(f"  [ok]  {f:46s} {chemin.stat().st_size / 1024:>9,.0f} ko")
        else:
            print(f"  [KO]  {f:46s} {'absent':>9s}")
            problemes.append(f"donnee manquante : {f}")

    print("\nNotebooks")
    for repertoire in ("notebooks/enonces", "notebooks/corriges"):
        n = len(list((ROOT / repertoire).glob("*.ipynb")))
        etat = "ok" if n else "KO"
        print(f"  [{etat}]  {repertoire:46s} {n:>9} notebooks")
        if not n:
            problemes.append(f"aucun notebook dans {repertoire}")

    print()
    if problemes:
        print(f"{len(problemes)} probleme(s) :")
        for p in problemes:
            print(f"  - {p}")
        print("\nCorrectifs :")
        print("  pip install -r requirements.txt")
        print("  python tools/generate_soc_data.py --out data --seed 42")
        print("  python tools/build_notebooks.py")
        return 1

    print("Environnement complet. Bon TP.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
