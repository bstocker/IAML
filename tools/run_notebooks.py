#!/usr/bin/env python3
"""Execute les notebooks corriges pour verifier qu'ils tournent de bout en bout.

C'est le garde-fou du depot : si un corrige casse (montee de version d'une
bibliotheque, changement du generateur de donnees), la CI le signale avant que
les etudiants ne le decouvrent en TP.

Usage :
    python tools/run_notebooks.py                 # tous les corriges
    python tools/run_notebooks.py 04 07           # seulement ceux-la
"""

from __future__ import annotations

import sys
import time
import traceback
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas d'affichage interactif en CI

import nbformat
from nbclient import NotebookClient

ROOT = Path(__file__).resolve().parent.parent
CORRIGES = ROOT / "notebooks" / "corriges"
TIMEOUT = 1200


def executer(chemin: Path) -> tuple[bool, str, float]:
    nb = nbformat.read(chemin, as_version=4)
    client = NotebookClient(nb, timeout=TIMEOUT, kernel_name="python3",
                            resources={"metadata": {"path": str(ROOT)}})
    t0 = time.perf_counter()
    try:
        client.execute()
        return True, "", time.perf_counter() - t0
    except Exception:
        return False, traceback.format_exc(limit=6), time.perf_counter() - t0


def main() -> int:
    filtres = sys.argv[1:]
    cibles = sorted(CORRIGES.glob("*_corrige.ipynb"))
    if filtres:
        cibles = [c for c in cibles if any(f in c.name for f in filtres)]
    if not cibles:
        print("Aucun notebook a executer.", file=sys.stderr)
        return 1

    echecs = []
    for nb_path in cibles:
        print(f"→ {nb_path.name} ... ", end="", flush=True)
        ok, err, duree = executer(nb_path)
        print(f"{'OK' if ok else 'ECHEC'} ({duree:.0f} s)")
        if not ok:
            echecs.append((nb_path.name, err))

    print("\n" + "=" * 70)
    if echecs:
        for nom, err in echecs:
            print(f"\n### {nom}\n{err}")
        print(f"{len(echecs)}/{len(cibles)} notebook(s) en echec.")
        return 1
    print(f"{len(cibles)}/{len(cibles)} notebooks executes sans erreur.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
