#!/usr/bin/env python3
"""Construit les notebooks Jupyter (enonces + corriges) a partir d'une source unique.

Les ateliers sont ecrits dans `ateliers/src/*.py` au format « percent » (compatible
jupytext et VS Code). Chaque cellule commence par un marqueur :

    # %% [markdown]        -> cellule Markdown (lignes prefixees par « # »)
    # %%                   -> cellule de code presente dans les DEUX versions
    # %% tags=["todo"]     -> cellule presente uniquement dans l'ENONCE
    # %% tags=["solution"] -> cellule presente uniquement dans le CORRIGE

Ce script n'utilise que la bibliotheque standard : il fonctionne meme avant
l'installation des dependances.

Usage :
    python tools/build_notebooks.py            # construit tout
    python tools/build_notebooks.py --check    # verifie que les .ipynb sont a jour
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "ateliers" / "src"
OUT_ENONCE = ROOT / "notebooks" / "enonces"
OUT_CORRIGE = ROOT / "notebooks" / "corriges"

CELL_RE = re.compile(r"^#\s*%%(?P<rest>.*)$")
TAGS_RE = re.compile(r"tags\s*=\s*(\[[^\]]*\])")


@dataclass
class Cell:
    kind: str  # "code" | "markdown"
    tags: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    def source(self) -> list[str]:
        lines = list(self.lines)
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if self.kind == "markdown":
            lines = [re.sub(r"^# ?", "", ln) for ln in lines]
        return [ln + "\n" for ln in lines[:-1]] + (lines[-1:] if lines else [])


def parse(path: Path) -> list[Cell]:
    cells: list[Cell] = []
    current: Cell | None = None
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = CELL_RE.match(raw)
        if m:
            rest = m.group("rest")
            kind = "markdown" if "[markdown]" in rest else "code"
            tags_m = TAGS_RE.search(rest)
            tags = json.loads(tags_m.group(1).replace("'", '"')) if tags_m else []
            unknown = set(tags) - {"todo", "solution"}
            if unknown:
                raise SystemExit(f"{path}:{lineno}: tag inconnu {sorted(unknown)}")
            current = Cell(kind=kind, tags=tags)
            cells.append(current)
            continue
        if current is None:
            # En-tete de fichier (docstring, imports de confort) : ignore.
            continue
        current.lines.append(raw)
    return [c for c in cells if c.source()]


def to_notebook(cells: list[Cell], variant: str, title: str) -> dict:
    drop = "solution" if variant == "enonce" else "todo"
    nb_cells = []
    for cell in cells:
        if drop in cell.tags:
            continue
        # nbformat >= 4.5 exige un identifiant stable par cellule.
        base = {"id": f"cell-{len(nb_cells):03d}", "metadata": {},
                "source": cell.source()}
        if cell.tags:
            base["metadata"]["tags"] = cell.tags
        if cell.kind == "markdown":
            nb_cells.append({"cell_type": "markdown", **base})
        else:
            nb_cells.append(
                {"cell_type": "code", "execution_count": None, "outputs": [], **base}
            )
    return {
        "cells": nb_cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python", "version": "3.11"},
            "iaml": {"variante": variant, "atelier": title},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def build(check_only: bool = False) -> int:
    OUT_ENONCE.mkdir(parents=True, exist_ok=True)
    OUT_CORRIGE.mkdir(parents=True, exist_ok=True)
    sources = sorted(SRC_DIR.glob("*.py"))
    if not sources:
        raise SystemExit(f"Aucune source trouvee dans {SRC_DIR}")

    stale: list[str] = []
    for src in sources:
        cells = parse(src)
        for variant, outdir, suffix in (
            ("enonce", OUT_ENONCE, ""),
            ("corrige", OUT_CORRIGE, "_corrige"),
        ):
            nb = to_notebook(cells, variant, src.stem)
            target = outdir / f"{src.stem}{suffix}.ipynb"
            payload = json.dumps(nb, ensure_ascii=False, indent=1) + "\n"
            if check_only:
                if not target.exists() or target.read_text(encoding="utf-8") != payload:
                    stale.append(str(target.relative_to(ROOT)))
            else:
                target.write_text(payload, encoding="utf-8")
                n_code = sum(1 for c in nb["cells"] if c["cell_type"] == "code")
                print(f"  {target.relative_to(ROOT)}  ({n_code} cellules de code)")

    if check_only:
        if stale:
            print("Notebooks desynchronises des sources :", file=sys.stderr)
            for s in stale:
                print(f"  - {s}", file=sys.stderr)
            print("\nRelancez : make build", file=sys.stderr)
            return 1
        print(f"{len(sources)} ateliers : notebooks a jour.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verifie sans ecrire")
    args = ap.parse_args()
    sys.exit(build(check_only=args.check))
