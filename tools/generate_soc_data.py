#!/usr/bin/env python3
"""Generateur de jeux de donnees synthetiques imitant les artefacts d'un SOC.

AUCUNE donnee reelle, AUCUNE donnee personnelle : tout est tire de lois
statistiques parametrees, avec une graine fixe pour garantir la reproductibilite
(deux etudiants obtiennent exactement le meme jeu de donnees).

Le generateur injecte volontairement :
  * un desequilibre de classes realiste (~8 % de vrais positifs) ;
  * une variable « fuitee » (temps de traitement analyste) pour l'atelier 04 ;
  * une derive de distribution sur les 30 derniers jours pour l'atelier 10 ;
  * des anomalies etiquetees (C2 beaconing, exfiltration, scan, tunnel DNS) ;
  * des boucles de reprise dans le journal d'incidents pour le process mining.

Usage :
    python tools/generate_soc_data.py --out data --seed 42
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

T0 = datetime(2025, 1, 6, 0, 0, 0)  # lundi
JOURS = 180


# --------------------------------------------------------------------------
# Utilitaires
# --------------------------------------------------------------------------
def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


def horodatages(rng: np.random.Generator, n: int, jours: int = JOURS,
                biais_ouvrable: float = 0.75) -> pd.Series:
    """Tire n horodatages avec une saisonnalite jour/nuit et semaine/week-end."""
    jour = rng.integers(0, jours, n)
    date = np.array([T0 + timedelta(days=int(j)) for j in jour])
    jour_semaine = np.array([d.weekday() for d in date])

    ouvrable = (rng.random(n) < biais_ouvrable) & (jour_semaine < 5)
    heure = np.where(
        ouvrable,
        rng.normal(14, 2.6, n).clip(7, 19),
        rng.choice(np.arange(0, 24), n),
    )
    minute = rng.integers(0, 60, n)
    seconde = rng.integers(0, 60, n)
    ts = [
        d + timedelta(hours=float(h), minutes=int(m), seconds=int(s))
        for d, h, m, s in zip(date, heure, minute, seconde)
    ]
    return pd.Series(ts).sort_values().reset_index(drop=True)


def ip_interne(rng: np.random.Generator, n: int) -> np.ndarray:
    return np.array(
        [f"10.{rng.integers(0, 6)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"
         for _ in range(n)]
    )


def ip_externe(rng: np.random.Generator, n: int) -> np.ndarray:
    return np.array(
        [f"{rng.integers(11, 223)}.{rng.integers(0, 255)}."
         f"{rng.integers(0, 255)}.{rng.integers(1, 254)}"
         for _ in range(n)]
    )


# --------------------------------------------------------------------------
# 1. Inventaire (CMDB) et annuaire
# --------------------------------------------------------------------------
ZONES = ["poste_travail", "serveurs", "dmz", "industriel", "infra_admin"]
OS_PAR_ZONE = {
    "poste_travail": ["Windows 11", "Windows 10", "macOS 14"],
    "serveurs": ["Windows Server 2022", "Debian 12", "RHEL 9"],
    "dmz": ["Debian 12", "RHEL 9"],
    "industriel": ["Windows 7 embedded", "Linux embarque"],
    "infra_admin": ["Windows Server 2022", "Debian 12"],
}
DEPARTEMENTS = ["finance", "rh", "production", "r_et_d", "commerce", "dsi", "direction"]


def generer_assets(rng: np.random.Generator, n: int = 140) -> pd.DataFrame:
    zone = rng.choice(ZONES, n, p=[0.55, 0.20, 0.08, 0.07, 0.10])
    os_ = [rng.choice(OS_PAR_ZONE[z]) for z in zone]
    crit_base = {"poste_travail": 1.6, "serveurs": 3.0, "dmz": 3.3,
                 "industriel": 3.6, "infra_admin": 3.8}
    crit = np.array([
        int(np.clip(round(rng.normal(crit_base[z], 0.7)), 1, 4)) for z in zone
    ])
    return pd.DataFrame({
        "asset_id": [f"AST-{i:04d}" for i in range(n)],
        "hostname": [f"{z[:3]}-{i:04d}" for i, z in enumerate(zone)],
        "ip": ip_interne(rng, n),
        "os": os_,
        "zone": zone,
        "criticite": crit,
        "departement": rng.choice(DEPARTEMENTS, n),
        "expose_internet": (zone == "dmz") | (rng.random(n) < 0.04),
        "agent_edr": rng.random(n) < 0.88,
        "derniere_maj_jours": rng.integers(0, 400, n),
    })


def generer_users(rng: np.random.Generator, n: int = 220) -> pd.DataFrame:
    dept = rng.choice(DEPARTEMENTS, n)
    role = rng.choice(
        ["utilisateur", "developpeur", "admin_sys", "admin_secu", "prestataire"],
        n, p=[0.62, 0.15, 0.10, 0.04, 0.09],
    )
    return pd.DataFrame({
        "user_id": [f"U-{i:04d}" for i in range(n)],
        "username": [f"{d[:2]}user{i:03d}" for i, d in enumerate(dept)],
        "departement": dept,
        "role": role,
        "compte_admin": np.isin(role, ["admin_sys", "admin_secu"]),
        "anciennete_jours": rng.integers(5, 4000, n),
        "mfa_actif": rng.random(n) < 0.82,
    })


# --------------------------------------------------------------------------
# 2. Sous-ensemble MITRE ATT&CK (identifiants publics, descriptions reformulees)
# --------------------------------------------------------------------------
TACTIQUES = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0001", "initial-access", "Acces initial"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistance"),
    ("TA0004", "privilege-escalation", "Elevation de privileges"),
    ("TA0005", "defense-evasion", "Contournement des defenses"),
    ("TA0006", "credential-access", "Acces aux identifiants"),
    ("TA0007", "discovery", "Decouverte"),
    ("TA0008", "lateral-movement", "Deplacement lateral"),
    ("TA0009", "collection", "Collecte"),
    ("TA0011", "command-and-control", "Commande et controle"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]

# (id, nom, tactiques, plateformes, sources de donnees, technique parente)
TECHNIQUES = [
    ("T1595", "Active Scanning", ["reconnaissance"], ["PRE"], ["Network Traffic"], None),
    ("T1566", "Phishing", ["initial-access"], ["Windows", "Linux", "macOS"], ["Network Traffic", "File"], None),
    ("T1566.001", "Spearphishing Attachment", ["initial-access"], ["Windows", "macOS"], ["File", "Network Traffic"], "T1566"),
    ("T1566.002", "Spearphishing Link", ["initial-access"], ["Windows", "Linux", "macOS"], ["Network Traffic"], "T1566"),
    ("T1190", "Exploit Public-Facing Application", ["initial-access"], ["Windows", "Linux"], ["Network Traffic", "Application Log"], None),
    ("T1133", "External Remote Services", ["initial-access", "persistence"], ["Windows", "Linux"], ["Logon Session", "Network Traffic"], None),
    ("T1078", "Valid Accounts", ["initial-access", "persistence", "privilege-escalation", "defense-evasion"], ["Windows", "Linux", "macOS"], ["Logon Session", "User Account"], None),
    ("T1059", "Command and Scripting Interpreter", ["execution"], ["Windows", "Linux", "macOS"], ["Process", "Command"], None),
    ("T1059.001", "PowerShell", ["execution"], ["Windows"], ["Process", "Command", "Script"], "T1059"),
    ("T1059.003", "Windows Command Shell", ["execution"], ["Windows"], ["Process", "Command"], "T1059"),
    ("T1059.004", "Unix Shell", ["execution"], ["Linux", "macOS"], ["Process", "Command"], "T1059"),
    ("T1204", "User Execution", ["execution"], ["Windows", "Linux", "macOS"], ["Process", "File"], None),
    ("T1053", "Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"], ["Windows", "Linux"], ["Process", "Scheduled Job"], None),
    ("T1053.005", "Scheduled Task", ["persistence"], ["Windows"], ["Process", "Scheduled Job"], "T1053"),
    ("T1547", "Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"], ["Windows", "Linux"], ["Windows Registry", "File"], None),
    ("T1547.001", "Registry Run Keys / Startup Folder", ["persistence"], ["Windows"], ["Windows Registry"], "T1547"),
    ("T1136", "Create Account", ["persistence"], ["Windows", "Linux"], ["User Account"], None),
    ("T1543", "Create or Modify System Process", ["persistence", "privilege-escalation"], ["Windows", "Linux"], ["Service", "Process"], None),
    ("T1543.003", "Windows Service", ["persistence"], ["Windows"], ["Service", "Windows Registry"], "T1543"),
    ("T1548", "Abuse Elevation Control Mechanism", ["privilege-escalation", "defense-evasion"], ["Windows", "Linux", "macOS"], ["Process", "Command"], None),
    ("T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"], ["Windows", "Linux"], ["Process", "Application Log"], None),
    ("T1055", "Process Injection", ["privilege-escalation", "defense-evasion"], ["Windows", "Linux"], ["Process", "Module"], None),
    ("T1027", "Obfuscated Files or Information", ["defense-evasion"], ["Windows", "Linux", "macOS"], ["File", "Script"], None),
    ("T1070", "Indicator Removal", ["defense-evasion"], ["Windows", "Linux"], ["File", "Windows Registry"], None),
    ("T1070.001", "Clear Windows Event Logs", ["defense-evasion"], ["Windows"], ["Windows Registry", "Command"], "T1070"),
    ("T1218", "System Binary Proxy Execution", ["defense-evasion"], ["Windows"], ["Process", "Command"], None),
    ("T1562", "Impair Defenses", ["defense-evasion"], ["Windows", "Linux"], ["Service", "Windows Registry"], None),
    ("T1562.001", "Disable or Modify Tools", ["defense-evasion"], ["Windows", "Linux"], ["Service", "Command"], "T1562"),
    ("T1110", "Brute Force", ["credential-access"], ["Windows", "Linux", "macOS"], ["Logon Session", "User Account"], None),
    ("T1110.003", "Password Spraying", ["credential-access"], ["Windows", "Linux"], ["Logon Session"], "T1110"),
    ("T1003", "OS Credential Dumping", ["credential-access"], ["Windows", "Linux"], ["Process", "Command"], None),
    ("T1003.001", "LSASS Memory", ["credential-access"], ["Windows"], ["Process", "Command"], "T1003"),
    ("T1555", "Credentials from Password Stores", ["credential-access"], ["Windows", "Linux", "macOS"], ["Process", "File"], None),
    ("T1558", "Steal or Forge Kerberos Tickets", ["credential-access"], ["Windows"], ["Logon Session", "Network Traffic"], None),
    ("T1558.003", "Kerberoasting", ["credential-access"], ["Windows"], ["Logon Session"], "T1558"),
    ("T1087", "Account Discovery", ["discovery"], ["Windows", "Linux"], ["Process", "Command"], None),
    ("T1018", "Remote System Discovery", ["discovery"], ["Windows", "Linux"], ["Process", "Network Traffic"], None),
    ("T1046", "Network Service Discovery", ["discovery"], ["Windows", "Linux"], ["Network Traffic"], None),
    ("T1082", "System Information Discovery", ["discovery"], ["Windows", "Linux", "macOS"], ["Process", "Command"], None),
    ("T1021", "Remote Services", ["lateral-movement"], ["Windows", "Linux"], ["Logon Session", "Network Traffic"], None),
    ("T1021.001", "Remote Desktop Protocol", ["lateral-movement"], ["Windows"], ["Logon Session", "Network Traffic"], "T1021"),
    ("T1021.002", "SMB/Windows Admin Shares", ["lateral-movement"], ["Windows"], ["Network Share", "Logon Session"], "T1021"),
    ("T1570", "Lateral Tool Transfer", ["lateral-movement"], ["Windows", "Linux"], ["File", "Network Traffic"], None),
    ("T1560", "Archive Collected Data", ["collection"], ["Windows", "Linux", "macOS"], ["File", "Process"], None),
    ("T1005", "Data from Local System", ["collection"], ["Windows", "Linux", "macOS"], ["File", "Command"], None),
    ("T1071", "Application Layer Protocol", ["command-and-control"], ["Windows", "Linux", "macOS"], ["Network Traffic"], None),
    ("T1071.001", "Web Protocols", ["command-and-control"], ["Windows", "Linux", "macOS"], ["Network Traffic"], "T1071"),
    ("T1071.004", "DNS", ["command-and-control"], ["Windows", "Linux", "macOS"], ["Network Traffic"], "T1071"),
    ("T1573", "Encrypted Channel", ["command-and-control"], ["Windows", "Linux", "macOS"], ["Network Traffic"], None),
    ("T1090", "Proxy", ["command-and-control"], ["Windows", "Linux"], ["Network Traffic"], None),
    ("T1105", "Ingress Tool Transfer", ["command-and-control"], ["Windows", "Linux", "macOS"], ["Network Traffic", "File"], None),
    ("T1041", "Exfiltration Over C2 Channel", ["exfiltration"], ["Windows", "Linux", "macOS"], ["Network Traffic"], None),
    ("T1048", "Exfiltration Over Alternative Protocol", ["exfiltration"], ["Windows", "Linux"], ["Network Traffic"], None),
    ("T1567", "Exfiltration Over Web Service", ["exfiltration"], ["Windows", "Linux", "macOS"], ["Network Traffic"], None),
    ("T1486", "Data Encrypted for Impact", ["impact"], ["Windows", "Linux"], ["File", "Process"], None),
    ("T1489", "Service Stop", ["impact"], ["Windows", "Linux"], ["Service", "Process"], None),
    ("T1490", "Inhibit System Recovery", ["impact"], ["Windows"], ["Command", "Process"], None),
]

GROUPES = [
    ("G0016", "APT29", ["Cozy Bear", "Nobelium"], "espionnage"),
    ("G0007", "APT28", ["Fancy Bear", "Sofacy"], "espionnage"),
    ("G0032", "Lazarus Group", ["Hidden Cobra"], "espionnage_lucratif"),
    ("G0008", "Carbanak", ["Anunak"], "lucratif"),
    ("G0046", "FIN7", ["Carbon Spider"], "lucratif"),
    ("G0102", "Wizard Spider", ["TEMP.MixMaster"], "rancongiciel"),
    ("G0069", "MuddyWater", ["Static Kitten"], "espionnage"),
    ("G0050", "APT32", ["OceanLotus"], "espionnage"),
    ("G0045", "menuPass", ["APT10", "Stone Panda"], "espionnage"),
    ("G0096", "APT41", ["Winnti"], "espionnage_lucratif"),
]

LOGICIELS = [
    ("S0002", "Mimikatz", "outil"),
    ("S0154", "Cobalt Strike", "outil"),
    ("S0357", "Impacket", "outil"),
    ("S0029", "PsExec", "outil"),
    ("S0521", "BloodHound", "outil"),
    ("S0552", "AdFind", "outil"),
    ("S0575", "Conti", "maliciel"),
    ("S0266", "TrickBot", "maliciel"),
    ("S0483", "IcedID", "maliciel"),
    ("S0154b", "Beacon", "maliciel"),
    ("S0106", "cmd", "outil"),
    ("S0192", "Pupy", "outil"),
]

MITIGATIONS = [
    ("M1032", "Authentification multifacteur"),
    ("M1026", "Gestion des comptes a privileges"),
    ("M1017", "Sensibilisation des utilisateurs"),
    ("M1051", "Mise a jour des logiciels"),
    ("M1049", "Antivirus / antimaliciel"),
    ("M1030", "Segmentation reseau"),
    ("M1027", "Politique de mots de passe"),
    ("M1038", "Prevention d'execution"),
    ("M1047", "Audit"),
    ("M1053", "Sauvegarde des donnees"),
    ("M1037", "Filtrage du trafic reseau"),
    ("M1042", "Desactivation de fonctionnalites"),
]


def generer_attack(rng: np.random.Generator) -> dict:
    """Construit un sous-ensemble ATT&CK + un bundle de type STIX 2.1."""
    tactiques = [{"id": i, "shortname": s, "nom_fr": f} for i, s, f in TACTIQUES]
    techniques = []
    for tid, nom, tacs, plats, sources, parent in TECHNIQUES:
        techniques.append({
            "id": tid,
            "nom": nom,
            "tactiques": tacs,
            "plateformes": plats,
            "sources_donnees": sources,
            "sous_technique_de": parent,
            "est_sous_technique": parent is not None,
            "description": (
                f"L'adversaire recourt a « {nom} » dans le cadre de la ou des "
                f"tactiques {', '.join(tacs)}. Detection possible via : "
                f"{', '.join(sources)}."
            ),
        })

    ids_tech = [t["id"] for t in techniques]

    # Relations groupe -> technique (chaque groupe a un profil de tactiques favori)
    rel_groupes = []
    for gid, nom, alias, motiv in GROUPES:
        k = int(rng.integers(9, 20))
        choisies = rng.choice(ids_tech, size=k, replace=False)
        for t in choisies:
            rel_groupes.append({"groupe": gid, "technique": str(t),
                                "type": "utilise"})

    rel_logiciels = []
    for sid, nom, cat in LOGICIELS:
        k = int(rng.integers(3, 9))
        for t in rng.choice(ids_tech, size=k, replace=False):
            rel_logiciels.append({"logiciel": sid, "technique": str(t),
                                  "type": "implemente"})

    rel_mitigations = []
    for mid, nom in MITIGATIONS:
        k = int(rng.integers(4, 12))
        for t in rng.choice(ids_tech, size=k, replace=False):
            rel_mitigations.append({"mitigation": mid, "technique": str(t),
                                    "type": "attenue"})

    sous_ensemble = {
        "_avertissement": (
            "Sous-ensemble pedagogique. Les identifiants et noms de techniques "
            "sont ceux du referentiel public MITRE ATT&CK ; les descriptions et "
            "les relations sont simplifiees / synthetiques et ne doivent pas "
            "etre utilisees en production."
        ),
        "tactiques": tactiques,
        "techniques": techniques,
        "groupes": [{"id": g, "nom": n, "alias": a, "motivation": m}
                    for g, n, a, m in GROUPES],
        "logiciels": [{"id": s, "nom": n, "categorie": c} for s, n, c in LOGICIELS],
        "mitigations": [{"id": m, "nom": n} for m, n in MITIGATIONS],
        "relations": rel_groupes + rel_logiciels + rel_mitigations,
    }

    # --- Variante « STIX 2.1 simplifiee » ---------------------------------
    objets = []
    for t in techniques:
        objets.append({
            "type": "attack-pattern",
            "id": f"attack-pattern--{t['id'].lower().replace('.', '-')}",
            "name": t["nom"],
            "description": t["description"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": t["id"]}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": p}
                for p in t["tactiques"]
            ],
            "x_mitre_platforms": t["plateformes"],
            "x_mitre_is_subtechnique": t["est_sous_technique"],
        })
    for gid, nom, alias, motiv in GROUPES:
        objets.append({
            "type": "intrusion-set",
            "id": f"intrusion-set--{gid.lower()}",
            "name": nom,
            "aliases": [nom] + alias,
            "primary_motivation": motiv,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": gid}
            ],
        })
    for sid, nom, cat in LOGICIELS:
        objets.append({
            "type": "tool" if cat == "outil" else "malware",
            "id": f"{'tool' if cat == 'outil' else 'malware'}--{sid.lower()}",
            "name": nom,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": sid}
            ],
        })
    for mid, nom in MITIGATIONS:
        objets.append({
            "type": "course-of-action",
            "id": f"course-of-action--{mid.lower()}",
            "name": nom,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": mid}
            ],
        })

    index_type = {}
    for gid, *_ in GROUPES:
        index_type[gid] = f"intrusion-set--{gid.lower()}"
    for sid, nom, cat in LOGICIELS:
        index_type[sid] = f"{'tool' if cat == 'outil' else 'malware'}--{sid.lower()}"
    for mid, _ in MITIGATIONS:
        index_type[mid] = f"course-of-action--{mid.lower()}"

    for r in sous_ensemble["relations"]:
        source_key = r.get("groupe") or r.get("logiciel") or r.get("mitigation")
        rel_type = {"utilise": "uses", "implemente": "uses",
                    "attenue": "mitigates"}[r["type"]]
        cible = f"attack-pattern--{r['technique'].lower().replace('.', '-')}"
        objets.append({
            "type": "relationship",
            "id": f"relationship--{source_key.lower()}-{rel_type}-"
                  f"{r['technique'].lower().replace('.', '-')}",
            "relationship_type": rel_type,
            "source_ref": index_type[source_key],
            "target_ref": cible,
        })

    bundle = {"type": "bundle", "id": "bundle--iaml-attack-subset",
              "spec_version": "2.1", "objects": objets}
    return {"sous_ensemble": sous_ensemble, "bundle": bundle}


# --------------------------------------------------------------------------
# 3. Vulnerabilites (CVE synthetiques) et exposition des actifs
# --------------------------------------------------------------------------
PRODUITS = [
    ("Serveur web Aurora", "AuroraSoft", ["T1190"]),
    ("Passerelle VPN Kestrel", "Kestrel Networks", ["T1133", "T1190"]),
    ("Suite bureautique Nimbus", "Nimbus Corp", ["T1204", "T1566.001"]),
    ("Noyau Linux (distribution interne)", "Communaute", ["T1068"]),
    ("Hyperviseur Volta", "Volta Systems", ["T1068"]),
    ("Client de messagerie Larus", "Larus Ltd", ["T1566.002"]),
    ("Base de donnees Coral", "Coral DB", ["T1190", "T1005"]),
    ("Agent de sauvegarde Petra", "Petra Backup", ["T1490"]),
    ("Console d'administration Onyx", "Onyx IT", ["T1078", "T1021"]),
    ("Automate industriel Zephyr", "Zephyr Automation", ["T1489"]),
]


def generer_cve(rng: np.random.Generator, n: int = 420) -> pd.DataFrame:
    idx = rng.integers(0, len(PRODUITS), n)
    produit = [PRODUITS[i][0] for i in idx]
    editeur = [PRODUITS[i][1] for i in idx]
    technique = [str(rng.choice(PRODUITS[i][2])) for i in idx]
    cvss = np.round(np.clip(rng.beta(5, 3, n) * 10, 0.1, 10.0), 1)
    exploit_connu = rng.random(n) < sigmoid((cvss - 8.0) * 0.9)
    return pd.DataFrame({
        "cve_id": [f"CVE-{int(a)}-{1000 + i:04d}"
                   for i, a in enumerate(rng.integers(2021, 2026, n))],
        "produit": produit,
        "editeur": editeur,
        "cvss_v3": cvss,
        "severite": pd.cut(cvss, [0, 3.9, 6.9, 8.9, 10],
                           labels=["faible", "moyenne", "elevee", "critique"]),
        "exploit_public": exploit_connu,
        "exploite_dans_la_nature": exploit_connu & (rng.random(n) < 0.28),
        "technique_attack": technique,
        "description": [
            f"Vulnerabilite affectant {p} permettant a un attaquant distant "
            f"de compromettre la confidentialite ou l'integrite du service."
            for p in produit
        ],
    })


def generer_expositions(rng: np.random.Generator, assets: pd.DataFrame,
                        cve: pd.DataFrame) -> pd.DataFrame:
    lignes = []
    for _, a in assets.iterrows():
        # Plus la machine est en retard de mise a jour, plus elle cumule de CVE.
        lam = 1.5 + a["derniere_maj_jours"] / 45.0
        k = int(rng.poisson(lam))
        for cid in rng.choice(cve["cve_id"].to_numpy(), size=min(k, 12),
                              replace=False):
            lignes.append({"asset_id": a["asset_id"], "cve_id": cid,
                           "detectee_le": (T0 + timedelta(
                               days=int(rng.integers(0, JOURS)))).date().isoformat(),
                           "corrigee": bool(rng.random() < 0.45)})
    return pd.DataFrame(lignes)


# --------------------------------------------------------------------------
# 4. Alertes SIEM etiquetees (apprentissage supervise, atelier 04)
# --------------------------------------------------------------------------
# (regle, libelle, famille, tactique, technique, severite SIEM par defaut)
REGLES = [
    ("R-001", "Echecs d'authentification repetes", "bruteforce", "credential-access", "T1110.003", 2),
    ("R-002", "Connexion depuis un pays inhabituel", "acces", "initial-access", "T1078", 3),
    ("R-003", "PowerShell encode (base64)", "execution", "execution", "T1059.001", 3),
    ("R-004", "Acces memoire LSASS", "credential", "credential-access", "T1003.001", 4),
    ("R-005", "Creation de tache planifiee", "persistance", "persistence", "T1053.005", 2),
    ("R-006", "Effacement du journal de securite", "evasion", "defense-evasion", "T1070.001", 4),
    ("R-007", "Balise periodique vers domaine inconnu", "c2", "command-and-control", "T1071.001", 3),
    ("R-008", "Requetes DNS de longueur anormale", "c2", "command-and-control", "T1071.004", 3),
    ("R-009", "Transfert sortant volumineux", "exfil", "exfiltration", "T1048", 3),
    ("R-010", "Depot sur service de partage en ligne", "exfil", "exfiltration", "T1567", 2),
    ("R-011", "Scan de ports interne", "recon", "discovery", "T1046", 2),
    ("R-012", "Enumeration Active Directory", "recon", "discovery", "T1087", 2),
    ("R-013", "Connexion RDP entre postes de travail", "lateral", "lateral-movement", "T1021.001", 3),
    ("R-014", "Execution distante via SMB", "lateral", "lateral-movement", "T1021.002", 3),
    ("R-015", "Antivirus desactive", "evasion", "defense-evasion", "T1562.001", 3),
    ("R-016", "Chiffrement massif de fichiers", "impact", "impact", "T1486", 4),
    ("R-017", "Suppression des cliches instantanes", "impact", "impact", "T1490", 4),
    ("R-018", "Peripherique USB de stockage monte", "politique", "collection", "T1005", 1),
    ("R-019", "Navigation vers categorie interdite", "politique", "reconnaissance", "T1595", 1),
    ("R-020", "Logiciel non homologue installe", "politique", "execution", "T1204", 1),
    ("R-021", "Creation de compte local", "persistance", "persistence", "T1136", 2),
    ("R-022", "Injection de code dans un processus", "execution", "defense-evasion", "T1055", 4),
]

FAMILLES_A_RISQUE = {"credential", "c2", "exfil", "impact", "lateral"}
FAMILLES_BRUYANTES = {"politique", "recon"}


def generer_alertes(rng: np.random.Generator, assets: pd.DataFrame,
                    users: pd.DataFrame, n: int = 14000) -> pd.DataFrame:
    ts = horodatages(rng, n, biais_ouvrable=0.62)
    jour_relatif = np.array([(t - T0).days for t in ts])

    # Les regles bruyantes dominent le volume : loi de puissance sur les regles.
    poids = np.array([
        3.0 if r[2] in FAMILLES_BRUYANTES else (0.7 if r[2] in FAMILLES_A_RISQUE else 1.4)
        for r in REGLES
    ])
    poids = poids / poids.sum()
    ridx = rng.choice(len(REGLES), n, p=poids)

    # --- Derive : sur les 30 derniers jours, une nouvelle regle EDR sature le SOC
    fenetre_derive = jour_relatif >= (JOURS - 30)
    remplace = fenetre_derive & (rng.random(n) < 0.35)
    ridx = np.where(remplace, REGLES.index(
        ("R-020", "Logiciel non homologue installe", "politique", "execution", "T1204", 1)
    ), ridx)

    regle_id = np.array([REGLES[i][0] for i in ridx])
    regle_nom = np.array([REGLES[i][1] for i in ridx])
    famille = np.array([REGLES[i][2] for i in ridx])
    tactique = np.array([REGLES[i][3] for i in ridx])
    technique = np.array([REGLES[i][4] for i in ridx])
    severite = np.array([REGLES[i][5] for i in ridx])

    a = assets.sample(n, replace=True, random_state=int(rng.integers(1e6))).reset_index(drop=True)
    u = users.sample(n, replace=True, random_state=int(rng.integers(1e6))).reset_index(drop=True)

    src_externe = np.isin(famille, ["acces", "c2", "exfil"]) | (rng.random(n) < 0.25)
    src_ip = np.where(src_externe, ip_externe(rng, n), ip_interne(rng, n))
    reputation = np.where(
        src_externe,
        np.clip(rng.beta(1.6, 4.0, n) * 100, 0, 100),  # score de menace 0-100
        rng.uniform(0, 12, n),
    )
    # La derive augmente aussi le bruit de reputation sur la periode recente.
    reputation = np.where(fenetre_derive, np.clip(reputation + rng.normal(8, 6, n), 0, 100),
                          reputation)

    nb_correles = rng.poisson(np.where(np.isin(famille, list(FAMILLES_A_RISQUE)), 9, 3)) + 1
    duree = np.round(np.abs(rng.normal(120, 90, n)) + nb_correles * 5, 1)
    heure = np.array([t.hour for t in ts])
    jour_sem = np.array([t.weekday() for t in ts])
    hors_ouvrable = (heure < 7) | (heure > 19) | (jour_sem >= 5)

    octets = np.where(
        famille == "exfil",
        rng.lognormal(17.5, 1.6, n),
        rng.lognormal(11.0, 1.8, n),
    ).astype(np.int64)

    port = np.where(
        famille == "c2", rng.choice([80, 443, 53, 8080], n, p=[.2, .5, .2, .1]),
        rng.choice([22, 80, 135, 389, 443, 445, 3389, 5985, 8080],
                   n, p=[.08, .16, .1, .08, .24, .12, .1, .06, .06]),
    )

    # Compteurs de contexte (volumetrie recente par hote / par compte)
    df_tmp = pd.DataFrame({"ts": ts, "host": a["hostname"], "user": u["username"]})
    df_tmp["jour"] = jour_relatif
    nb_host = df_tmp.groupby(["host", "jour"])["ts"].transform("count").to_numpy()
    nb_user = df_tmp.groupby(["user", "jour"])["ts"].transform("count").to_numpy()

    # --- Modele generatif du verdict analyste (la « verite terrain ») --------
    logit = (
        -4.10
        + 1.25 * np.isin(famille, list(FAMILLES_A_RISQUE))
        - 0.95 * np.isin(famille, list(FAMILLES_BRUYANTES))
        + 0.024 * reputation
        + 0.42 * (a["criticite"].to_numpy() >= 3)
        + 0.55 * u["compte_admin"].to_numpy()
        + 0.48 * hors_ouvrable
        + 0.38 * np.log1p(nb_correles)
        + 0.35 * (octets > 5e7)
        + 0.30 * (nb_host > 6)
        + 0.25 * (severite >= 4)
        - 0.40 * u["mfa_actif"].to_numpy()
        - 0.30 * a["agent_edr"].to_numpy()
        + rng.normal(0, 0.55, n)  # part irreductible : l'analyste voit plus que le SIEM
    )
    p_tp = sigmoid(logit)
    est_tp = rng.random(n) < p_tp

    # --- Variable FUITEE : connue seulement APRES le traitement de l'alerte --
    temps_analyste = np.round(
        np.where(est_tp, rng.gamma(6, 7, n), rng.gamma(2, 2.5, n)) + 1.5, 1
    )

    df = pd.DataFrame({
        "alert_id": [f"ALT-{i:06d}" for i in range(n)],
        "horodatage": ts,
        "regle_id": regle_id,
        "regle_nom": regle_nom,
        "famille_regle": famille,
        "tactique_attack": tactique,
        "technique_attack": technique,
        "severite_siem": severite,
        "source_ip": src_ip,
        "source_externe": src_externe,
        "reputation_source": np.round(reputation, 1),
        "destination_ip": a["ip"].to_numpy(),
        "port_destination": port,
        "protocole": np.where(np.isin(port, [53]), "udp", "tcp"),
        "hostname": a["hostname"].to_numpy(),
        "zone": a["zone"].to_numpy(),
        "criticite_actif": a["criticite"].to_numpy(),
        "agent_edr": a["agent_edr"].to_numpy(),
        "username": u["username"].to_numpy(),
        "compte_admin": u["compte_admin"].to_numpy(),
        "mfa_actif": u["mfa_actif"].to_numpy(),
        "departement": u["departement"].to_numpy(),
        "evenements_correles": nb_correles,
        "duree_fenetre_s": duree,
        "octets_transferes": octets,
        "hors_heures_ouvrables": hors_ouvrable,
        "alertes_hote_24h": nb_host,
        "alertes_compte_24h": nb_user,
        "temps_traitement_analyste_min": temps_analyste,   # <-- FUITE
        "verdict": np.where(est_tp, "vrai_positif", "faux_positif"),
    })

    # Qualite des donnees : valeurs manquantes et doublons, volontairement.
    manquants = rng.random(n) < 0.035
    df.loc[manquants, "reputation_source"] = np.nan
    manquants2 = rng.random(n) < 0.02
    df.loc[manquants2, "departement"] = None
    doublons = df.sample(frac=0.012, random_state=7)
    df = pd.concat([df, doublons], ignore_index=True)
    return df.sort_values("horodatage").reset_index(drop=True)


# --------------------------------------------------------------------------
# 5. Journaux d'evenements systeme (apprentissage non supervise, ateliers 05-06)
# --------------------------------------------------------------------------
# Chaque hote suit un profil d'usage latent : c'est ce que le clustering doit
# retrouver sans jamais voir l'etiquette.
PROFILS = {
    "bureautique": {
        "evts": {"ouverture_session": .18, "fermeture_session": .16, "processus": .34,
                 "acces_fichier": .22, "echec_auth": .04, "requete_dns": .05,
                 "elevation": .005, "modif_registre": .005},
        "procs": ["winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "teams.exe"],
        "volume": (90, 30), "nuit": 0.04, "hotes": 0.50,
    },
    "developpeur": {
        "evts": {"ouverture_session": .10, "fermeture_session": .09, "processus": .48,
                 "acces_fichier": .20, "echec_auth": .03, "requete_dns": .08,
                 "elevation": .015, "modif_registre": .005},
        "procs": ["code.exe", "python.exe", "git.exe", "docker.exe", "node.exe", "powershell.exe"],
        "volume": (240, 70), "nuit": 0.12, "hotes": 0.15,
    },
    "admin_systeme": {
        "evts": {"ouverture_session": .16, "fermeture_session": .13, "processus": .30,
                 "acces_fichier": .12, "echec_auth": .06, "requete_dns": .06,
                 "elevation": .12, "modif_registre": .05},
        "procs": ["powershell.exe", "mmc.exe", "psexec.exe", "reg.exe", "net.exe", "ssh.exe"],
        "volume": (170, 60), "nuit": 0.22, "hotes": 0.12,
    },
    "serveur_batch": {
        "evts": {"ouverture_session": .04, "fermeture_session": .03, "processus": .55,
                 "acces_fichier": .30, "echec_auth": .01, "requete_dns": .05,
                 "elevation": .01, "modif_registre": .01},
        "procs": ["cron", "backup_agent", "java", "postgres", "rsync"],
        "volume": (420, 110), "nuit": 0.48, "hotes": 0.16,
    },
    "poste_itinerant": {
        "evts": {"ouverture_session": .26, "fermeture_session": .22, "processus": .24,
                 "acces_fichier": .12, "echec_auth": .09, "requete_dns": .06,
                 "elevation": .005, "modif_registre": .005},
        "procs": ["chrome.exe", "vpnclient.exe", "outlook.exe", "zoom.exe"],
        "volume": (70, 30), "nuit": 0.18, "hotes": 0.07,
    },
}

PROFIL_COMPROMIS = {
    "evts": {"ouverture_session": .12, "fermeture_session": .06, "processus": .34,
             "acces_fichier": .14, "echec_auth": .12, "requete_dns": .12,
             "elevation": .06, "modif_registre": .04},
    "procs": ["powershell.exe", "rundll32.exe", "certutil.exe", "wmic.exe",
              "mshta.exe", "7z.exe"],
    "volume": (200, 60), "nuit": 0.55,
}

EVENT_ID = {"ouverture_session": 4624, "fermeture_session": 4634, "processus": 4688,
            "acces_fichier": 4663, "echec_auth": 4625, "requete_dns": 22,
            "elevation": 4672, "modif_registre": 4657}

TYPES = list(EVENT_ID)

# Affinites de succession : un journal reel n'est PAS une suite de tirages
# independants. Une ouverture de session est suivie de processus, un echec
# d'authentification appelle un autre echec, une elevation precede une
# modification du registre. C'est cette structure sequentielle que l'atelier 06
# apprend a modeliser ; sans elle, predire l'evenement suivant serait impossible.
AFFINITES = {
    "ouverture_session": {"processus": 4.0, "acces_fichier": 3.0, "requete_dns": 2.0,
                          "elevation": 2.0, "modif_registre": 1.0,
                          "fermeture_session": 0.5, "ouverture_session": 0.3,
                          "echec_auth": 0.3},
    "fermeture_session": {"ouverture_session": 4.0, "processus": 0.6,
                          "acces_fichier": 0.5, "requete_dns": 0.5,
                          "elevation": 0.3, "modif_registre": 0.3,
                          "echec_auth": 0.5, "fermeture_session": 0.2},
    "processus": {"processus": 3.0, "acces_fichier": 3.0, "requete_dns": 2.0,
                  "modif_registre": 1.5, "fermeture_session": 1.0, "elevation": 1.0,
                  "ouverture_session": 0.3, "echec_auth": 0.3},
    "acces_fichier": {"acces_fichier": 4.0, "processus": 2.0,
                      "fermeture_session": 1.5, "requete_dns": 0.6,
                      "elevation": 0.4, "modif_registre": 0.4,
                      "ouverture_session": 0.3, "echec_auth": 0.2},
    "echec_auth": {"echec_auth": 6.0, "ouverture_session": 2.0, "processus": 0.3,
                   "acces_fichier": 0.2, "requete_dns": 0.2, "elevation": 0.2,
                   "modif_registre": 0.2, "fermeture_session": 0.4},
    "requete_dns": {"requete_dns": 3.0, "processus": 2.0, "acces_fichier": 1.0,
                    "fermeture_session": 0.6, "elevation": 0.4,
                    "modif_registre": 0.3, "ouverture_session": 0.3,
                    "echec_auth": 0.2},
    "elevation": {"processus": 4.0, "modif_registre": 3.0, "acces_fichier": 1.5,
                  "requete_dns": 0.6, "elevation": 0.8, "fermeture_session": 0.5,
                  "ouverture_session": 0.2, "echec_auth": 0.2},
    "modif_registre": {"modif_registre": 2.0, "processus": 2.0, "elevation": 1.5,
                       "acces_fichier": 1.0, "requete_dns": 0.5,
                       "fermeture_session": 0.6, "ouverture_session": 0.2,
                       "echec_auth": 0.2},
}

# L'attaquant enchaine differemment : reconnaissance d'identifiants, elevation,
# outil telecharge, balise DNS, collecte de fichiers.
AFFINITES_ATTAQUANT = {
    "echec_auth": {"elevation": 4.0, "ouverture_session": 3.0},
    "elevation": {"requete_dns": 3.0, "processus": 4.0},
    "processus": {"requete_dns": 4.0, "acces_fichier": 2.5},
    "requete_dns": {"acces_fichier": 3.0, "requete_dns": 4.0},
    "acces_fichier": {"requete_dns": 3.0, "acces_fichier": 3.0},
}


def matrice_transition(marginales: dict, attaquant: bool = False) -> dict:
    """Combine les affinites de succession et les frequences propres au profil."""
    matrice = {}
    for depuis in TYPES:
        aff = dict(AFFINITES[depuis])
        if attaquant and depuis in AFFINITES_ATTAQUANT:
            aff.update(AFFINITES_ATTAQUANT[depuis])
        # Racine carree des frequences : le profil module la chaine sans ecraser
        # la structure de succession, qui doit rester apprenable.
        poids = np.array([aff.get(v, 0.5) * max(marginales.get(v, 0.0), 1e-3) ** 1.0
                          for v in TYPES])
        matrice[depuis] = poids / poids.sum()
    return matrice


def generer_evenements(rng: np.random.Generator, assets: pd.DataFrame,
                       users: pd.DataFrame, jours: int = 30):
    """Journaux systeme par hote, generes par sessions markoviennes.

    Deux proprietes voulues :
      * une STRUCTURE SEQUENTIELLE reelle (atelier 06) ;
      * une compromission ADDITIVE et localisee dans le temps (ateliers 05, 06) :
        elle se surajoute au comportement habituel de la machine sur les derniers
        jours, au lieu de le remplacer. Sans cela, les hotes compromis formeraient
        un groupe homogene que n'importe quel partitionnement isolerait.
    """
    noms = list(PROFILS)
    proba = np.array([PROFILS[n]["hotes"] for n in noms])
    proba = proba / proba.sum()
    affectation = rng.choice(noms, len(assets), p=proba)

    matrices = {n: matrice_transition(PROFILS[n]["evts"]) for n in noms}
    matrice_attaquant = matrice_transition(PROFIL_COMPROMIS["evts"], attaquant=True)

    compromis = set(rng.choice(len(assets), 6, replace=False).tolist())
    jour_compromission = {i: int(rng.integers(jours - 12, jours - 5)) for i in compromis}
    intensite = {i: float(rng.uniform(0.25, 0.50)) for i in compromis}

    def session(matrice, conf, longueur, debut, hote, comptes, attaquant):
        """Une session = une marche aleatoire dans la chaine, horodatee."""
        etat = "echec_auth" if (attaquant and rng.random() < 0.35) else "ouverture_session"
        compte = str(rng.choice(comptes))
        instant = debut
        sortie = []
        for _ in range(longueur):
            sortie.append((
                instant, hote, compte, EVENT_ID[etat], etat,
                str(rng.choice(conf["procs"])) if etat in ("processus", "elevation") else "",
                int(rng.choice([2, 3, 10])) if etat.endswith("session") else 0,
                "echec" if etat == "echec_auth" else "succes",
            ))
            instant = instant + timedelta(seconds=float(rng.exponential(150)) + 1)
            etat = str(rng.choice(TYPES, p=matrice[etat]))
        return sortie

    lignes = []
    for i, (_, actif) in enumerate(assets.iterrows()):
        profil = affectation[i]
        conf = PROFILS[profil]
        matrice = matrices[profil]
        comptes = users.sample(
            int(rng.integers(1, 4)), random_state=int(rng.integers(1e6))
        )["username"].tolist()

        for j in range(jours):
            n_evt = max(6, int(rng.normal(*conf["volume"]) / 10))
            actif_compromis = (i in compromis) and j >= jour_compromission[i]
            n_att = int(n_evt * intensite[i]) if actif_compromis else 0

            for conf_src, mat, n, att in (
                (conf, matrice, n_evt - n_att, False),
                (PROFIL_COMPROMIS, matrice_attaquant, n_att, True),
            ):
                restant = n
                while restant > 0:
                    longueur = min(restant, int(rng.integers(4, 16)))
                    restant -= longueur
                    nuit = rng.random() < conf_src["nuit"]
                    heure = (rng.uniform(0, 6) if nuit
                             else float(np.clip(rng.normal(13, 3), 7, 20)))
                    debut = T0 + timedelta(days=j, hours=heure,
                                           minutes=int(rng.integers(0, 60)))
                    lignes.extend(session(mat, conf_src, longueur, debut,
                                          actif["hostname"], comptes, att))

    ev = pd.DataFrame(lignes, columns=[
        "horodatage", "hostname", "username", "event_id", "type_evenement",
        "processus", "type_ouverture_session", "statut",
    ]).sort_values("horodatage").reset_index(drop=True)

    verite = pd.DataFrame({
        "hostname": assets["hostname"],
        "profil_usage": affectation,
        "compromis": [i in compromis for i in range(len(assets))],
        "jour_compromission": [jour_compromission.get(i, -1) for i in range(len(assets))],
    })
    return ev, verite


# --------------------------------------------------------------------------
# 6. Flux reseau (detection d'anomalies, atelier 08)
# --------------------------------------------------------------------------
# Services externes legitimes que les postes contactent en permanence : sans eux,
# toute paire (source, destination) recurrente serait anormale et l'exercice de
# detection de balises C2 n'aurait aucun faux positif a discuter.
SERVICES_LEGITIMES = [
    ("maj_systeme", 443, 3),
    ("cdn_contenu", 443, 6),
    ("saas_bureautique", 443, 5),
    ("resolveur_dns", 53, 2),
    ("telemetrie_editeur", 443, 3),
    ("horodatage_ntp", 123, 2),
]


def generer_netflow(rng: np.random.Generator, assets: pd.DataFrame,
                    n_normal: int = 78000):
    ips = assets["ip"].to_numpy()

    # --- Catalogue des destinations externes legitimes recurrentes -----------
    catalogue = []
    for service, port, k in SERVICES_LEGITIMES:
        for ip in ip_externe(rng, k):
            catalogue.append((service, str(ip), port))

    # Deux sous-ensembles distincts : la navigation « a la demande » d'un cote,
    # les services strictement periodiques de l'autre (NTP, remontee d'agent).
    PERIODIQUES = {"horodatage_ntp", "telemetrie_editeur"}
    navigation = [c for c in catalogue if c[0] not in PERIODIQUES]
    periodiques = [c for c in catalogue if c[0] in PERIODIQUES]
    cat_ips = np.array([c[1] for c in navigation])
    cat_ports = np.array([c[2] for c in navigation])

    # Quelques serveurs internes tres sollicites (AD, partage, proxy, supervision)
    serveurs_internes = rng.choice(ips, 8, replace=False)

    src = rng.choice(ips, n_normal)
    tirage = rng.random(n_normal)
    idx_cat = rng.integers(0, len(navigation), n_normal)

    # 48 % vers un service externe legitime, 27 % vers un serveur interne,
    # 25 % vers une destination externe ponctuelle.
    dst = np.where(
        tirage < 0.48, cat_ips[idx_cat],
        np.where(tirage < 0.75, rng.choice(serveurs_internes, n_normal),
                 ip_externe(rng, n_normal)),
    )
    ports = np.where(
        tirage < 0.48, cat_ports[idx_cat],
        np.where(tirage < 0.75,
                 rng.choice([445, 389, 88, 3128, 22], n_normal,
                            p=[.30, .22, .18, .20, .10]),
                 rng.choice([80, 443, 8080, 25, 3389], n_normal,
                            p=[.24, .52, .12, .06, .06])),
    )

    duree = np.round(np.abs(rng.lognormal(0.6, 1.2, n_normal)), 2)
    oct_env = (rng.lognormal(7.2, 1.5, n_normal) * (1 + duree / 20)).astype(np.int64)
    oct_rec = (oct_env * rng.lognormal(1.1, 0.9, n_normal)).astype(np.int64)

    ts = horodatages(rng, n_normal, jours=14, biais_ouvrable=0.8)
    flux = pd.DataFrame({
        "horodatage": ts,
        "ip_source": src,
        "ip_destination": dst,
        "port_destination": ports,
        "protocole": np.where(np.isin(ports, [53, 123]), "udp", "tcp"),
        "duree_s": duree,
        "octets_envoyes": oct_env,
        "octets_recus": oct_rec,
        "paquets_envoyes": np.maximum(1, (oct_env / rng.uniform(500, 1400, n_normal))).astype(int),
        "paquets_recus": np.maximum(1, (oct_rec / rng.uniform(500, 1400, n_normal))).astype(int),
    })
    flux["categorie_reelle"] = "normal"

    # --- Balises LEGITIMES : NTP, remontee d'agent EDR, supervision ---------
    # Elles sont periodiques comme un C2 : ce sont les faux positifs a discuter.
    # Chaque destination periodique est contactee par PLUSIEURS hotes : c'est ce
    # qui la distingue d'un serveur de commande, contacte par un seul poste.
    legitimes = []
    for hote in rng.choice(ips, 42, replace=False):
        service, cible, port = periodiques[int(rng.integers(0, len(periodiques)))]
        periode = 64.0 if service == "horodatage_ntp" else float(rng.choice([300, 600]))
        debut = T0 + timedelta(hours=float(rng.uniform(0, 24)))
        for k in range(int(rng.integers(200, 500))):
            legitimes.append({
                "horodatage": debut + timedelta(
                    seconds=k * periode + float(rng.normal(0, periode * 0.05))),
                "ip_source": str(hote), "ip_destination": cible,
                "port_destination": port,
                "protocole": "udp" if port == 123 else "tcp",
                "duree_s": round(float(abs(rng.normal(0.3, 0.1))), 3),
                "octets_envoyes": int(abs(rng.normal(560 if port == 123 else 2100, 120))),
                "octets_recus": int(abs(rng.normal(520 if port == 123 else 900, 100))),
                "paquets_envoyes": int(rng.integers(1, 6)),
                "paquets_recus": int(rng.integers(1, 5)),
                "categorie_reelle": "normal",
            })
    flux = pd.concat([flux, pd.DataFrame(legitimes)], ignore_index=True)

    anomalies = []

    # (a) C2 beaconing : intervalle quasi constant, charge utile petite et stable
    for _ in range(6):
        hote = str(rng.choice(ips))
        c2 = str(rng.choice(ip_externe(rng, 1)))
        intervalle = float(rng.choice([30, 60, 120, 300]))
        debut = T0 + timedelta(days=float(rng.integers(0, 12)), hours=float(rng.integers(0, 24)))
        for k in range(int(rng.integers(120, 400))):
            gigue = rng.normal(0, intervalle * 0.03)
            anomalies.append({
                "horodatage": debut + timedelta(seconds=k * intervalle + float(gigue)),
                "ip_source": hote, "ip_destination": c2,
                "port_destination": int(rng.choice([443, 80])), "protocole": "tcp",
                "duree_s": round(float(abs(rng.normal(0.8, 0.15))), 2),
                "octets_envoyes": int(abs(rng.normal(1250, 60))),
                "octets_recus": int(abs(rng.normal(430, 40))),
                "paquets_envoyes": int(rng.integers(4, 8)),
                "paquets_recus": int(rng.integers(3, 6)),
                "categorie_reelle": "c2_beaconing",
            })

    # (b) Exfiltration : gros volume sortant, ratio envoye/recu tres eleve
    for _ in range(9):
        hote = str(rng.choice(ips))
        for k in range(int(rng.integers(4, 22))):
            env = int(rng.lognormal(18.2, 0.7))
            anomalies.append({
                "horodatage": T0 + timedelta(days=float(rng.integers(0, 14)),
                                             hours=float(rng.uniform(0, 5))),
                "ip_source": hote, "ip_destination": str(rng.choice(ip_externe(rng, 1))),
                "port_destination": int(rng.choice([443, 22, 21])), "protocole": "tcp",
                "duree_s": round(float(abs(rng.normal(240, 90))), 2),
                "octets_envoyes": env, "octets_recus": int(env * rng.uniform(0.001, 0.01)),
                "paquets_envoyes": int(env / 1400), "paquets_recus": int(rng.integers(20, 200)),
                "categorie_reelle": "exfiltration",
            })

    # (c) Scan de ports : une source, beaucoup de destinations/ports, flux minuscules
    for _ in range(4):
        hote = str(rng.choice(ips))
        base = T0 + timedelta(days=float(rng.integers(0, 14)), hours=float(rng.uniform(0, 24)))
        for k in range(int(rng.integers(200, 500))):
            anomalies.append({
                "horodatage": base + timedelta(seconds=k * float(rng.uniform(0.05, 0.4))),
                "ip_source": hote, "ip_destination": str(rng.choice(ips)),
                "port_destination": int(rng.integers(1, 65535)), "protocole": "tcp",
                "duree_s": 0.01, "octets_envoyes": int(rng.integers(40, 80)),
                "octets_recus": int(rng.choice([0, 0, 40, 60])),
                "paquets_envoyes": 1, "paquets_recus": int(rng.choice([0, 1])),
                "categorie_reelle": "scan_ports",
            })

    # (d) Tunnel DNS : rafales sur UDP/53, volume sortant anormalement eleve
    for _ in range(4):
        hote = str(rng.choice(ips))
        resolveur = str(rng.choice([c[1] for c in navigation if c[0] == "resolveur_dns"]))
        debut = T0 + timedelta(days=float(rng.integers(0, 14)))
        for k in range(int(rng.integers(200, 600))):
            anomalies.append({
                "horodatage": debut + timedelta(seconds=float(k * rng.uniform(1, 6))),
                "ip_source": hote, "ip_destination": resolveur,
                "port_destination": 53, "protocole": "udp",
                "duree_s": round(float(abs(rng.normal(0.05, 0.02))), 3),
                "octets_envoyes": int(abs(rng.normal(720, 90))),
                "octets_recus": int(abs(rng.normal(180, 40))),
                "paquets_envoyes": 1, "paquets_recus": 1,
                "categorie_reelle": "tunnel_dns",
            })

    flux = pd.concat([flux, pd.DataFrame(anomalies)], ignore_index=True)
    flux = flux.sort_values("horodatage").reset_index(drop=True)
    flux.insert(0, "flow_id", [f"FLW-{i:07d}" for i in range(len(flux))])

    verite = flux[["flow_id", "categorie_reelle"]].copy()
    verite["anomalie"] = verite["categorie_reelle"] != "normal"
    return flux.drop(columns=["categorie_reelle"]), verite


# --------------------------------------------------------------------------
# 7. Journal d'evenements du processus de traitement d'incident (process mining)
# --------------------------------------------------------------------------
ANALYSTES = ({"N1": [f"analyste_n1_{i}" for i in range(1, 9)],
              "N2": [f"analyste_n2_{i}" for i in range(1, 5)],
              "N3": [f"expert_n3_{i}" for i in range(1, 3)],
              "AUTO": ["moteur_correlation"]})

TYPES_INCIDENT = ["hameconnage", "maliciel", "compte_compromis", "exfiltration",
                  "deni_de_service", "usage_abusif", "vulnerabilite_exploitee"]


def _acteur(rng, niveau):
    return str(rng.choice(ANALYSTES[niveau]))


def generer_journal_incidents(rng: np.random.Generator, n_cas: int = 700) -> pd.DataFrame:
    lignes = []
    for c in range(n_cas):
        cas = f"INC-{c:05d}"
        type_inc = str(rng.choice(TYPES_INCIDENT,
                                  p=[.26, .20, .16, .08, .06, .14, .10]))
        priorite = str(rng.choice(["P1", "P2", "P3", "P4"], p=[.05, .18, .42, .35]))
        source = str(rng.choice(["SIEM", "EDR", "utilisateur", "CTI", "audit"],
                                p=[.45, .27, .18, .07, .03]))
        t = T0 + timedelta(days=float(rng.integers(0, JOURS)),
                           hours=float(rng.uniform(0, 24)))

        def pousser(activite, niveau, minutes_attente):
            nonlocal t
            # File d'attente allongee la nuit et le week-end (goulet d'etranglement)
            facteur = 3.2 if (t.hour < 7 or t.hour > 19 or t.weekday() >= 5) else 1.0
            t = t + timedelta(minutes=float(abs(rng.normal(minutes_attente, minutes_attente * .5))) * facteur)
            lignes.append({
                "case_id": cas, "activite": activite, "horodatage": t,
                "ressource": _acteur(rng, niveau), "niveau": niveau,
                "type_incident": type_inc, "priorite": priorite,
                "source_detection": source,
            })

        pousser("Detection", "AUTO", 0)

        # Ecart de procedure n° 1 : escalade directe sans qualification N1
        # (typiquement la nuit, quand le N1 n'est pas arme). Ces cas donnent
        # matiere a l'analyse de conformite de l'atelier 07.
        escalade_directe = rng.random() < 0.04
        if not escalade_directe:
            pousser("Qualification N1", "N1", 25 if priorite in ("P1", "P2") else 90)

        if not escalade_directe and rng.random() < 0.52:                      # variante majoritaire : faux positif
            pousser("Cloture faux positif", "N1", 8)
            continue

        if rng.random() < 0.55:
            pousser("Enrichissement CTI", "N1", 20)

        pousser("Escalade N2", "N1", 15)
        pousser("Analyse approfondie N2", "N2", 120 if priorite == "P4" else 40)

        # Boucle de reprise : demande d'information complementaire
        for _ in range(int(rng.choice([0, 1, 2, 3], p=[.55, .28, .12, .05]))):
            pousser("Demande d'information", "N2", 30)
            pousser("Analyse approfondie N2", "N2", 180)

        if rng.random() < 0.22:
            pousser("Escalade N3", "N2", 45)
            pousser("Analyse forensique", "N3", 240)

        if rng.random() < 0.18:
            pousser("Cloture faux positif", "N2", 20)
            continue

        # Ecart de procedure n° 2 : cloture prononcee avant le confinement
        # (pression sur les delais), le confinement etant realise apres coup.
        cloture_prematuree = rng.random() < 0.03
        if cloture_prematuree:
            pousser("Cloture", "N1", 20)
        pousser("Confinement", "N2", 35 if priorite in ("P1", "P2") else 150)
        if rng.random() < 0.85:
            pousser("Eradication", "N2", 90)
        pousser("Retablissement", "N2", 120)
        pousser("Redaction du rapport", "N2", 60)
        if not cloture_prematuree:
            pousser("Cloture", "N1", 30)

        if rng.random() < 0.09:                       # reouverture
            pousser("Reouverture", "N1", 2400)
            pousser("Analyse approfondie N2", "N2", 90)
            pousser("Cloture", "N2", 120)

    return pd.DataFrame(lignes).sort_values(["case_id", "horodatage"]).reset_index(drop=True)


# --------------------------------------------------------------------------
# 8. Rapports d'incident en texte libre (donnees non structurees)
# --------------------------------------------------------------------------
GABARITS = {
    "hameconnage": (
        "Le {date}, {n} utilisateurs du service {dept} ont signale un courriel "
        "usurpant l'identite du service {usurpe}. Le message contenait un lien vers "
        "hxxps://{domaine}/login redirigeant vers une page de collecte d'identifiants. "
        "L'expediteur apparent etait {compte}@{domaine}. Le bac a sable a identifie "
        "la piece jointe {fichier} (SHA-256 {hash}). Technique observee : {technique}. "
        "Le domaine a ete bloque sur la passerelle et {n} comptes ont fait l'objet "
        "d'une reinitialisation de mot de passe."
    ),
    "maliciel": (
        "Detection EDR sur le poste {hote} le {date}. Le processus {proc} a lance "
        "une commande encodee puis a etabli une connexion vers {ip} sur le port {port}. "
        "L'empreinte du binaire depose est {hash}. La persistance a ete installee via "
        "{technique}. Le poste a ete isole du reseau a {heure} et une image memoire a "
        "ete prelevee pour analyse."
    ),
    "compte_compromis": (
        "Le compte {compte} du service {dept} a presente {n} echecs d'authentification "
        "suivis d'une connexion reussie depuis {ip} le {date}. Aucune authentification "
        "multifacteur n'etait active. L'attaquant a enumere l'annuaire "
        "({technique}) puis a tente un deplacement lateral vers {hote}. "
        "Le compte a ete desactive et les sessions revoquees."
    ),
    "exfiltration": (
        "Un transfert sortant de {volume} Mo a ete observe depuis {hote} vers {ip} "
        "le {date} entre {heure} et minuit. Les donnees ont ete archivees au prealable "
        "dans {fichier}. Technique : {technique}. La classification des donnees "
        "concernees est en cours ; le flux a ete bloque au niveau du pare-feu."
    ),
    "vulnerabilite_exploitee": (
        "Exploitation de la vulnerabilite {cve} sur {hote} le {date}. La requete "
        "malveillante provenait de {ip}. Une porte derobee a ete deposee "
        "({fichier}, SHA-256 {hash}) et la technique {technique} a ete confirmee. "
        "Le correctif editeur a ete applique le lendemain sur les {n} serveurs exposes."
    ),
    "usage_abusif": (
        "Le {date}, le poste {hote} a installe un logiciel non homologue et a "
        "contacte {ip}. Aucune activite malveillante n'a ete confirmee ; l'evenement "
        "releve de la politique d'usage. Technique associee (a titre indicatif) : "
        "{technique}. Un rappel de la charte a ete adresse au service {dept}."
    ),
}

# La technique citee dans un rapport doit etre coherente avec le type
# d'incident : sinon le croisement « techniques observees chez nous » de
# l'atelier 09 ne serait que du bruit.
TECHNIQUES_PAR_TYPE = {
    "hameconnage": ["T1566", "T1566.001", "T1566.002", "T1204", "T1027"],
    "maliciel": ["T1059.001", "T1055", "T1547.001", "T1053.005", "T1543.003",
                 "T1105", "T1071.001", "T1562.001"],
    "compte_compromis": ["T1078", "T1110", "T1110.003", "T1087", "T1021.001",
                         "T1003.001", "T1558.003"],
    "exfiltration": ["T1560", "T1041", "T1048", "T1567", "T1005"],
    "vulnerabilite_exploitee": ["T1190", "T1068", "T1133", "T1505" ],
    "usage_abusif": ["T1204", "T1595", "T1005"],
}

DOMAINES_FICTIFS = ["portail-rh-secure.example", "mise-a-jour-facture.example",
                    "cdn-static-assets.example", "login-microsft.example",
                    "partage-doc.example", "vpn-acces.example"]
FICHIERS = ["facture_2025.xlsm", "rapport.pdf.exe", "update.dll", "archive.7z",
            "svchosts.exe", "note_interne.docm"]


_NOM_TECHNIQUE = {t[0]: t[1] for t in TECHNIQUES}


def _libelle_technique(rng: np.random.Generator, type_incident: str) -> str:
    candidates = [t for t in TECHNIQUES_PAR_TYPE.get(type_incident, [])
                  if t in _NOM_TECHNIQUE]
    tid = str(rng.choice(candidates)) if candidates else str(rng.choice(list(_NOM_TECHNIQUE)))
    return f"{tid} ({_NOM_TECHNIQUE[tid]})"


def generer_rapports(rng: np.random.Generator, journal: pd.DataFrame,
                     assets: pd.DataFrame, users: pd.DataFrame,
                     cve: pd.DataFrame, dossier: Path, n: int = 180) -> pd.DataFrame:
    dossier.mkdir(parents=True, exist_ok=True)
    resume = journal.groupby("case_id").agg(
        type_incident=("type_incident", "first"),
        priorite=("priorite", "first"),
        debut=("horodatage", "min"),
    ).reset_index()
    resume = resume[resume["type_incident"].isin(GABARITS)]
    echantillon = resume.sample(min(n, len(resume)),
                                random_state=int(rng.integers(1e6)))

    index = []
    for _, r in echantillon.iterrows():
        gabarit = GABARITS[r["type_incident"]]
        texte = gabarit.format(
            date=r["debut"].strftime("%d/%m/%Y"),
            heure=f"{int(rng.integers(0, 24)):02d}h{int(rng.integers(0, 60)):02d}",
            n=int(rng.integers(2, 40)),
            dept=str(rng.choice(DEPARTEMENTS)),
            usurpe=str(rng.choice(["informatique", "paie", "achats", "direction"])),
            domaine=str(rng.choice(DOMAINES_FICTIFS)),
            compte=str(rng.choice(users["username"].to_numpy())),
            fichier=str(rng.choice(FICHIERS)),
            hash="".join(rng.choice(list("0123456789abcdef"), 64)),
            hote=str(rng.choice(assets["hostname"].to_numpy())),
            proc=str(rng.choice(["powershell.exe", "rundll32.exe", "mshta.exe",
                                 "wscript.exe", "certutil.exe"])),
            ip=str(rng.choice(ip_externe(rng, 1))),
            port=int(rng.choice([80, 443, 8080, 4444])),
            volume=int(rng.integers(120, 8000)),
            cve=str(rng.choice(cve["cve_id"].to_numpy())),
            technique=_libelle_technique(rng, r["type_incident"]),
        )
        nom = f"RPT-{r['case_id'][4:]}.txt"
        entete = (
            f"RAPPORT D'INCIDENT (donnee synthetique a usage pedagogique)\n"
            f"Reference : {r['case_id']}\n"
            f"Priorite  : {r['priorite']}\n"
            f"{'-' * 72}\n\n"
        )
        (dossier / nom).write_text(entete + texte + "\n", encoding="utf-8")
        index.append({"case_id": r["case_id"], "fichier": nom,
                      "type_incident": r["type_incident"], "priorite": r["priorite"]})
    return pd.DataFrame(index)


# --------------------------------------------------------------------------
# 9. Corpus bibliographique FICTIF (atelier 11 : entrainement au criblage)
# --------------------------------------------------------------------------
BIBLIO_SUJETS = [
    ("detection d'intrusion par apprentissage profond", "ML"),
    ("graphes de connaissances pour la cyberveille", "KM"),
    ("detection d'anomalies non supervisee sur flux reseau", "DA"),
    ("process mining applique a la reponse a incident", "PM"),
    ("reduction des faux positifs dans un SOC", "ML"),
    ("explicabilite des modeles de detection", "ML"),
    ("extraction d'entites depuis des rapports de menace", "KM"),
    ("apprentissage federe pour la cybersecurite", "ML"),
    ("attaques adverses contre les detecteurs", "ML"),
    ("ontologies de la menace et alignement STIX/ATT&CK", "KM"),
    ("detection de balises C2 par analyse temporelle", "DA"),
    ("modeles de langue pour le triage d'alertes", "ML"),
]
BIBLIO_VENUES = ["Computers & Security", "IEEE TIFS", "ACM CCS", "USENIX Security",
                 "DIMVA", "RAID", "Journal of Cybersecurity", "arXiv (preprint)",
                 "SSTIC", "C&ESAR"]


def generer_biblio(rng: np.random.Generator, n: int = 90) -> pd.DataFrame:
    idx = rng.integers(0, len(BIBLIO_SUJETS), n)
    annee = rng.choice([2021, 2022, 2023, 2024, 2025], n, p=[.10, .15, .22, .28, .25])
    venue = rng.choice(BIBLIO_VENUES, n)
    return pd.DataFrame({
        "ref_id": [f"REF-{i:03d}" for i in range(n)],
        "titre": [f"[FICTIF] Une approche pour la {BIBLIO_SUJETS[i][0]}" for i in idx],
        "auteurs": [f"Auteur{int(rng.integers(1, 99))} et al." for _ in range(n)],
        "annee": annee,
        "venue": venue,
        "type_publication": np.where(venue == "arXiv (preprint)", "preprint",
                                     rng.choice(["article", "conference"], n)),
        "domaine": [BIBLIO_SUJETS[i][1] for i in idx],
        "mots_cles": [BIBLIO_SUJETS[i][0] for i in idx],
        "jeu_de_donnees": rng.choice(
            ["prive/non publie", "CIC-IDS2017", "UNSW-NB15", "synthetique",
             "logs internes", "non precise"], n, p=[.28, .14, .12, .16, .12, .18]),
        "code_disponible": rng.random(n) < 0.34,
        "evaluation_comparative": rng.random(n) < 0.45,
        "nb_citations": rng.poisson(18, n),
        "resume": [
            f"[RESUME FICTIF] Les auteurs proposent une methode de "
            f"{BIBLIO_SUJETS[i][0]}. L'evaluation porte sur un jeu de donnees "
            f"et rapporte des performances superieures a l'etat de l'art."
            for i in idx
        ],
    })


# --------------------------------------------------------------------------
# Point d'entree
# --------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data", help="repertoire de sortie")
    ap.add_argument("--seed", type=int, default=42, help="graine aleatoire")
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    out = Path(args.out)
    (out / "verite_terrain").mkdir(parents=True, exist_ok=True)
    (out / "attack").mkdir(parents=True, exist_ok=True)

    print(f"Generation dans {out.resolve()} (graine={args.seed})")

    assets = generer_assets(rng)
    users = generer_users(rng)
    assets.to_csv(out / "assets.csv", index=False)
    users.to_csv(out / "utilisateurs.csv", index=False)
    print(f"  assets.csv                {len(assets):>7} lignes")
    print(f"  utilisateurs.csv          {len(users):>7} lignes")

    attack = generer_attack(rng)
    (out / "attack" / "attack_subset.json").write_text(
        json.dumps(attack["sous_ensemble"], ensure_ascii=False, indent=2),
        encoding="utf-8")
    (out / "attack" / "attack_bundle_stix.json").write_text(
        json.dumps(attack["bundle"], ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  attack/attack_subset.json {len(attack['sous_ensemble']['techniques']):>7} techniques, "
          f"{len(attack['sous_ensemble']['relations'])} relations")

    cve = generer_cve(rng)
    expo = generer_expositions(rng, assets, cve)
    cve.to_csv(out / "cve.csv", index=False)
    expo.to_csv(out / "vulnerabilites_hotes.csv", index=False)
    print(f"  cve.csv                   {len(cve):>7} lignes")
    print(f"  vulnerabilites_hotes.csv  {len(expo):>7} lignes")

    alertes = generer_alertes(rng, assets, users)
    alertes.to_csv(out / "alertes_siem.csv", index=False)
    taux = (alertes["verdict"] == "vrai_positif").mean()
    print(f"  alertes_siem.csv          {len(alertes):>7} lignes "
          f"({taux:.1%} de vrais positifs)")

    evenements, profils = generer_evenements(rng, assets, users)
    evenements.to_csv(out / "evenements_systeme.csv", index=False)
    profils.to_csv(out / "verite_terrain" / "profils_hotes.csv", index=False)
    print(f"  evenements_systeme.csv    {len(evenements):>7} lignes")

    flux, flux_verite = generer_netflow(rng, assets)
    flux.to_csv(out / "netflow.csv", index=False)
    flux_verite.to_csv(out / "verite_terrain" / "netflow_etiquettes.csv", index=False)
    print(f"  netflow.csv               {len(flux):>7} lignes "
          f"({flux_verite['anomalie'].mean():.2%} d'anomalies)")

    journal = generer_journal_incidents(rng)
    journal.to_csv(out / "journal_incidents.csv", index=False)
    print(f"  journal_incidents.csv     {len(journal):>7} lignes "
          f"({journal['case_id'].nunique()} incidents)")

    index_rapports = generer_rapports(rng, journal, assets, users, cve,
                                      out / "rapports")
    index_rapports.to_csv(out / "rapports_index.csv", index=False)
    print(f"  rapports/*.txt            {len(index_rapports):>7} fichiers")

    biblio = generer_biblio(rng)
    biblio.to_csv(out / "corpus_fictif_pour_exercice.csv", index=False)
    print(f"  corpus_fictif_...csv      {len(biblio):>7} references FICTIVES")

    (out / "LISEZ-MOI.md").write_text(f"""# Jeux de donnees synthetiques — IAML

Genere par `tools/generate_soc_data.py` (graine **{args.seed}**).
**Aucune donnee reelle, aucune donnee personnelle.** Tout est tire de lois
statistiques ; toute ressemblance avec un systeme existant serait fortuite.

| Fichier | Contenu | Ateliers |
|---|---|---|
| `assets.csv` | Inventaire des actifs (CMDB) | 01, 02, 03 |
| `utilisateurs.csv` | Annuaire des comptes | 01, 04 |
| `alertes_siem.csv` | Alertes SIEM etiquetees (verdict analyste) | 01, 04, 10 |
| `evenements_systeme.csv` | Journaux d'evenements systeme | 01, 05, 06 |
| `netflow.csv` | Flux reseau | 08 |
| `journal_incidents.csv` | Journal du processus de reponse a incident | 07 |
| `rapports/*.txt` | Rapports d'incident en texte libre | 06, 09 |
| `cve.csv`, `vulnerabilites_hotes.csv` | Vulnerabilites et expositions | 03 |
| `attack/attack_subset.json` | Sous-ensemble ATT&CK (tabulaire) | 02, 03 |
| `attack/attack_bundle_stix.json` | Meme contenu au format STIX 2.1 simplifie | 03 |
| `corpus_fictif_pour_exercice.csv` | Corpus bibliographique **FICTIF** | 11 |
| `verite_terrain/` | Etiquettes reservees a l'**evaluation** | 05, 08 |

> `verite_terrain/` ne doit jamais servir a l'entrainement d'un modele non
> supervise : c'est la reference qui sert uniquement a mesurer la qualite du
> resultat, comme on le ferait a posteriori dans un vrai SOC.

> Les identifiants MITRE ATT&CK sont ceux du referentiel public ; les
> descriptions et les relations sont **simplifiees et synthetiques**.

> Le corpus bibliographique est **entierement fictif** (titres prefixes par
> `[FICTIF]`) : il sert a s'entrainer au criblage, jamais a citer.
""", encoding="utf-8")

    print("\nTermine.")


if __name__ == "__main__":
    main()
