from __future__ import annotations

from fastapi import APIRouter

from core.attack_path.pathfinder import find_attack_paths, find_paths_for_cve
from core.attack_path.remediation import ranked_remediations
from core.attack_path.risk_scorer import blast_radius
from core.graph_engine import graph

router = APIRouter()


@router.get("/snapshot")
def snapshot():
    return graph.graph_snapshot()


@router.get("/cves/summary")
def cve_summary(sample_limit: int = 10):
    return graph.cve_summary(sample_limit=sample_limit)


@router.get("/attack-paths")
def attack_paths(limit: int = 10):
    paths = find_attack_paths(limit=limit)
    return {"paths": paths, "blast_radius": blast_radius(paths)}


@router.get("/attack-paths/{cve_id}")
def attack_paths_for_cve(cve_id: str):
    return {"cve_id": cve_id, "paths": find_paths_for_cve(cve_id)}


@router.get("/remediations")
def remediations(limit: int = 3):
    return {"remediations": ranked_remediations(limit=limit)}
