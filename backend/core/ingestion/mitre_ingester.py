from __future__ import annotations

import httpx

from core.graph_engine import graph

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def ingest_mitre_attack(limit: int = 300) -> dict:
    async with httpx.AsyncClient(timeout=90) as client:
        response = await client.get(MITRE_URL)
        response.raise_for_status()
        objects = response.json().get("objects", [])
    count = 0
    for obj in objects:
        if obj.get("revoked") or obj.get("type") != "attack-pattern":
            continue
        external_id = next(
            (ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
            obj.get("id"),
        )
        tactic = ", ".join(k.get("phase_name", "") for k in obj.get("kill_chain_phases", []))
        graph.execute(
            """
            MERGE (t:AttackTechnique {mitre_id: $mitre_id})
            SET t.name = $name, t.tactic = $tactic, t.description = $description
            """,
            mitre_id=external_id,
            name=obj.get("name", ""),
            tactic=tactic,
            description=obj.get("description", "")[:3000],
        )
        count += 1
        if count >= limit:
            break
    return {"source": "mitre_attack", "count": count}
