from __future__ import annotations

from core.graph_engine import graph


def find_attack_paths(limit: int = 10) -> list[dict]:
    return graph.attack_paths(limit=limit)


def find_paths_for_cve(cve_id: str, limit: int = 10) -> list[dict]:
    return graph.execute(
        """
        MATCH path = (cve:CVE {id: $cve_id})-[:AFFECTS]->(:Package)-[:USED_BY]->(:Service)
                     -[:RUNS_ON]->(:Server)-[:STORES]->(:BusinessData)
        RETURN [node IN nodes(path) | properties(node)] AS nodes,
               [rel IN relationships(path) | type(rel)] AS relationships,
               length(path) AS hops
        ORDER BY hops ASC LIMIT $limit
        """,
        cve_id=cve_id,
        limit=limit,
    )
