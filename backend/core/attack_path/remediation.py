from __future__ import annotations

from core.graph_engine import graph


def ranked_remediations(limit: int = 3) -> list[dict]:
    return graph.top_remediations(limit=limit)
