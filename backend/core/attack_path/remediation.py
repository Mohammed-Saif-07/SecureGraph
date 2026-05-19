from __future__ import annotations

from core.graph_engine import graph


def ranked_remediations(limit: int = 3, service_name: str | None = None) -> list[dict]:
    """Return ranked remediation candidates, optionally scoped to a service.

    ``service_name`` is forwarded to the Neo4j query as a filter. Callers that
    omit it (the public remediations API and the PDF report) keep their
    existing org-wide behaviour.
    """
    return graph.top_remediations(limit=limit, service_name=service_name)
