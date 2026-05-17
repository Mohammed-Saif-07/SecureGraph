from __future__ import annotations

import csv
import gzip
from io import StringIO

import httpx

from core.graph_engine import graph

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


async def fetch_epss_scores(cve_ids: list[str] | None = None) -> list[dict]:
    """Fetch EPSS scores from FIRST for specific CVEs or the default latest page."""
    params = {"cve": ",".join(cve_ids)} if cve_ids else {}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(EPSS_API_URL, params=params)
        response.raise_for_status()
    rows = response.json().get("data", [])
    return [
        {"cve_id": row["cve"], "epss_score": float(row["epss"]), "epss_percentile": float(row["percentile"])}
        for row in rows
    ]


async def fetch_daily_epss_csv(limit: int | None = None) -> list[dict]:
    """Download the daily compressed EPSS feed and normalize it for Neo4j updates."""
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        response = await client.get(EPSS_CSV_URL)
        response.raise_for_status()
    text = gzip.decompress(response.content).decode("utf-8")
    rows = []
    for row in csv.DictReader(line for line in StringIO(text) if not line.startswith("#")):
        rows.append({"cve_id": row["cve"], "epss_score": float(row["epss"]), "epss_percentile": float(row["percentile"])})
        if limit and len(rows) >= limit:
            break
    return rows


async def import_epss(cve_ids: list[str] | None = None, limit: int | None = None) -> dict:
    """Update CVE nodes with current EPSS exploit prediction scores."""
    rows = await fetch_epss_scores(cve_ids) if cve_ids else await fetch_daily_epss_csv(limit=limit)
    count = graph.update_epss_scores(rows)
    return {"source": "epss", "updated": count}
