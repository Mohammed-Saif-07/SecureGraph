from __future__ import annotations

import csv
from io import StringIO

import httpx

from core.graph_engine import graph

EPSS_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss(cve_ids: list[str] | None = None) -> list[dict]:
    params = {}
    if cve_ids:
        params["cve"] = ",".join(cve_ids)
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(EPSS_URL, params=params)
        response.raise_for_status()
        return response.json().get("data", [])


async def ingest_epss(cve_ids: list[str] | None = None) -> dict:
    rows = await fetch_epss(cve_ids)
    for row in rows:
        graph.execute(
            """
            MERGE (c:CVE {id: $cve})
            SET c.epss_score = toFloat($epss),
                c.percentile = toFloat($percentile),
                c.exploit_in_wild = toFloat($epss) >= 0.75
            """,
            cve=row["cve"],
            epss=row["epss"],
            percentile=row["percentile"],
        )
    return {"source": "epss", "count": len(rows)}


def parse_epss_csv(text: str) -> list[dict]:
    return list(csv.DictReader(StringIO(text)))
