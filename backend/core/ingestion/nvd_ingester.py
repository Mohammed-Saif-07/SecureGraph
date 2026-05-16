from __future__ import annotations

import asyncio
from datetime import datetime
from typing import AsyncIterator

import httpx

from core.graph_engine import graph

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity(metrics: dict) -> tuple[float, str]:
    cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
    if not cvss:
        return 0.0, "unknown"
    item = cvss[0]
    data = item.get("cvssData", {})
    return float(data.get("baseScore", 0.0)), item.get("baseSeverity", data.get("baseSeverity", "unknown")).lower()


def normalize_nvd_item(item: dict) -> dict:
    cve = item["cve"]
    cvss_score, severity = _severity(cve.get("metrics", {}))
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    return {
        "id": cve["id"],
        "description": description[:4000],
        "cvss_score": cvss_score,
        "epss_score": 0.0,
        "published_date": cve.get("published", "")[:10],
        "severity": severity,
        "patch_available": bool(cve.get("configurations")),
        "exploit_in_wild": False,
    }


async def iter_nvd_cves(results_per_page: int = 2000, max_pages: int | None = None) -> AsyncIterator[dict]:
    start_index = 0
    page = 0
    async with httpx.AsyncClient(timeout=60) as client:
        while True:
            response = await client.get(
                NVD_URL,
                params={"startIndex": start_index, "resultsPerPage": results_per_page},
            )
            response.raise_for_status()
            payload = response.json()
            for vuln in payload.get("vulnerabilities", []):
                yield normalize_nvd_item(vuln)
            total = payload.get("totalResults", 0)
            start_index += results_per_page
            page += 1
            if start_index >= total or (max_pages and page >= max_pages):
                break
            await asyncio.sleep(0.7)


async def ingest_nvd(max_pages: int | None = 1) -> dict:
    count = 0
    started = datetime.utcnow()
    async for cve in iter_nvd_cves(max_pages=max_pages):
        graph.upsert_cve(cve)
        count += 1
    return {"source": "nvd", "count": count, "started_at": started.isoformat()}
