from __future__ import annotations

import asyncio
import re
from datetime import date, datetime, timedelta
from typing import AsyncIterator

import httpx

from core.config import settings
from core.graph_engine import graph

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_DATE_RANGE_DAYS = 120


def _cvss_metrics(cve: dict) -> tuple[float, str, str, str]:
    """Extract CVSS score, severity, attack vector, and complexity from NVD metrics."""
    metrics = cve.get("metrics", {})
    candidates = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
    if not candidates:
        return 0.0, "unknown", "", ""
    metric = candidates[0]
    data = metric.get("cvssData", {})
    return (
        float(data.get("baseScore", 0.0)),
        str(metric.get("baseSeverity") or data.get("baseSeverity") or "unknown").lower(),
        str(data.get("attackVector", "")),
        str(data.get("attackComplexity", "")),
    )


def _cwe_id(cve: dict) -> str:
    """Return the primary CWE identifier from NVD weakness data."""
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-"):
                return value
    return "CWE-UNKNOWN"


def _package_from_cpe(criteria: str) -> dict | None:
    """Best-effort package extraction from a CPE 2.3 criteria string."""
    parts = criteria.split(":")
    if len(parts) < 6 or not criteria.startswith("cpe:2.3"):
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if product in {"*", "-", ""}:
        return None
    name = product.replace("\\", "").replace("_", "-").lower()
    ecosystem = "generic"
    if "python" in vendor or "pypi" in vendor:
        ecosystem = "PyPI"
    elif "node" in vendor or "npm" in vendor:
        ecosystem = "npm"
    elif "apache" in vendor:
        ecosystem = "Maven"
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": version if version not in {"*", "-"} else "*",
        "latest_version": "latest safe release",
    }


def extract_packages(cve: dict) -> list[dict]:
    """Extract affected packages from NVD CPE match criteria."""
    packages: dict[tuple[str, str, str], dict] = {}
    for config in cve.get("configurations", []):
        nodes = config.get("nodes", [])
        for node in nodes:
            for match in node.get("cpeMatch", []):
                package = _package_from_cpe(match.get("criteria", ""))
                if package:
                    packages[(package["name"], package["ecosystem"], package["version"])] = package
    return list(packages.values())


def normalize_nvd_cve(item: dict) -> tuple[dict, list[dict]]:
    """Normalize an NVD vulnerability item into graph-ready CVE and Package records."""
    cve = item["cve"]
    cvss_score, severity, attack_vector, complexity = _cvss_metrics(cve)
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    raw_references = cve.get("references", [])
    if isinstance(raw_references, dict):
        references = raw_references.get("referenceData", [])
    else:
        references = raw_references
    cve_record = {
        "id": cve["id"],
        "cve_id": cve["id"],
        "description": description[:4000],
        "cvss_score": cvss_score,
        "published_date": cve.get("published", "")[:10],
        "severity": severity,
        "cwe_id": _cwe_id(cve),
        "cvss_attack_vector": attack_vector,
        "cvss_complexity": complexity,
        "references_count": len(references),
        "has_patch": any(
            re.search(
                r"patch|fix|release|advisory",
                " ".join(ref.get("tags", [])) if ref.get("tags") else ref.get("url", ""),
                re.I,
            )
            for ref in references
        ),
        "patch_available": bool(references),
        "exploit_in_wild": False,
    }
    return cve_record, extract_packages(cve)


async def iter_recent_cves(months: int = 24, results_per_page: int = 2000, max_pages: int | None = None) -> AsyncIterator[tuple[dict, list[dict]]]:
    """Yield normalized CVEs published in the last N months from NVD API 2.0."""
    end = datetime.utcnow()
    start = end - timedelta(days=months * 30)
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    delay = 0.7 if settings.nvd_api_key else 6.2
    page = 0
    async with httpx.AsyncClient(timeout=90) as client:
        window_start = start
        while window_start < end:
            window_end = min(window_start + timedelta(days=NVD_MAX_DATE_RANGE_DAYS), end)
            start_index = 0
            while True:
                response = await client.get(
                    NVD_API_URL,
                    headers=headers,
                    params={
                        "pubStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "pubEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "resultsPerPage": results_per_page,
                        "startIndex": start_index,
                    },
                )
                response.raise_for_status()
                payload = response.json()
                for item in payload.get("vulnerabilities", []):
                    yield normalize_nvd_cve(item)
                total = int(payload.get("totalResults", 0))
                start_index += results_per_page
                page += 1
                if start_index >= total or (max_pages is not None and page >= max_pages):
                    break
                await asyncio.sleep(delay)
            if max_pages is not None and page >= max_pages:
                break
            window_start = window_end + timedelta(seconds=1)
            await asyncio.sleep(delay)


async def import_recent_cves(months: int = 24, max_pages: int | None = None) -> dict:
    """Import recent NVD CVEs into Neo4j with affected package relationships."""
    cve_count = 0
    package_count = 0
    async for cve, packages in iter_recent_cves(months=months, max_pages=max_pages):
        graph.upsert_cve(cve)
        cve_count += 1
        for package in packages:
            graph.upsert_package(package, [cve["id"]])
            package_count += 1
    return {"source": "nvd", "months": months, "cves": cve_count, "package_links": package_count, "imported_at": date.today().isoformat()}
