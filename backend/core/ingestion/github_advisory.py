from __future__ import annotations

import httpx

from core.config import settings
from core.graph_engine import graph

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
ECOSYSTEMS = ["PIP", "NPM", "MAVEN", "RUBYGEMS", "NUGET", "COMPOSER"]
ECOSYSTEM_LABELS = {"PIP": "PyPI", "NPM": "npm", "MAVEN": "Maven", "RUBYGEMS": "RubyGems", "NUGET": "NuGet", "COMPOSER": "Composer"}


def _cve_id(advisory: dict) -> str:
    """Choose the CVE identifier when GitHub advisory data provides one."""
    for identifier in advisory.get("identifiers", []):
        if identifier.get("type") == "CVE":
            return identifier["value"]
    return advisory["ghsaId"]


async def fetch_advisories(ecosystem: str, first: int = 50) -> list[dict]:
    """Fetch package-level GitHub Security Advisories for one ecosystem."""
    if not settings.github_token:
        return []
    query = """
    query($ecosystem: SecurityAdvisoryEcosystem!, $first: Int!) {
      securityAdvisories(first: $first, ecosystem: $ecosystem, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
        nodes {
          ghsaId
          summary
          description
          severity
          publishedAt
          identifiers { type value }
          references { url }
          vulnerabilities(first: 20) {
            nodes {
              package { name ecosystem }
              vulnerableVersionRange
              firstPatchedVersion { identifier }
            }
          }
        }
      }
    }
    """
    headers = {"Authorization": f"Bearer {settings.github_token}"}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(GITHUB_GRAPHQL_URL, headers=headers, json={"query": query, "variables": {"ecosystem": ecosystem, "first": first}})
        response.raise_for_status()
    return response.json().get("data", {}).get("securityAdvisories", {}).get("nodes", [])


async def import_github_advisories(first_per_ecosystem: int = 50) -> dict:
    """Import GitHub Advisory package vulnerabilities into Neo4j."""
    imported = 0
    package_links = 0
    for ecosystem in ECOSYSTEMS:
        advisories = await fetch_advisories(ecosystem, first=first_per_ecosystem)
        for advisory in advisories:
            cve_id = _cve_id(advisory)
            cve = {
                "id": cve_id,
                "cve_id": cve_id,
                "description": (advisory.get("summary") or advisory.get("description") or "")[:4000],
                "severity": str(advisory.get("severity", "unknown")).lower(),
                "published_date": str(advisory.get("publishedAt", ""))[:10],
                "references_count": len(advisory.get("references", [])),
                "has_patch": False,
                "patch_available": False,
            }
            imported += 1
            for vuln in advisory.get("vulnerabilities", {}).get("nodes", []):
                package_info = vuln.get("package") or {}
                fixed = vuln.get("firstPatchedVersion") or {}
                package = {
                    "name": package_info.get("name"),
                    "ecosystem": ECOSYSTEM_LABELS.get(ecosystem, package_info.get("ecosystem", ecosystem)),
                    "version": vuln.get("vulnerableVersionRange") or "*",
                    "fixed_version": fixed.get("identifier"),
                }
                if not package["name"]:
                    continue
                cve["has_patch"] = bool(package["fixed_version"])
                cve["patch_available"] = bool(package["fixed_version"])
                graph.upsert_package_vulnerability(package, cve)
                package_links += 1
    return {"source": "github_advisory", "advisories": imported, "package_links": package_links}
